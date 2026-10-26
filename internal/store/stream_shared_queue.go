package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/streamlog"
)

type StreamSharedJobQueue struct{ DB *sql.DB }

type streamSharedJob struct {
	ID     string    `json:"id"`
	Sensor string    `json:"sensor"`
	Campus string    `json:"campus"`
	Domain string    `json:"domain"`
	IP     string    `json:"ip,omitempty"`
	MAC    string    `json:"mac,omitempty"`
	At     time.Time `json:"at"`
}

type streamSharedCoverage struct {
	Sensor   string          `json:"sensor"`
	Campus   string          `json:"campus"`
	Domain   string          `json:"domain"`
	Source   string          `json:"source"`
	Instance string          `json:"instance"`
	From     time.Time       `json:"from"`
	To       time.Time       `json:"to"`
	Complete bool            `json:"complete"`
	Document json.RawMessage `json:"document"`
}

type preparedStreamSharedJobs struct {
	Owner      string
	Sensor     string
	ScopeID    string
	Hash       string
	Handshakes []streamSharedJob
	Gateways   []streamSharedJob
	Coverage   []streamSharedCoverage
}

// One source file has one producer owner. The receipt belongs to the fixed
// source position, while work is coalesced by business key inside that segment.
func prepareStreamSharedJobs(segment streamlog.Segment) (preparedStreamSharedJobs, error) {
	if segment.Source != "device-signals" || segment.Epoch == "" || segment.SourcePath == "" || len(segment.Events) == 0 || len(segment.Events) > streamlog.MaxSegmentEvents {
		return preparedStreamSharedJobs{}, errors.New("invalid shared stream segment")
	}
	encoded, err := json.Marshal(struct {
		Epoch   string `json:"epoch"`
		Path    string `json:"path"`
		File    string `json:"file"`
		Start   int64  `json:"start"`
		End     int64  `json:"end"`
		Parser  string `json:"parser"`
		RawHash string `json:"raw_hash"`
		Events  any    `json:"events"`
	}{segment.Epoch, segment.SourcePath, segment.FileID, segment.StartOffset, segment.EndOffset, segment.ParserVersion, segment.RawSHA256, segment.Events})
	if err != nil {
		return preparedStreamSharedJobs{}, err
	}
	sum := sha256.Sum256(encoded)
	p := preparedStreamSharedJobs{Hash: hex.EncodeToString(sum[:])}
	handshakes := map[string]streamSharedJob{}
	gateways := map[string]streamSharedJob{}
	coverage := map[string]streamSharedCoverage{}
	for _, event := range segment.Events {
		if event.Source != "handshake-sidecar" && event.Source != "packet-sidecar" {
			return p, fmt.Errorf("unexpected source owner in shared segment: %w", streamlog.ErrContentConflict)
		}
		// Shared ownership comes from events that can create a shared job or
		// coverage record. The handshake file also carries packet context
		// such as TTL, NDP and SSDP; those events retain their body and index
		// without claiming packet-sidecar shared work.
		sharedOwnerEvent := event.Source == "handshake-sidecar" && (event.SourceEventType == "handshake" || event.SourceEventType == "capture_coverage") ||
			event.Source == "packet-sidecar" && (event.SourceEventType == "ieee1905_client_association" || event.SourceEventType == "ieee1905_client_snapshot" || event.SourceEventType == "capture_coverage")
		if sharedOwnerEvent {
			if p.Owner == "" {
				p.Owner = event.Source
			} else if p.Owner != event.Source {
				return p, fmt.Errorf("mixed source owners in shared segment: %w", streamlog.ErrContentConflict)
			}
		}
		sensor := stringFromMap(event.Observer, "sensor_id")
		scopeID := stringFromMap(event.Observer, "capture_scope_id")
		campus := stringFromMap(event.Subject, "campus_id")
		if campus == "" {
			campus = stringFromMap(event.Payload, "campus_id")
		}
		domain := stringFromMap(event.Payload, "access_domain")
		if sensor == "" || scopeID == "" || campus == "" || domain == "" || (p.Sensor != "" && p.Sensor != sensor) || (p.ScopeID != "" && p.ScopeID != scopeID) {
			return p, fmt.Errorf("shared source scope incomplete or changed: %w", streamlog.ErrContentConflict)
		}
		p.Sensor = sensor
		p.ScopeID = scopeID
		at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil {
			return p, err
		}
		switch {
		case event.Source == "handshake-sidecar" && event.SourceEventType == "handshake":
			ip := stringFromMap(event.Subject, "ip")
			if _, err := netip.ParseAddr(ip); err != nil {
				return p, fmt.Errorf("invalid shared subject IP: %w", streamlog.ErrContentConflict)
			}
			id := policy.StableID(sensor, campus, domain, ip)
			if old, ok := handshakes[id]; !ok || at.After(old.At) {
				handshakes[id] = streamSharedJob{id, sensor, campus, domain, ip, "", at}
			}
		case event.Source == "packet-sidecar" && (event.SourceEventType == "ieee1905_client_association" || event.SourceEventType == "ieee1905_client_snapshot"):
			mac := strings.ToLower(stringFromMap(event.Subject, "mac"))
			if !validUnicastMAC(mac) {
				return p, fmt.Errorf("invalid shared gateway MAC: %w", streamlog.ErrContentConflict)
			}
			id := policy.StableID(sensor, campus, domain, mac)
			if old, ok := gateways[id]; !ok || at.After(old.At) {
				gateways[id] = streamSharedJob{id, sensor, campus, domain, "", mac, at}
			}
		case event.SourceEventType == "capture_coverage":
			raw, err := json.Marshal(event.Payload["capture_coverage"])
			if err != nil {
				return p, err
			}
			var c sharedaccess.CoverageV2
			if err := json.Unmarshal(raw, &c); err != nil {
				return p, err
			}
			if c.SchemaVersion != "capture-coverage/v2" || c.From.IsZero() || !c.To.After(c.From) {
				return p, fmt.Errorf("invalid shared capture coverage: %w", streamlog.ErrContentConflict)
			}
			instance := stringFromMap(event.Observer, "collector_instance_id")
			if instance == "" {
				return p, fmt.Errorf("shared capture instance missing: %w", streamlog.ErrContentConflict)
			}
			key := sensor + "\x00" + campus + "\x00" + domain + "\x00" + event.Source + "\x00" + instance
			if old, ok := coverage[key]; !ok || c.To.After(old.To) {
				coverage[key] = streamSharedCoverage{sensor, campus, domain, event.Source, instance, c.From, c.To, c.Complete(), raw}
			} else if c.To.Equal(old.To) && string(raw) != string(old.Document) {
				return p, fmt.Errorf("conflicting shared capture coverage: %w", streamlog.ErrContentConflict)
			}
		}
	}
	if p.Owner == "" {
		return p, fmt.Errorf("shared segment has no business owner: %w", streamlog.ErrContentConflict)
	}
	for _, v := range handshakes {
		p.Handshakes = append(p.Handshakes, v)
	}
	for _, v := range gateways {
		p.Gateways = append(p.Gateways, v)
	}
	for _, v := range coverage {
		p.Coverage = append(p.Coverage, v)
	}
	sort.Slice(p.Handshakes, func(i, j int) bool { return p.Handshakes[i].ID < p.Handshakes[j].ID })
	sort.Slice(p.Gateways, func(i, j int) bool { return p.Gateways[i].ID < p.Gateways[j].ID })
	sort.Slice(p.Coverage, func(i, j int) bool {
		a, b := p.Coverage[i], p.Coverage[j]
		return a.Sensor+"/"+a.Campus+"/"+a.Domain+"/"+a.Source+"/"+a.Instance < b.Sensor+"/"+b.Campus+"/"+b.Domain+"/"+b.Source+"/"+b.Instance
	})
	return p, nil
}

func (q StreamSharedJobQueue) MarkStreamSharedJobs(ctx context.Context, id string, segment streamlog.Segment) error {
	if q.DB == nil || id == "" {
		return ErrStreamProjectorUnavailable
	}
	p, err := prepareStreamSharedJobs(segment)
	if err != nil {
		return err
	}
	tx, err := q.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var registered, registeredScope, generation string
	if err := tx.QueryRowContext(ctx, `SELECT sensor_id,scope_id,cancel_id FROM stream_shared_source_cutovers WHERE epoch=$1 AND source_path=$2 AND source_owner=$3 AND state='active'`, segment.Epoch, segment.SourcePath, p.Owner).Scan(&registered, &registeredScope, &generation); err != nil {
		return err
	}
	if registered != p.Sensor || registeredScope != p.ScopeID || generation == "" {
		return streamlog.ErrContentConflict
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO stream_shared_segment_receipts(segment_id,epoch,source_path,source_owner,segment_sha256,event_count)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(segment_id) DO NOTHING`, id, segment.Epoch, segment.SourcePath, p.Owner, p.Hash, len(segment.Events))
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		var prior string
		if err := tx.QueryRowContext(ctx, `SELECT segment_sha256 FROM stream_shared_segment_receipts WHERE segment_id=$1`, id).Scan(&prior); err != nil {
			return err
		}
		if prior != p.Hash {
			return streamlog.ErrContentConflict
		}
		return tx.Commit()
	}
	if len(p.Handshakes) > 0 {
		raw, err := json.Marshal(p.Handshakes)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_jobs(job_id,sensor_id,campus_id,access_domain,ip,last_event_at,first_received_at,dirty_since,generation_id)
 SELECT id,sensor,campus,domain,ip::inet,at,clock_timestamp(),clock_timestamp(),$2 FROM jsonb_to_recordset($1::jsonb)
 AS r(id text,sensor text,campus text,domain text,ip text,at timestamptz) ORDER BY id
 ON CONFLICT(job_id) DO UPDATE SET revision=shared_observation_jobs.revision+1,
 last_event_at=GREATEST(shared_observation_jobs.last_event_at,EXCLUDED.last_event_at),last_received_at=clock_timestamp(),last_dependency_at=clock_timestamp(),
	first_received_at=CASE WHEN shared_observation_jobs.generation_id<>EXCLUDED.generation_id THEN EXCLUDED.first_received_at ELSE shared_observation_jobs.first_received_at END,
 dirty_since=CASE WHEN shared_observation_jobs.generation_id<>EXCLUDED.generation_id OR shared_observation_jobs.revision=shared_observation_jobs.completed_revision THEN EXCLUDED.dirty_since ELSE LEAST(shared_observation_jobs.dirty_since,EXCLUDED.dirty_since) END,
 next_attempt_at=now(),expired=false,canceled_epoch='',generation_id=EXCLUDED.generation_id,lease_token='',lease_until=NULL`, raw, generation)
		if err != nil {
			return err
		}
	}
	if len(p.Gateways) > 0 {
		raw, err := json.Marshal(p.Gateways)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_gateway_observation_jobs(job_id,sensor_id,campus_id,access_domain,gateway_mac,last_event_at,first_received_at,dirty_since,generation_id)
 SELECT id,sensor,campus,domain,mac,at,clock_timestamp(),clock_timestamp(),$2 FROM jsonb_to_recordset($1::jsonb)
 AS r(id text,sensor text,campus text,domain text,mac text,at timestamptz) ORDER BY id
 ON CONFLICT(job_id) DO UPDATE SET revision=shared_gateway_observation_jobs.revision+1,
 last_event_at=GREATEST(shared_gateway_observation_jobs.last_event_at,EXCLUDED.last_event_at),
	first_received_at=CASE WHEN shared_gateway_observation_jobs.generation_id<>EXCLUDED.generation_id THEN EXCLUDED.first_received_at ELSE shared_gateway_observation_jobs.first_received_at END,
 dirty_since=CASE WHEN shared_gateway_observation_jobs.generation_id<>EXCLUDED.generation_id OR shared_gateway_observation_jobs.revision=shared_gateway_observation_jobs.completed_revision THEN EXCLUDED.dirty_since ELSE LEAST(shared_gateway_observation_jobs.dirty_since,EXCLUDED.dirty_since) END,
 next_attempt_at=now(),expired=false,canceled_epoch='',generation_id=EXCLUDED.generation_id`, raw, generation)
		if err != nil {
			return err
		}
	}
	if len(p.Coverage) > 0 {
		raw, err := json.Marshal(p.Coverage)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_capture_progress(sensor_id,campus_id,access_domain,source,collector_instance_id,covered_from,covered_to,complete,document,generation_id)
	 SELECT sensor,campus,domain,source,instance,"from","to",complete,document,$2 FROM jsonb_to_recordset($1::jsonb)
 AS r(sensor text,campus text,domain text,source text,instance text,"from" timestamptz,"to" timestamptz,complete boolean,document jsonb)
 ORDER BY sensor,campus,domain,source,instance
 ON CONFLICT(sensor_id,campus_id,access_domain,source,collector_instance_id) DO UPDATE SET
	 covered_from=EXCLUDED.covered_from,covered_to=EXCLUDED.covered_to,complete=EXCLUDED.complete,document=EXCLUDED.document,generation_id=EXCLUDED.generation_id,received_at=now()
	 WHERE shared_capture_progress.generation_id<>EXCLUDED.generation_id OR EXCLUDED.covered_to>shared_capture_progress.covered_to`, raw, generation)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
