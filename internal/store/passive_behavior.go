package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
)

const passiveBehaviorSegmentSize = 128

type passiveBehaviorInput struct {
	Sensor, Site, Domain, VLAN, VRF, IP string
	Kind, Value, EventID                string
	At                                  time.Time
}

func passiveBehaviorWriteEnabled() bool {
	return discovery.HardwareProjectionEnabled() && os.Getenv("PROXY_SENTINEL_PASSIVE_BEHAVIOR_WRITE") == "true"
}

func extractPassiveBehavior(event normalized.Event, scope passiveDiscoveryScope) []passiveBehaviorInput {
	if event.EventID == "" || len(event.EventID) > 256 || passiveString(event.Observer, "capture_scope_issue") != "" {
		return nil
	}
	base := passiveBehaviorInput{
		Sensor: passiveString(event.Observer, "sensor_id"), Site: passiveString(event.Subject, "campus_id"),
		Domain: passiveString(event.Payload, "access_domain"), VLAN: passiveScopeField(event, "vlan"),
		VRF: passiveScopeField(event, "vrf"), EventID: event.EventID,
	}
	if base.Site == "" {
		base.Site = base.Sensor
	}
	if base.Domain == "" {
		base.Domain = passiveInterface(event)
	}
	if base.Sensor == "" || base.Domain == "" {
		return nil
	}
	for _, field := range []string{base.Sensor, base.Site, base.Domain, base.VLAN, base.VRF} {
		if len(field) > 64 {
			return nil
		}
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return nil
	}
	base.At = at
	source := passiveString(event.Flow, "src_ip")
	var results []passiveBehaviorInput
	add := func(ip, kind, value string) {
		addr, err := netip.ParseAddr(ip)
		if value == "" || err != nil || !scope.allows(addr.Unmap().String()) {
			return
		}
		item := base
		item.IP, item.Kind, item.Value = addr.Unmap().String(), kind, value
		results = append(results, item)
	}
	switch event.SourceEventType {
	case "dns":
		add(source, "vendor_domain", discovery.PassiveBehaviorDomain(passiveString(event.Payload, "query")))
	case "conn", "syn_attempt", "syn_ack_observed":
		proto := passiveString(event.Flow, "proto")
		port, _ := passiveInt(event.Flow, "dst_port")
		destination := passiveString(event.Flow, "dst_ip")
		if port == 123 && proto == "udp" && event.SourceEventType == "conn" {
			if ip, err := netip.ParseAddr(destination); err == nil && ip.IsGlobalUnicast() {
				add(source, "ntp", ip.Unmap().String())
			}
		}
		if !passiveBehaviorPort(proto, port) {
			break
		}
		service := proto + "/" + strconv.Itoa(port)
		add(source, "port_attempt", service)
		replyPackets, _ := passiveInt(event.Flow, "pkts_toclient")
		if event.SourceEventType == "conn" && proto == "tcp" && replyPackets > 0 && passiveString(event.Payload, "state") == "SF" {
			add(destination, "port_response", service)
		} else if event.SourceEventType == "syn_ack_observed" {
			add(source, "port_reply_seen", service)
		}
	case "ttl", "hop_limit":
		if source == "" {
			source = passiveString(event.Subject, "ip")
		}
		ttl, _ := passiveInt(event.Payload, event.SourceEventType)
		window, _ := passiveInt(event.Payload, "tcp_window")
		stack := passiveString(event.Payload, "tcp_stack")
		if ttl > 0 && ttl <= 255 && window > 0 && window <= 65535 && stack != "" {
			add(source, "tcp_stack", fmt.Sprintf("TTL %d · Window %d", ttl, window))
			switch {
			case ttl >= 100 && ttl <= 128 && window == 64240 && strings.Contains(stack, "ts=false"):
				add(source, "tcp_os_clue", "Windows")
			case ttl >= 50 && ttl <= 64 && window == 64240 && strings.Contains(stack, "ts=true"):
				add(source, "tcp_os_clue", "Unix")
			}
		}
	}
	return results
}

func passiveBehaviorPort(proto string, port int) bool {
	if proto != "tcp" {
		return false
	}
	switch port {
	case 554, 1883, 631, 8883, 9100:
		return true
	default:
		return false
	}
}

func (s *DBStore) stagePassiveBehavior(ctx context.Context, batch ingest.Batch, events []normalized.Event) error {
	scope, err := parsePassiveDiscoveryScope(os.Getenv("PROXY_SENTINEL_DISCOVERY_CIDRS"))
	if err != nil {
		return err
	}
	var items []passiveBehaviorInput
	for _, event := range events {
		for _, item := range extractPassiveBehavior(event, scope) {
			if item.Sensor == batch.SensorID {
				items = append(items, item)
			}
		}
	}
	if len(items) == 0 {
		return nil
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for start := 0; start < len(items); start += passiveBehaviorSegmentSize {
		selected := items[start:min(start+passiveBehaviorSegmentSize, len(items))]
		var through time.Time
		for _, item := range selected {
			if item.At.After(through) {
				through = item.At
			}
		}
		data, err := json.Marshal(selected)
		if err != nil {
			return err
		}
		if len(data) > 2*1024*1024 {
			return fmt.Errorf("behavior segment exceeds 2 MiB")
		}
		digest := sha256.Sum256(data)
		checksum := hex.EncodeToString(digest[:])
		segment := start / passiveBehaviorSegmentSize
		result, err := tx.ExecContext(ctx, `INSERT INTO passive_behavior_batch_work(batch_id,segment,sensor_id,payload,byte_size,payload_sha256,source_through)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(batch_id,segment) DO NOTHING`, batch.BatchID, segment, batch.SensorID, string(data), len(data), checksum, through)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			var prior string
			if err := tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM passive_behavior_batch_work WHERE batch_id=$1 AND segment=$2`, batch.BatchID, segment).Scan(&prior); err != nil {
				return err
			}
			if prior != checksum {
				return fmt.Errorf("behavior segment content changed for the same ingest batch")
			}
		}
	}
	return tx.Commit()
}

type passiveBehaviorWindow struct {
	Owner string    `json:"owner"`
	Kind  string    `json:"kind"`
	Value string    `json:"value"`
	IP    string    `json:"ip"`
	Event string    `json:"event"`
	At    time.Time `json:"at"`
}

func (s *DBStore) processPassiveBehavior(ctx context.Context, sensor string) (bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var batch string
	var segment int
	var payload []byte
	var ingestedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT w.batch_id,w.segment,w.payload,i.committed_at
 FROM passive_behavior_batch_work w JOIN ingest_batches i ON i.batch_id=w.batch_id AND i.status='committed' AND i.committed_at IS NOT NULL
 JOIN passive_discovery_state d ON d.sensor_id=w.sensor_id AND d.cursor_timestamp>=w.source_through
 WHERE w.sensor_id=$1 AND w.processed_at IS NULL AND w.next_attempt_at<=now()
 ORDER BY w.next_attempt_at,w.enqueued_at,w.batch_id,w.segment LIMIT 1 FOR UPDATE OF w SKIP LOCKED`, sensor).Scan(&batch, &segment, &payload, &ingestedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := applyPassiveBehaviorSegment(ctx, tx, sensor, batch, segment, payload, ingestedAt); err != nil {
		_ = tx.Rollback()
		audit, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, reportErr := s.pg.db.ExecContext(audit, `UPDATE passive_behavior_batch_work SET attempts=attempts+1,
 next_attempt_at=now()+make_interval(secs=>least(300,5*(least(attempts,59)+1))),last_error=$3
 WHERE batch_id=$1 AND segment=$2 AND processed_at IS NULL`, batch, segment, discovery.WorkErrorCode(err))
		return false, errors.Join(err, reportErr)
	}
	return true, tx.Commit()
}

func applyPassiveBehaviorSegment(ctx context.Context, tx *sql.Tx, sensor, batch string, segment int, payload []byte, ingestedAt time.Time) error {
	var input []passiveBehaviorInput
	if len(payload) > 2*1024*1024 || json.Unmarshal(payload, &input) != nil || len(input) == 0 || len(input) > passiveBehaviorSegmentSize {
		return fmt.Errorf("invalid bounded behavior segment")
	}
	observations := make([]discovery.Observation, 0, len(input))
	for _, item := range input {
		observations = append(observations, discovery.Observation{Node: item.Sensor, Site: item.Site, Domain: item.Domain, VLAN: item.VLAN, VRF: item.VRF, IP: item.IP, ObservedAt: item.At, Origin: "behavior"})
	}
	if err := resolveHardwareOwnershipBatch(ctx, tx, observations); err != nil {
		return err
	}
	windows := make([]passiveBehaviorWindow, 0, len(input))
	for index, item := range input {
		owner := discovery.PassiveBehaviorKey(item.Sensor, item.Site, item.Domain, item.VLAN, item.VRF, observations[index].MAC, item.IP)
		if owner != "" {
			windows = append(windows, passiveBehaviorWindow{Owner: owner, Kind: item.Kind, Value: item.Value, IP: item.IP, Event: item.EventID, At: item.At})
		}
	}
	rows, err := json.Marshal(windows)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `WITH input AS (
 SELECT *, date_bin(interval '5 minutes',at,'2000-01-01 00:00:00+00'::timestamptz) bucket
 FROM jsonb_to_recordset($3::jsonb) AS x(owner text,kind text,value text,ip inet,event text,at timestamptz)
), merged AS (
 SELECT owner,bucket,kind,value,min(at) first_seen,max(at) last_seen,(array_agg(event ORDER BY at DESC,event DESC))[1] event_id,
 (array_agg(ip ORDER BY at DESC,event DESC))[1] ip
 FROM input GROUP BY owner,bucket,kind,value
)
INSERT INTO passive_behavior_windows(owner_key,sensor_id,bucket_at,kind,value,first_seen,last_seen,first_ingested_at,event_id,ip,batch_id)
SELECT owner,$1,bucket,kind,value,first_seen,last_seen,$4,event_id,ip,$2 FROM merged
ON CONFLICT(owner_key,bucket_at,kind,value) DO UPDATE SET
 first_seen=least(passive_behavior_windows.first_seen,EXCLUDED.first_seen),
 last_seen=greatest(passive_behavior_windows.last_seen,EXCLUDED.last_seen),
 first_ingested_at=least(passive_behavior_windows.first_ingested_at,EXCLUDED.first_ingested_at),
 event_id=CASE WHEN (EXCLUDED.last_seen,EXCLUDED.event_id)>(passive_behavior_windows.last_seen,passive_behavior_windows.event_id)
  THEN EXCLUDED.event_id ELSE passive_behavior_windows.event_id END,
 ip=CASE WHEN (EXCLUDED.last_seen,EXCLUDED.event_id)>(passive_behavior_windows.last_seen,passive_behavior_windows.event_id)
  THEN EXCLUDED.ip ELSE passive_behavior_windows.ip END,
 batch_id=CASE WHEN (EXCLUDED.last_seen,EXCLUDED.event_id)>(passive_behavior_windows.last_seen,passive_behavior_windows.event_id)
  THEN EXCLUDED.batch_id ELSE passive_behavior_windows.batch_id END
WHERE EXCLUDED.first_seen<passive_behavior_windows.first_seen
 OR EXCLUDED.first_ingested_at<passive_behavior_windows.first_ingested_at
 OR (EXCLUDED.last_seen,EXCLUDED.event_id)>(passive_behavior_windows.last_seen,passive_behavior_windows.event_id)`, sensor, batch, string(rows), ingestedAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE passive_behavior_batch_work SET payload='[]'::jsonb,processed_at=now(),last_error='' WHERE batch_id=$1 AND segment=$2`, batch, segment)
	return err
}

func (s *DBStore) runPassiveBehavior(ctx context.Context, sensor string) {
	if !passiveBehaviorWriteEnabled() {
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	lastPrune := time.Time{}
	for ctx.Err() == nil {
		budget, cancel := context.WithTimeout(ctx, 6*time.Second)
		for range 12 {
			worked, err := s.processPassiveBehavior(budget, sensor)
			if err != nil && ctx.Err() == nil {
				log.Printf("passive behavior: %s", discovery.WorkErrorCode(err))
			}
			if !worked || err != nil {
				break
			}
		}
		if budget.Err() == nil && time.Since(lastPrune) >= time.Minute {
			_, err := s.pg.db.ExecContext(budget, `DELETE FROM passive_behavior_windows WHERE ctid IN (
 SELECT ctid FROM passive_behavior_windows WHERE first_ingested_at<now()-interval '30 days' ORDER BY first_ingested_at LIMIT 1000
)`)
			if err == nil {
				lastPrune = time.Now()
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ReadPassiveBehavior rechecks the bounded detail sample against the event-time
// binding index. A late revocation, corrected assignment or scope conflict
// must not leave a device candidate dependent on a stale stored association.
func ReadPassiveBehavior(ctx context.Context, db *sql.DB, key string, owner discovery.PassiveBehaviorOwner) (discovery.PassiveBehavior, error) {
	now := time.Now().UTC()
	rows, err := db.QueryContext(ctx, `SELECT kind,value,bucket_at,last_seen,event_id,host(ip)
 FROM passive_behavior_windows WHERE owner_key=$1 AND bucket_at>=$2
 ORDER BY bucket_at DESC,kind,value LIMIT 161`, key, now.Add(-2*time.Hour).Truncate(5*time.Minute))
	if err != nil {
		return discovery.PassiveBehavior{}, err
	}
	defer rows.Close()
	var items []discovery.PassiveBehaviorEvidence
	var probes []discovery.Observation
	for rows.Next() {
		var item discovery.PassiveBehaviorEvidence
		var ip string
		if err := rows.Scan(&item.Kind, &item.Value, &item.BucketAt, &item.ObservedAt, &item.EventID, &ip); err != nil {
			return discovery.PassiveBehavior{}, err
		}
		items = append(items, item)
		probes = append(probes, discovery.Observation{Node: owner.Sensor, Site: owner.Site, Domain: owner.Domain, VLAN: owner.VLAN, VRF: owner.VRF, IP: ip, ObservedAt: item.ObservedAt, Origin: "behavior"})
	}
	if err := rows.Err(); err != nil {
		return discovery.PassiveBehavior{}, err
	}
	rows.Close()
	truncated := len(items) > 160
	if truncated {
		items = items[:160]
		probes = probes[:160]
	}
	trusted := owner.MAC != ""
	if trusted && len(probes) > 0 {
		if err := resolveHardwareOwnershipBatch(ctx, db, probes); err != nil {
			return discovery.PassiveBehavior{}, err
		}
		accepted := items[:0]
		for i, item := range items {
			if strings.EqualFold(probes[i].MAC, owner.MAC) {
				accepted = append(accepted, item)
			}
		}
		items = accepted
	}
	var gap bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM passive_behavior_batch_work w WHERE sensor_id=$1 AND processed_at IS NULL
  AND source_through<now()-interval '5 minutes'
  AND EXISTS (SELECT 1 FROM ingest_batches i WHERE i.batch_id=w.batch_id AND i.status='committed')
)`, owner.Sensor).Scan(&gap); err != nil {
		return discovery.PassiveBehavior{}, err
	}
	result := discovery.SummarizePassiveBehavior(items, trusted, now)
	if truncated || gap {
		result.Status = "partial"
		// The trace can still be examined, but unresolved input may carry a
		// contradicting signal outside this bounded sample.
		result.CandidateType = ""
	}
	return result, nil
}
