package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"sort"
	"strings"
	"time"
)

func (s *DBStore) enqueueSharedGateways(ctx context.Context, events []normalized.Event) error {
	type job struct {
		ID     string    `json:"id"`
		Sensor string    `json:"sensor"`
		Campus string    `json:"campus"`
		Domain string    `json:"domain"`
		MAC    string    `json:"mac"`
		At     time.Time `json:"at"`
	}
	jobs := map[string]job{}
	for _, e := range events {
		if e.Source != "packet-sidecar" || (e.SourceEventType != "ieee1905_client_association" && e.SourceEventType != "ieee1905_client_snapshot") {
			continue
		}
		sensor, campus, domain, mac := stringFromMap(e.Observer, "sensor_id"), stringFromMap(e.Subject, "campus_id"), stringFromMap(e.Payload, "access_domain"), strings.ToLower(stringFromMap(e.Subject, "mac"))
		if campus == "" {
			campus = stringFromMap(e.Payload, "campus_id")
		}
		if sensor == "" || !validUnicastMAC(mac) {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			return err
		}
		id := policy.StableID(sensor, campus, domain, mac)
		if old, ok := jobs[id]; !ok || at.After(old.At) {
			jobs[id] = job{id, sensor, campus, domain, mac, at}
		}
	}
	if len(jobs) == 0 {
		return nil
	}
	list := []job{}
	for _, v := range jobs {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO shared_gateway_observation_jobs(job_id,sensor_id,campus_id,access_domain,gateway_mac,last_event_at,first_received_at,dirty_since)
 SELECT id,sensor,campus,domain,mac,at,COALESCE((SELECT started_at FROM ingest_batches WHERE batch_id=$2),now()),COALESCE((SELECT started_at FROM ingest_batches WHERE batch_id=$2),now()) FROM jsonb_to_recordset($1::jsonb) r(id text,sensor text,campus text,domain text,mac text,at timestamptz) ORDER BY id
 ON CONFLICT(job_id) DO UPDATE SET revision=shared_gateway_observation_jobs.revision+1,last_event_at=GREATEST(shared_gateway_observation_jobs.last_event_at,EXCLUDED.last_event_at),next_attempt_at=now(),expired=false,dirty_since=CASE WHEN shared_gateway_observation_jobs.revision=shared_gateway_observation_jobs.completed_revision THEN EXCLUDED.dirty_since ELSE LEAST(shared_gateway_observation_jobs.dirty_since,EXCLUDED.dirty_since) END`, raw, ctx.Value(sharedIngestBatchKey{}))
	return err
}

// Resolve at most one affected gateway. A missing lease stays pending until the
// observation expires; storage errors roll back without advancing completion.
func (s *DBStore) ResolveSharedGateway(ctx context.Context, cfg sharedaccess.Config, now time.Time) (did bool, err error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id, mac, previous string
	var scope SharedObservationScope
	var at, received time.Time
	var revision int64
	config, _ := json.Marshal(cfg.Sources)
	err = tx.QueryRowContext(ctx, `SELECT job_id,sensor_id,campus_id,access_domain,gateway_mac,COALESCE(host(resolved_ip),''),last_event_at,dirty_since,revision FROM shared_gateway_observation_jobs WHERE NOT expired AND next_attempt_at<=now() AND (sensor_id,campus_id,access_domain) IN (SELECT sensor_id,campus_id,access_domain FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,campus_id text,access_domain text,source text) WHERE source='packet-sidecar') ORDER BY next_attempt_at,job_id FOR UPDATE SKIP LOCKED LIMIT 1`, config).Scan(&id, &scope.SensorID, &scope.CampusID, &scope.AccessDomain, &mac, &previous, &at, &received, &revision)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			report, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, reportErr := s.pg.db.ExecContext(report, `UPDATE shared_gateway_observation_jobs SET last_error='processing_failed',next_attempt_at=now()+interval '5 seconds' WHERE job_id=$1`, id)
			if reportErr != nil {
				err = fmt.Errorf("%w; report: %v", err, reportErr)
			}
		}
	}()
	ip, err := s.ieee1905GatewayIPAt(ctx, scope.SensorID, scope.CampusID, mac, at)
	if err != nil {
		return true, err
	}
	current, err := s.ieee1905GatewayIPAt(ctx, scope.SensorID, scope.CampusID, mac, now)
	if err != nil {
		return true, err
	}
	if current != ip {
		ip = ""
	}
	expired := !now.Before(at.Add(cfg.Freshness()))
	reason := ""
	if ip == "" {
		reason = "gateway_ownership_unavailable"
	}
	targets := map[string]bool{previous: true, ip: true}
	for target := range targets {
		if target == "" {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_jobs(job_id,sensor_id,campus_id,access_domain,ip,last_event_at,first_received_at,dirty_since)
 VALUES($1,$2,$3,$4,$5::inet,$6,$7,$7) ON CONFLICT(job_id) DO UPDATE SET revision=shared_observation_jobs.revision+1,last_event_at=GREATEST(shared_observation_jobs.last_event_at,EXCLUDED.last_event_at),last_received_at=now(),next_attempt_at=now(),expired=false,
 dirty_since=CASE WHEN shared_observation_jobs.revision=shared_observation_jobs.completed_revision THEN EXCLUDED.dirty_since ELSE LEAST(shared_observation_jobs.dirty_since,EXCLUDED.dirty_since) END`, policy.StableID(scope.SensorID, scope.CampusID, scope.AccessDomain, target), scope.SensorID, scope.CampusID, scope.AccessDomain, target, at, received)
		if err != nil {
			return true, err
		}
	}
	next := now.Add(5 * time.Second)
	if ip != "" {
		next = at.Add(cfg.Freshness())
	}
	_, err = tx.ExecContext(ctx, `UPDATE shared_gateway_observation_jobs SET completed_revision=CASE WHEN $2<>'' OR $3 THEN $4 ELSE completed_revision END,resolved_ip=NULLIF($2,'')::inet,expired=$3,next_attempt_at=$5,last_error=$6 WHERE job_id=$1`, id, ip, expired, revision, next, reason)
	if err != nil {
		return true, err
	}
	return true, tx.Commit()
}

type sharedAssociationEvent struct {
	sharedObservationEvent
	MAC  string `json:"subject_mac"`
	Kind string `json:"source_event_type"`
}

func (s *DBStore) sharedAssociationRows(ctx context.Context, scope SharedObservationScope, mac string, from, to time.Time, preserveVariants ...bool) ([]sharedAssociationEvent, error) {
	query := fmt.Sprintf(`SELECT formatDateTime(min(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS timestamp,event_id,source,collector_instance_id,subject_mac,source_event_type,min(payload_json) AS payload_json,uniqExact(payload_json) AS payload_versions FROM shared_association_events_v1
 PREWHERE sensor_id=%s AND campus_id=%s AND access_domain=%s AND subject_mac IN ('',%s) AND timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<=parseDateTime64BestEffort(%s,6)
 GROUP BY event_id,source,collector_instance_id,subject_mac,source_event_type ORDER BY min(timestamp),event_id LIMIT 2001 SETTINGS prefer_column_name_to_alias=1,max_threads=1,max_memory_usage=134217728,max_execution_time=2 FORMAT JSONEachRow`, chQuote(scope.SensorID), chQuote(scope.CampusID), chQuote(scope.AccessDomain), chQuote(mac), chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano)))
	if len(preserveVariants) > 0 && preserveVariants[0] {
		query = strings.Replace(query, "min(payload_json) AS payload_json", "payload_json", 1)
		query = strings.Replace(query, "subject_mac,source_event_type ORDER BY", "subject_mac,source_event_type,payload_json ORDER BY", 1)
	}
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, err
	}
	rows := []sharedAssociationEvent{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return nil, err
	}
	if len(rows) > 2000 {
		return nil, fmt.Errorf("association window exceeds bound")
	}
	return rows, nil
}

// A complete BSS snapshot establishes membership; subsequent scoped negatives
// retire it. Bare joins or old unmeasured summaries remain candidate evidence.
func buildAssociationWindow(scope SharedObservationScope, mac string, rows []sharedAssociationEvent, now time.Time, freshness time.Duration) sharedaccess.Window {
	w := sharedaccess.Window{SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: scope.IP, RuleVersion: sharedaccess.RuleVersion, Records: []sharedaccess.RecordRef{}, EventIDs: []string{}, Samples: map[string]map[string]sharedaccess.FeatureSample{}, Conflicts: []string{}, Sources: []string{"packet-sidecar"}}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Timestamp == rows[j].Timestamp {
			if rows[i].Kind != rows[j].Kind {
				return rows[i].Kind == "ieee1905_client_snapshot"
			}
			if rows[i].EventID != rows[j].EventID {
				return rows[i].EventID < rows[j].EventID
			}
			return rows[i].Payload < rows[j].Payload
		}
		return rows[i].Timestamp < rows[j].Timestamp
	})
	type membership struct {
		clients map[string]bool
		at      time.Time
	}
	bsses := map[string]membership{}
	seen := map[string]string{}
	for _, row := range rows {
		key := row.Source + "/" + row.Instance + "/" + row.EventID
		if old, ok := seen[key]; ok {
			if old != row.Payload {
				w.Conflicts = append(w.Conflicts, "duplicate_event_changed")
			}
			continue
		}
		seen[key] = row.Payload
		var p struct {
			Coverage  sharedaccess.CoverageV2       `json:"capture_coverage"`
			Snapshots []ieee1905AssociationSnapshot `json:"bss_snapshots"`
			BSSID     string                        `json:"bssid"`
			Client    string                        `json:"client_mac"`
			State     string                        `json:"association_state"`
		}
		if json.Unmarshal([]byte(row.Payload), &p) != nil {
			w.Conflicts = append(w.Conflicts, "association_payload_invalid")
			continue
		}
		fact := sharedaccess.CoverageFact{EventID: row.EventID, Source: row.Source, Instance: row.Instance, Coverage: p.Coverage}
		if row.MAC == mac {
			fact.IP = scope.IP
		}
		w.CoverageFacts = append(w.CoverageFacts, fact)
		if row.PayloadVersions > 1 {
			w.Conflicts = append(w.Conflicts, "duplicate_event_changed")
			continue
		}
		if row.MAC != mac {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, row.Timestamp)
		if err != nil || at.Before(now.Add(-10*time.Minute)) || at.After(now) {
			continue
		}
		w.Records = append(w.Records, sharedaccess.RecordRef{EventID: row.EventID, Source: row.Source, InstanceID: row.Instance})
		w.EventIDs = append(w.EventIDs, row.EventID)
		if w.From.IsZero() || at.Before(w.From) {
			w.From = at
		}
		if at.After(w.To) {
			w.To = at
			w.LastObservedAt = at
		}
		if p.Coverage.SchemaVersion != "capture-coverage/v2" || at.Before(p.Coverage.From) || !at.Before(p.Coverage.To) {
			w.Conflicts = append(w.Conflicts, "legacy_association_without_coverage")
			continue
		}
		if p.Coverage.From.Before(w.From) {
			w.From = p.Coverage.From
		}
		switch row.Kind {
		case "ieee1905_client_snapshot":
			for _, snap := range p.Snapshots {
				if !validUnicastMAC(snap.BSSID) {
					w.Conflicts = append(w.Conflicts, "association_payload_invalid")
					continue
				}
				clients := map[string]bool{}
				for _, client := range snap.ClientMACs {
					if validUnicastMAC(client) {
						clients[strings.ToLower(client)] = true
					}
				}
				old, ok := bsses[snap.BSSID]
				if ok && old.at.Equal(at) {
					a, _ := json.Marshal(old.clients)
					b, _ := json.Marshal(clients)
					if string(a) != string(b) {
						w.Conflicts = append(w.Conflicts, "association_same_time_conflict")
					}
				}
				bsses[snap.BSSID] = membership{clients, at}
			}
		case "ieee1905_client_association":
			if p.State == "left" {
				if bss, ok := bsses[p.BSSID]; ok {
					delete(bss.clients, strings.ToLower(p.Client))
					bsses[p.BSSID] = bss
				}
			}
		}
	}
	clients := map[string]bool{}
	for _, bss := range bsses {
		if !now.Before(bss.at.Add(freshness)) {
			continue
		}
		for client := range bss.clients {
			clients[client] = true
		}
	}
	for client := range clients {
		w.AssociatedClients = append(w.AssociatedClients, client)
	}
	sort.Strings(w.AssociatedClients)
	return w
}

func (s *DBStore) includeSharedGateway(ctx context.Context, scope SharedObservationScope, cfg sharedaccess.Config, handshake sharedaccess.Window, item sharedaccess.BehaviorAssessment, now time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error) {
	registered := false
	for _, src := range cfg.Sources {
		if src.Source == "packet-sidecar" && src.SensorID == scope.SensorID && src.CampusID == scope.CampusID && src.AccessDomain == scope.AccessDomain {
			registered = true
		}
	}
	if !registered {
		return handshake, item, nil
	}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT gateway_mac FROM shared_gateway_observation_jobs WHERE sensor_id=$1 AND campus_id=$2 AND access_domain=$3 AND resolved_ip=$4::inet AND last_event_at>=$5 ORDER BY gateway_mac LIMIT 3`, scope.SensorID, scope.CampusID, scope.AccessDomain, scope.IP, now.Add(-10*time.Minute))
	if err != nil {
		return handshake, item, err
	}
	macs := []string{}
	for rows.Next() {
		var mac string
		if err = rows.Scan(&mac); err != nil {
			rows.Close()
			return handshake, item, err
		}
		macs = append(macs, mac)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return handshake, item, err
	}
	if len(macs) == 0 {
		return handshake, item, nil
	}
	if len(macs) > 1 {
		handshake.Conflicts = append(handshake.Conflicts, "gateway_ownership_conflicting")
		handshake.Complete = false
		handshake.CoverageVerified = false
		return finalizeSharedObservation(handshake, cfg, now)
	}
	events, err := s.sharedAssociationRows(ctx, scope, macs[0], now.Add(-11*time.Minute), now)
	if err != nil {
		return handshake, item, err
	}
	w := buildAssociationWindow(scope, macs[0], events, now, cfg.Freshness())
	if w.LastObservedAt.IsZero() {
		return handshake, item, nil
	}
	w.GatewayMAC = macs[0]
	w.Conflicts = append(w.Conflicts, sharedaccess.VerifyCoverage(w, cfg, w.CoverageFacts)...)
	facts := w.CoverageFacts
	w.CoverageFacts = nil
	for _, fact := range facts {
		if fact.Coverage.From.Before(w.To) && fact.Coverage.To.After(w.From) {
			w.CoverageFacts = append(w.CoverageFacts, fact)
		}
	}
	// A lease must cover the whole evidence window and remain unrevoked now.
	// It is checked independently from account authentication and retained in proof.
	var leaseID string
	var observed, until time.Time
	err = s.pg.db.QueryRowContext(ctx, `SELECT l.event_id,l.observed_at,l.valid_until FROM device_address_leases l
 WHERE l.sensor_id=$1 AND l.campus_id=$2 AND l.endpoint_id=$3 AND l.ip=$4::inet AND l.action='ack' AND l.observed_at<=$5 AND l.valid_until>$6
 AND NOT EXISTS(SELECT 1 FROM device_address_leases n WHERE n.sensor_id=l.sensor_id AND n.campus_id=l.campus_id AND n.observed_at>=l.observed_at AND n.observed_at<=$6 AND
 ((n.action='stop' AND n.endpoint_id=l.endpoint_id AND n.ip=l.ip) OR (n.action='ack' AND ((n.ip=l.ip AND n.endpoint_id<>l.endpoint_id) OR (n.endpoint_id=l.endpoint_id AND n.ip<>l.ip))))) ORDER BY l.observed_at DESC,l.event_id LIMIT 1`, scope.SensorID, scope.CampusID, "mac:"+macs[0], scope.IP, w.From, now).Scan(&leaseID, &observed, &until)
	if err != nil && err != sql.ErrNoRows {
		return handshake, item, err
	}
	if err == sql.ErrNoRows {
		w.Conflicts = append(w.Conflicts, "gateway_ownership_unavailable")
	} else {
		w.GatewayLease, _ = json.Marshal(map[string]any{"event_id": leaseID, "gateway_mac": macs[0], "ip": scope.IP, "observed_at": observed, "valid_until": until, "sensor_id": scope.SensorID, "campus_id": scope.CampusID})
	}
	sort.Strings(w.Conflicts)
	w.Complete = len(w.Conflicts) == 0
	w.CoverageVerified = w.Complete
	w, association, err := finalizeSharedObservation(w, cfg, now)
	if err != nil {
		return handshake, item, err
	}
	if association.Current && association.Status == "confirmed" {
		return w, association, nil
	}
	if item.Current && item.Status == "confirmed" {
		return handshake, item, nil
	}
	if association.LastSeen.After(item.LastSeen) || !item.Current {
		return w, association, nil
	}
	return handshake, item, nil
}
