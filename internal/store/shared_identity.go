package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

// insertSharedSnapshotMembers stores one chunk of members. Chunks may repeat: the key is unique.
func insertSharedSnapshotMembers(ctx context.Context, tx *sql.Tx, s IdentitySnapshot, members []policy.Session) error {
	raw, err := json.Marshal(members)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_identity_snapshot_members(source,sensor_id,campus_id,access_domain,snapshot_id,ip,session_id,document)
 SELECT $1,$2,$3,$4,$5,(v->>'ip')::inet,v->>'session_id',v FROM jsonb_array_elements($6::jsonb) v ON CONFLICT DO NOTHING`, s.Source, s.SensorID, s.CampusID, s.AccessDomain, s.SnapshotID, raw)
	return err
}

// insertSharedSnapshotIndex marks the snapshot indexed. Call it only after every member is stored:
// this row fires the shared-scope wake trigger and tells readers the members are complete.
func insertSharedSnapshotIndex(ctx context.Context, tx *sql.Tx, s IdentitySnapshot) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO shared_identity_snapshot_indexes(source,sensor_id,campus_id,access_domain,snapshot_id,observed_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, s.Source, s.SensorID, s.CampusID, s.AccessDomain, s.SnapshotID, s.ObservedAt)
	return err
}

func (s *DBStore) SharedIdentitySessions(ctx context.Context, m sharedaccess.IdentityMapping, ip string, from, to time.Time, period int) ([]policy.Session, error) {
	args := []any{m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, ip, from.Add(-time.Duration(3*period) * time.Second), to}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT session_data FROM policy_identity_observations
 WHERE session_data->>'source'=$1 AND session_data->>'sensor_id'=$2 AND session_data->>'campus_id'=$3 AND session_data->>'access_domain'=$4 AND session_data->>'ip'=$5
 AND observed_at BETWEEN $6 AND $7 ORDER BY observed_at,event_id LIMIT 2001`, args...)
	if err != nil {
		return nil, err
	}
	facts := []policy.Session{}
	for rows.Next() {
		var raw []byte
		var item policy.Session
		if err = rows.Scan(&raw); err == nil {
			err = json.Unmarshal(raw, &item)
		}
		if err != nil {
			rows.Close()
			return nil, err
		}
		facts = append(facts, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(facts) > 2000 {
		return nil, fmt.Errorf("identity window exceeds 2000 events")
	}
	// Metadata only: a complete snapshot that omits this IP must still end it.
	rows, err = s.pg.db.QueryContext(ctx, `SELECT f.snapshot_id,f.observed_at,f.interval_seconds,EXISTS(SELECT 1 FROM shared_identity_snapshot_indexes i WHERE i.source=f.source AND i.sensor_id=f.sensor_id AND i.campus_id=f.campus_id AND i.access_domain=f.access_domain AND i.snapshot_id=f.snapshot_id)
 FROM identity_full_snapshots f WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND observed_at BETWEEN $5 AND $6 ORDER BY observed_at LIMIT 257`, m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, from.Add(-time.Duration(3*period)*time.Second), to)
	if err != nil {
		return nil, err
	}
	snapshots := []IdentitySnapshot{}
	ids := []string{}
	indexedSnapshots := map[string]bool{}
	issue := ""
	for rows.Next() {
		v := IdentitySnapshot{IdentityScope: IdentityScope{m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain}}
		var indexed bool
		if err = rows.Scan(&v.SnapshotID, &v.ObservedAt, &v.IntervalSeconds, &indexed); err != nil {
			rows.Close()
			return nil, err
		}
		v.IntervalSeconds = period
		indexedSnapshots[v.SnapshotID] = indexed
		snapshots = append(snapshots, v)
		ids = append(ids, v.SnapshotID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(snapshots) > 256 {
		return nil, fmt.Errorf("identity snapshot window exceeds bound")
	}
	if len(snapshots) == 0 {
		issue = "identity_source_interrupted"
	} else {
		baseline := -1
		for i, snapshot := range snapshots {
			if !snapshot.ObservedAt.After(from) {
				baseline = i
			}
		}
		if baseline < 0 {
			issue = "identity_window_uncovered"
		} else {
			snapshots = snapshots[baseline:]
		}
		ids = nil
		for _, snapshot := range snapshots {
			ids = append(ids, snapshot.SnapshotID)
			if !indexedSnapshots[snapshot.SnapshotID] {
				issue = "identity_snapshot_index_pending"
			}
		}
	}
	rows, err = s.pg.db.QueryContext(ctx, `SELECT snapshot_id,document FROM shared_identity_snapshot_members WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND ip=$5::inet AND snapshot_id=ANY($6::text[]) LIMIT 2001`, m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, ip, ids)
	if err != nil {
		return nil, err
	}
	count := 0
	for rows.Next() {
		count++
		var id string
		var raw []byte
		var item policy.Session
		if err = rows.Scan(&id, &raw); err == nil {
			err = json.Unmarshal(raw, &item)
		}
		if err != nil {
			rows.Close()
			return nil, err
		}
		for i := range snapshots {
			if snapshots[i].SnapshotID == id {
				snapshots[i].Sessions = append(snapshots[i].Sessions, item)
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count > 2000 {
		return nil, fmt.Errorf("identity snapshot members exceed bound")
	}
	// Unprocessed identity changes may alter attribution inside this window.
	var pending bool
	err = s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_pipeline_scopes WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND (pending_records>0 OR last_error<>'' OR calibration_state IN ('failed','building')))`, m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain).Scan(&pending)
	if err != nil {
		return nil, err
	}
	if pending {
		issue = "identity_processing_pending"
	}
	if m.HealthBridgeID != "" {
		health, err := s.pg.db.QueryContext(ctx, `SELECT h.valid_from,LEAST(COALESCE(h.valid_to,r.heartbeat_at+interval '60 seconds'),r.heartbeat_at+interval '60 seconds') FROM shared_identity_health_intervals h JOIN identity_bridge_runtime r USING(bridge_id) WHERE h.bridge_id=$1 AND h.healthy AND h.valid_from<=$3 AND COALESCE(h.valid_to,r.heartbeat_at+interval '60 seconds')>=$2 ORDER BY h.valid_from LIMIT 1001`, m.HealthBridgeID, from, to)
		if err != nil {
			return nil, err
		}
		end := from
		n := 0
		for health.Next() {
			var a, b time.Time
			if err = health.Scan(&a, &b); err != nil {
				health.Close()
				return nil, err
			}
			n++
			if !a.After(end) && b.After(end) {
				end = b
			}
		}
		err = health.Err()
		health.Close()
		if err != nil {
			return nil, err
		}
		if end.Before(to) || n > 1000 {
			issue = "identity_source_interrupted"
		}
	}
	out := reconcileIdentitySessions(facts, snapshots, to)
	if len(out) == 0 && issue != "" {
		out = []policy.Session{{ID: "health", IP: ip, Source: m.Source, SensorID: m.IdentitySensorID, CampusID: m.IdentityCampusID, AccessDomain: m.IdentityAccessDomain, StartedAt: from, ConfirmedAt: from}}
	}
	for i := range out {
		out[i].HeartbeatSeconds = period
		out[i].ReconcileSeconds = period
		if issue != "" {
			out[i].IdentityIssue = issue
		}
	}
	return out, nil
}
