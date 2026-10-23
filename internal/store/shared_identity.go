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
	lower := from.Add(-time.Duration(3*period) * time.Second)
	logSQL := sharedSnapshotLogSQL
	logArgs := []any{m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, lower, to}
	if s.pg.identityDeltaEnabled {
		logSQL = deltaSharedSnapshotLogSQL
		logArgs = append(logArgs, ip)
	}
	rows, err = s.pg.db.QueryContext(ctx, logSQL, logArgs...)
	if err != nil {
		return nil, err
	}
	scope := IdentityScope{m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain}
	type logRow struct {
		meta      snapshotMeta
		projected bool
	}
	logged := []logRow{}
	for rows.Next() {
		row := logRow{meta: snapshotMeta{Scope: scope, IntervalSeconds: period}}
		fields := []any{&row.meta.SnapshotID, &row.meta.ObservedAt, &row.projected}
		var captured sql.NullTime
		if s.pg.identityDeltaEnabled {
			fields = append(fields, &captured)
		}
		if err = rows.Scan(fields...); err != nil {
			rows.Close()
			return nil, err
		}
		if captured.Valid {
			row.meta.CaptureStartedAt = captured.Time
		}
		logged = append(logged, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(logged) > 256 {
		return nil, fmt.Errorf("identity snapshot window exceeds bound")
	}
	issue := ""
	log := []snapshotMeta{}
	if len(logged) == 0 {
		issue = "identity_source_interrupted"
	} else {
		// Only projected snapshots carry membership. A snapshot newer than every projected one is still
		// being applied and may change this window; an older unprojected one was superseded and skipped.
		var newestProjected time.Time
		for _, row := range logged {
			if row.projected && row.meta.ObservedAt.After(newestProjected) {
				newestProjected = row.meta.ObservedAt
			}
		}
		baseline := -1
		for _, row := range logged {
			if !row.projected {
				continue
			}
			if !row.meta.ObservedAt.After(from) {
				baseline = len(log)
			}
			log = append(log, row.meta)
		}
		if baseline < 0 {
			issue = "identity_window_uncovered"
		} else {
			log = log[baseline:]
		}
		for _, row := range logged {
			if !row.projected && row.meta.ObservedAt.After(newestProjected) {
				issue = "identity_snapshot_index_pending"
			}
		}
	}
	memberSQL := sharedProjectionMembersSQL
	memberArgs := []any{m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, ip, lower}
	if s.pg.identityDeltaEnabled {
		memberSQL = `SELECT confirmed_at,document FROM (` + sharedProjectionMembersSQL + `) heads UNION ALL SELECT confirmed_at,document FROM identity_projection_intervals WHERE scope_key=$7 AND ip=$5 AND confirmed_at>=$6 LIMIT 2001`
		memberArgs = append(memberArgs, IdentityScopeKey(scope))
	}
	rows, err = s.pg.db.QueryContext(ctx, memberSQL, memberArgs...)
	if err != nil {
		return nil, err
	}
	members := []projectionMember{}
	for rows.Next() {
		var confirmed time.Time
		var raw []byte
		if err = rows.Scan(&confirmed, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		member, memberErr := projectionMemberFromRow(scope, confirmed, raw)
		if memberErr != nil {
			rows.Close()
			return nil, memberErr
		}
		members = append(members, member)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(members) > 2000 {
		return nil, fmt.Errorf("identity snapshot members exceed bound")
	}
	// Unprocessed identity changes may alter attribution inside this window.
	var pending bool
	if identitySplitProgressEnabled() {
		err = s.pg.db.QueryRowContext(ctx, deltaSharedPendingSQL, IdentityScopeKey(scope), ip, to).Scan(&pending)
	} else {
		err = s.pg.db.QueryRowContext(ctx, IdentityScopeStatusSQL(`SELECT EXISTS(SELECT 1 FROM identity_pipeline_scopes WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND (pending_records>0 OR last_error<>'' OR calibration_state IN ('failed','building')))`), m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain).Scan(&pending)
	}
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
	if identityCaptureConflict(facts, log, from, to) {
		issue = "identity_snapshot_capture_conflict"
	}
	out := policySessionsFromProjection(facts, log, members, to)
	if len(out) == 0 && issue != "" {
		out = []policy.Session{{ID: "health", IP: ip, Source: m.Source, SensorID: m.IdentitySensorID, CampusID: m.IdentityCampusID, AccessDomain: m.IdentityAccessDomain, StartedAt: from, ConfirmedAt: from}}
	}
	for i := range out {
		out[i].HeartbeatSeconds = period
		out[i].ReconcileSeconds = period
		if issue != "" {
			out[i].IdentityIssue = issue
			if issue == "identity_snapshot_capture_conflict" {
				out[i].AccountID = ""
			}
		}
	}
	return out, nil
}

// sharedSnapshotLogSQL reads the scope's snapshot timeline for one shared-observation window.
const sharedSnapshotLogSQL = `SELECT snapshot_id,observed_at,projected FROM identity_snapshot_log
 WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND observed_at BETWEEN $5 AND $6 ORDER BY observed_at LIMIT 257`

// sharedProjectionMembersSQL reads one IP's open members and members that ended inside the window.
const sharedProjectionMembersSQL = `SELECT p.confirmed_at,p.document FROM account_identity_session_projection p
 WHERE p.ip=$5 AND p.source=$1 AND p.sensor_id=$2 AND p.campus_id=$3 AND p.access_domain=$4
 AND (COALESCE(p.document->>'ended_at','')='' OR p.confirmed_at>=$6) LIMIT 2001`

const deltaSharedSnapshotLogSQL = `SELECT l.snapshot_id,l.observed_at,
 l.projected OR COALESCE((r.state IN ('ready','applying','completed') AND r.capture_started_at IS NOT NULL AND st.mode='delta' AND NOT EXISTS(SELECT 1 FROM identity_delta_changes c WHERE c.run_id=r.run_id AND c.ip=$7 AND c.applied_at IS NULL)),false),r.capture_started_at
 FROM identity_snapshot_log l LEFT JOIN identity_delta_runs r USING(source,sensor_id,campus_id,access_domain,snapshot_id)
 LEFT JOIN identity_delta_settings st ON st.scope_key=r.scope_key
 WHERE l.source=$1 AND l.sensor_id=$2 AND l.campus_id=$3 AND l.access_domain=$4 AND l.observed_at BETWEEN $5 AND $6 ORDER BY l.observed_at LIMIT 257`

const deltaSharedPendingSQL = `SELECT EXISTS(SELECT 1 FROM identity_pipeline_scope_status s JOIN identity_receive_progress r USING(scope_key)
 WHERE s.scope_key=$1 AND (
 (s.pending_records>0 AND s.processed_sequence<r.ip_tracking_after_sequence)
 OR EXISTS(SELECT 1 FROM identity_inbox_ip_pending p WHERE p.scope_key=$1 AND p.ip=$2 AND p.first_event_at<=$3)
 OR s.calibration_state='failed'))`
