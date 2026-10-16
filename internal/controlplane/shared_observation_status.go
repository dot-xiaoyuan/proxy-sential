package controlplane

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) sharedObservationStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	state := "disabled"
	blocker := "shared_observation_disabled"
	pending, failed, expired, matched, insufficient, coveragePartial, attributionMissing := 0, 0, 0, 0, 0, 0, 0
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	var last, captured, done, oldest sql.NullTime
	gatewayPending, gatewayFailed := 0, 0
	if s.sharedObservationEnabled {
		err := s.operations.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE revision>completed_revision),count(*) FILTER(WHERE last_error<>''),count(*) FILTER(WHERE expired),count(*) FILTER(WHERE last_result='matched' AND NOT expired),count(*) FILTER(WHERE last_result='insufficient' AND NOT expired),count(*) FILTER(WHERE coverage_state<>'verified' AND NOT expired),count(*) FILTER(WHERE attribution_state='insufficient' AND NOT expired),max(last_received_at),max(last_event_at),max(completed_at),min(dirty_since) FILTER(WHERE revision>completed_revision) FROM shared_observation_jobs`).Scan(&pending, &failed, &expired, &matched, &insufficient, &coveragePartial, &attributionMissing, &last, &captured, &done, &oldest)
		if err != nil {
			writeError(w, 503, "shared_status_unavailable", "共享任务状态读取失败")
			return
		}
		var gatewayEvent, gatewayReceived sql.NullTime
		err = s.operations.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE revision>completed_revision AND NOT expired),count(*) FILTER(WHERE last_error='processing_failed' AND NOT expired),max(last_event_at),max(dirty_since) FROM shared_gateway_observation_jobs`).Scan(&gatewayPending, &gatewayFailed, &gatewayEvent, &gatewayReceived)
		if err != nil {
			writeError(w, 503, "shared_status_unavailable", "共享接入关联任务状态读取失败")
			return
		}
		pending += gatewayPending
		failed += gatewayFailed
		if gatewayEvent.Valid && (!captured.Valid || gatewayEvent.Time.After(captured.Time)) {
			captured = gatewayEvent
		}
		if gatewayReceived.Valid && (!last.Valid || gatewayReceived.Time.After(last.Time)) {
			last = gatewayReceived
		}
		state, blocker = "healthy", ""
		if !last.Valid {
			state, blocker = "waiting", "shared_collection_no_data"
		} else if !captured.Valid || now.Sub(captured.Time) > s.sharedConfig.Freshness() {
			state, blocker = "expired", "shared_evidence_expired"
		}
		if failed > 0 {
			state, blocker = "failed", "shared_processing_failed"
		} else if pending > 0 {
			state, blocker = "processing", ""
		}
	}
	collection := "waiting"
	if last.Valid {
		collection = "healthy"
		if !captured.Valid || now.Sub(captured.Time) > s.sharedConfig.Freshness() {
			collection = "stale"
		}
	}
	collectors := []map[string]any{}
	config, _ := json.Marshal(s.sharedConfig.Sources)
	rows, err := s.operations.db.QueryContext(ctx, `SELECT c.sensor_id,c.campus_id,c.access_domain,c.source,p.collector_instance_id,p.covered_to,p.complete,COALESCE((p.document->>'stopped')::boolean,false) FROM jsonb_to_recordset($1::jsonb) c(sensor_id text,campus_id text,access_domain text,source text) LEFT JOIN LATERAL (SELECT collector_instance_id,covered_to,complete,document FROM shared_capture_progress WHERE sensor_id=c.sensor_id AND campus_id=c.campus_id AND access_domain=c.access_domain AND source=c.source ORDER BY covered_to DESC LIMIT 1) p ON true`, config)
	if err != nil {
		writeError(w, 503, "shared_status_unavailable", "采集覆盖状态读取失败")
		return
	}
	collection = "healthy"
	for rows.Next() {
		var sensor, campus, domain, source string
		var instance sql.NullString
		var covered sql.NullTime
		var complete sql.NullBool
		var stopped bool
		if err = rows.Scan(&sensor, &campus, &domain, &source, &instance, &covered, &complete, &stopped); err != nil {
			rows.Close()
			writeError(w, 503, "shared_status_unavailable", "采集覆盖状态读取失败")
			return
		}
		state := "healthy"
		if !covered.Valid {
			state = "waiting"
		} else if covered.Time.After(now) || now.Sub(covered.Time) > s.sharedConfig.Freshness() {
			state = "stale"
		} else if stopped {
			state = "unavailable"
		} else if !complete.Bool {
			state = "partial"
		}
		priority := map[string]int{"healthy": 0, "partial": 1, "waiting": 2, "stale": 3, "unavailable": 4}
		if priority[state] > priority[collection] {
			collection = state
		}
		collectors = append(collectors, map[string]any{"sensor_id": sensor, "campus_id": campus, "access_domain": domain, "source": source, "collector_instance_id": instance.String, "covered_to": func() any {
			if covered.Valid {
				return covered.Time
			}
			return nil
		}(), "complete": complete.Bool, "state": state})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		writeError(w, 503, "shared_status_unavailable", "采集覆盖状态读取失败")
		return
	}
	if len(collectors) == 0 {
		collection = "waiting"
	}
	identities := []map[string]any{}
	for _, m := range s.sharedConfig.IdentityMappings {
		scope := map[string]any{"source": m.Source, "sensor_id": m.IdentitySensorID, "campus_id": m.IdentityCampusID, "access_domain": m.IdentityAccessDomain}
		state, reason := "waiting", "identity_snapshot_pending"
		var observed sql.NullTime
		var count, period int
		err := s.operations.db.QueryRowContext(ctx, `SELECT observed_at,session_count,interval_seconds FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 ORDER BY observed_at DESC LIMIT 1`, m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain).Scan(&observed, &count, &period)
		if err != nil && err != sql.ErrNoRows {
			writeError(w, 503, "identity_status_unavailable", "身份来源状态读取失败")
			return
		}
		fresh := observed.Valid && period > 0 && now.Sub(observed.Time) < time.Duration(3*period)*time.Second
		if fresh {
			state, reason = "healthy", ""
		} else if observed.Valid {
			state, reason = "stale", "identity_source_interrupted"
		}
		if m.HealthBridgeID != "" {
			var bridgeState string
			var heartbeat sql.NullTime
			var failures int
			err = s.operations.db.QueryRowContext(ctx, `SELECT state,heartbeat_at,event_consecutive_failures+snapshot_consecutive_failures FROM identity_bridge_runtime WHERE bridge_id=$1`, m.HealthBridgeID).Scan(&bridgeState, &heartbeat, &failures)
			if err != nil && err != sql.ErrNoRows {
				writeError(w, 503, "identity_status_unavailable", "身份桥状态读取失败")
				return
			}
			if !heartbeat.Valid || now.Sub(heartbeat.Time) > time.Minute || bridgeState != "healthy" || failures > 0 {
				fresh = false
				state, reason = "unavailable", "identity_source_interrupted"
			}
		}
		item := map[string]any{"connector_id": m.Source + "/" + m.IdentitySensorID, "scope": scope, "state": state, "blocker": reason, "fresh": fresh, "record_count": count, "interval_seconds": period}
		if observed.Valid {
			item["observed_at"] = observed.Time
		}
		identities = append(identities, item)
	}

	nullable := func(v sql.NullTime) any {
		if v.Valid {
			return v.Time
		}
		return nil
	}
	writeJSON(w, 200, map[string]any{"checked_at": now, "identity": identities, "collection": map[string]any{"state": collection, "last_received_at": nullable(last), "last_event_at": nullable(captured), "sources": collectors}, "materialization": map[string]any{"configured": s.sharedObservationEnabled, "state": state, "blocker": blocker, "pending": pending, "failed": failed, "expired": expired, "completed_at": nullable(done), "oldest_pending_at": nullable(oldest)}, "attribution": map[string]any{"state": "evaluated_per_window", "mapping_version": s.sharedConfig.ID(), "insufficient": attributionMissing}, "policy": map[string]any{"state": state, "blocker": blocker, "router_confirmation": "unavailable", "router_confirmation_blocker": "router_forwarding_not_verified", "mode": "observe", "delivery_status": "not_sent", "matched": matched, "insufficient": insufficient, "coverage_partial": coveragePartial, "expired": expired}, "controller": map[string]any{"state": "disabled", "expected": true, "label": "执行功能关闭"}})
}
