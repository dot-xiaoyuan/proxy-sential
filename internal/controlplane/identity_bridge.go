package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const ncuIdentityBridgeID = "ncu-legacy-4k"

type IdentityBridgeDefaults struct {
	BridgeID                 string
	OnlinePort               int
	EventRedisAddr           string
	OnlineList               string
	EventList                string
	Source                   string
	SensorID                 string
	CampusID                 string
	AccessDomain             string
	BatchSize                int
	ReconcileIntervalSeconds int
}

func (c IdentityBridgeDefaults) normalized() IdentityBridgeDefaults {
	if c.BridgeID == "" {
		c.BridgeID = ncuIdentityBridgeID
	}
	if c.OnlinePort == 0 {
		c.OnlinePort = 16380
	}
	if c.EventRedisAddr == "" {
		c.EventRedisAddr = "222.204.3.227:16384"
	}
	if c.OnlineList == "" {
		c.OnlineList = "list:rad_online"
	}
	if c.EventList == "" {
		c.EventList = "list:antiproxy:127.0.0.1"
	}
	if c.Source == "" {
		c.Source = "ncu-srun4k"
	}
	if c.SensorID == "" {
		c.SensorID = "ncu-auth-redis"
	}
	if c.CampusID == "" {
		c.CampusID = "ncu"
	}
	if c.AccessDomain == "" {
		c.AccessDomain = "campus-auth"
	}
	if c.BatchSize == 0 {
		c.BatchSize = 500
	}
	if c.ReconcileIntervalSeconds == 0 {
		c.ReconcileIntervalSeconds = 1800
	}
	return c
}

type identityBridgeHeartbeat struct {
	ActiveHost                  string     `json:"active_host"`
	ActiveConfigVersion         int64      `json:"active_config_version"`
	State                       string     `json:"state"`
	OnlineChannelState          string     `json:"online_channel_state"`
	EventChannelState           string     `json:"event_channel_state"`
	SnapshotState               string     `json:"snapshot_state"`
	SourceQueue                 int64      `json:"source_queue"`
	ProcessingQueue             int64      `json:"processing_queue"`
	OnlineMembers               int64      `json:"online_members"`
	OnlineSessions              int64      `json:"online_sessions"`
	CommittedMessages           int64      `json:"committed_messages"`
	BadMessages                 int64      `json:"bad_messages"`
	EventConsecutiveFailures    int        `json:"event_consecutive_failures"`
	SnapshotConsecutiveFailures int        `json:"snapshot_consecutive_failures"`
	LastEventAt                 *time.Time `json:"last_event_at,omitempty"`
	LastSnapshotAttemptAt       *time.Time `json:"last_snapshot_attempt_at,omitempty"`
	LastSnapshotAt              *time.Time `json:"last_snapshot_at,omitempty"`
	LastErrorType               string     `json:"last_error_type,omitempty"`
	StartedAt                   *time.Time `json:"started_at,omitempty"`
}

type identityBridgeRunReport struct {
	RunID            string     `json:"run_id"`
	Kind             string     `json:"kind"`
	Status           string     `json:"status"`
	RecordsRead      int        `json:"records_read"`
	RecordsEmitted   int        `json:"records_emitted"`
	RecordsSkipped   int        `json:"records_skipped"`
	RecordsMalformed int        `json:"records_malformed"`
	RetryCount       int        `json:"retry_count"`
	DurationMillis   int64      `json:"duration_ms"`
	ErrorType        string     `json:"error_type,omitempty"`
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
}

var bridgeErrorTypePattern = regexp.MustCompile(`^[a-z0-9_]*$`)

func (s *Server) authorizeIdentityBridge(w http.ResponseWriter, r *http.Request) bool {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, http.StatusUnauthorized, "integration_auth_failed", "valid integration bearer token required")
		return false
	}
	if s.operations == nil || s.operations.db == nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_storage_unavailable", "identity bridge requires PostgreSQL storage")
		return false
	}
	return true
}

func (s *Server) identityBridgeRuntimeConfig(ctx context.Context) (map[string]any, error) {
	defaults := s.identityBridge.normalized()
	var host, updatedBy string
	var version int64
	var updatedAt time.Time
	err := s.operations.db.QueryRowContext(ctx, `SELECT desired_host,config_version,updated_by,updated_at FROM identity_bridge_configs WHERE bridge_id=$1`, defaults.BridgeID).Scan(&host, &version, &updatedBy, &updatedAt)
	if err != nil {
		return nil, err
	}
	host = normalizeIdentityBridgeHost(host)
	return map[string]any{
		"bridge_id": defaults.BridgeID, "host": host, "config_version": version,
		"online_redis_addr": net.JoinHostPort(host, fmt.Sprintf("%d", defaults.OnlinePort)),
		"event_redis_addr":  defaults.EventRedisAddr, "online_list": defaults.OnlineList,
		"event_list": defaults.EventList, "processing_list": defaults.EventList + ":proxy-sentinel-processing",
		"source": defaults.Source, "sensor_id": defaults.SensorID, "campus_id": defaults.CampusID,
		"access_domain": defaults.AccessDomain, "batch_size": defaults.BatchSize,
		"reconcile_interval_seconds": defaults.ReconcileIntervalSeconds, "updated_by": updatedBy, "updated_at": updatedAt,
	}, nil
}

func (s *Server) handleIdentityBridgeRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeIdentityBridge(w, r) {
		return
	}
	config, err := s.identityBridgeRuntimeConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_config_unavailable", "identity bridge configuration is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, config)
}

func (s *Server) handleIdentityBridgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeIdentityBridge(w, r) {
		return
	}
	var value identityBridgeHeartbeat
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.ActiveConfigVersion < 0 || !validSRunHost(value.ActiveHost) || !validBridgeState(value.State) || !validChannelState(value.OnlineChannelState) || !validChannelState(value.EventChannelState) || !validSnapshotState(value.SnapshotState) || value.SourceQueue < 0 || value.ProcessingQueue < 0 || value.OnlineMembers < 0 || value.OnlineSessions < 0 || value.CommittedMessages < 0 || value.BadMessages < 0 || value.EventConsecutiveFailures < 0 || value.SnapshotConsecutiveFailures < 0 || len(value.LastErrorType) > 100 || !bridgeErrorTypePattern.MatchString(value.LastErrorType) {
		writeError(w, http.StatusBadRequest, "bad_identity_bridge_heartbeat", "identity bridge heartbeat is invalid")
		return
	}
	_, err := s.operations.db.ExecContext(r.Context(), `INSERT INTO identity_bridge_runtime(bridge_id,active_host,active_config_version,state,online_channel_state,event_channel_state,snapshot_state,source_queue,processing_queue,online_members,online_sessions,committed_messages,bad_messages,event_consecutive_failures,snapshot_consecutive_failures,last_event_at,last_snapshot_attempt_at,last_snapshot_at,last_error_type,started_at,heartbeat_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now(),now()) ON CONFLICT(bridge_id) DO UPDATE SET active_host=EXCLUDED.active_host,active_config_version=EXCLUDED.active_config_version,state=EXCLUDED.state,online_channel_state=EXCLUDED.online_channel_state,event_channel_state=EXCLUDED.event_channel_state,snapshot_state=EXCLUDED.snapshot_state,source_queue=EXCLUDED.source_queue,processing_queue=EXCLUDED.processing_queue,online_members=EXCLUDED.online_members,online_sessions=EXCLUDED.online_sessions,committed_messages=EXCLUDED.committed_messages,bad_messages=EXCLUDED.bad_messages,event_consecutive_failures=EXCLUDED.event_consecutive_failures,snapshot_consecutive_failures=EXCLUDED.snapshot_consecutive_failures,last_event_at=EXCLUDED.last_event_at,last_snapshot_attempt_at=EXCLUDED.last_snapshot_attempt_at,last_snapshot_at=EXCLUDED.last_snapshot_at,last_error_type=EXCLUDED.last_error_type,started_at=COALESCE(identity_bridge_runtime.started_at,EXCLUDED.started_at),heartbeat_at=now(),updated_at=now()`, s.identityBridge.normalized().BridgeID, value.ActiveHost, value.ActiveConfigVersion, value.State, value.OnlineChannelState, value.EventChannelState, value.SnapshotState, value.SourceQueue, value.ProcessingQueue, value.OnlineMembers, value.OnlineSessions, value.CommittedMessages, value.BadMessages, value.EventConsecutiveFailures, value.SnapshotConsecutiveFailures, value.LastEventAt, value.LastSnapshotAttemptAt, value.LastSnapshotAt, value.LastErrorType, value.StartedAt)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_heartbeat_failed", "identity bridge heartbeat could not be saved")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validBridgeState(value string) bool {
	return value == "starting" || value == "healthy" || value == "degraded" || value == "switching" || value == "switch_failed" || value == "failed"
}

func validChannelState(value string) bool {
	return value == "pending" || value == "healthy" || value == "failed"
}

func validSnapshotState(value string) bool {
	return value == "pending" || value == "healthy" || value == "stale" || value == "failed"
}

func (s *Server) handleIdentityBridgeRunReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeIdentityBridge(w, r) {
		return
	}
	var value identityBridgeRunReport
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.RunID == "" || len(value.RunID) > 200 || (value.Kind != "snapshot" && value.Kind != "config_switch") || (value.Status != "running" && value.Status != "completed" && value.Status != "failed") || value.StartedAt.IsZero() || value.RecordsRead < 0 || value.RecordsEmitted < 0 || value.RecordsSkipped < 0 || value.RecordsMalformed < 0 || value.RetryCount < 0 || value.DurationMillis < 0 || len(value.ErrorType) > 100 || !bridgeErrorTypePattern.MatchString(value.ErrorType) {
		writeError(w, http.StatusBadRequest, "bad_identity_bridge_run", "identity bridge run report is invalid")
		return
	}
	_, err := s.operations.db.ExecContext(r.Context(), `INSERT INTO identity_bridge_runs(run_id,bridge_id,kind,status,records_read,records_emitted,records_skipped,records_malformed,retry_count,duration_ms,error_type,started_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(run_id) DO UPDATE SET status=EXCLUDED.status,records_read=EXCLUDED.records_read,records_emitted=EXCLUDED.records_emitted,records_skipped=EXCLUDED.records_skipped,records_malformed=EXCLUDED.records_malformed,retry_count=GREATEST(identity_bridge_runs.retry_count,EXCLUDED.retry_count),duration_ms=EXCLUDED.duration_ms,error_type=EXCLUDED.error_type,completed_at=EXCLUDED.completed_at`, value.RunID, s.identityBridge.normalized().BridgeID, value.Kind, value.Status, value.RecordsRead, value.RecordsEmitted, value.RecordsSkipped, value.RecordsMalformed, value.RetryCount, value.DurationMillis, value.ErrorType, value.StartedAt.UTC(), value.CompletedAt)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_run_failed", "identity bridge run report could not be saved")
		return
	}
	_, _ = s.operations.db.ExecContext(r.Context(), `DELETE FROM identity_bridge_runs WHERE created_at<now()-interval '30 days'`)
	_, _ = s.operations.db.ExecContext(r.Context(), `DELETE FROM identity_snapshot_uploads WHERE status<>'completed' AND created_at<now()-interval '24 hours'`)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIdentityBridge(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations == nil || s.operations.db == nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_storage_unavailable", "identity bridge requires PostgreSQL storage")
		return
	}
	if path == "/integrations/identity/bridge/runs" && r.Method == http.MethodGet {
		s.handleIdentityBridgeRuns(w, r)
		return
	}
	if path != "/integrations/identity/bridge" {
		writeError(w, http.StatusNotFound, "identity_bridge_not_found", "identity bridge endpoint not found")
		return
	}
	if r.Method == http.MethodPut {
		s.updateIdentityBridge(w, r)
		return
	}
	if r.Method == http.MethodGet {
		s.getIdentityBridge(w, r)
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported identity bridge operation")
}

func (s *Server) updateIdentityBridge(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string `json:"host"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&request) != nil || decoder.Decode(&extra) != io.EOF || !validSRunHost(request.Host) {
		writeError(w, http.StatusBadRequest, "bad_identity_bridge_config", "请输入有效的4K地址")
		return
	}
	request.Host = normalizeIdentityBridgeHost(request.Host)
	actor := sessionFromContext(r.Context()).User.ID
	var version int64
	err := s.operations.db.QueryRowContext(r.Context(), `UPDATE identity_bridge_configs SET desired_host=$2,config_version=CASE WHEN desired_host=$2 THEN config_version ELSE config_version+1 END,updated_by=$3,updated_at=CASE WHEN desired_host=$2 THEN updated_at ELSE now() END WHERE bridge_id=$1 RETURNING config_version`, s.identityBridge.normalized().BridgeID, request.Host, actor).Scan(&version)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_config_failed", "4K地址保存失败")
		return
	}
	s.appendAudit(r.Context(), "integration.identity_bridge.configure", s.identityBridge.normalized().BridgeID, fmt.Sprintf("version=%d", version))
	writeJSON(w, http.StatusAccepted, map[string]any{"bridge_id": s.identityBridge.normalized().BridgeID, "host": request.Host, "config_version": version, "state": "switching"})
}

func normalizeIdentityBridgeHost(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return strings.Trim(value, "[]")
	}
	return strings.ToLower(value)
}

func (s *Server) getIdentityBridge(w http.ResponseWriter, r *http.Request) {
	config, err := s.identityBridgeRuntimeConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_config_unavailable", "认证同步配置读取失败")
		return
	}
	defaults := s.identityBridge.normalized()
	var activeHost, state, onlineState, eventState, snapshotState, errorType string
	var activeVersion, sourceQueue, processingQueue, onlineMembers, onlineSessions, committed, bad int64
	var eventFailures, snapshotFailures int
	var lastEvent, lastAttempt, lastSnapshot, started, heartbeat sql.NullTime
	err = s.operations.db.QueryRowContext(r.Context(), `SELECT active_host,active_config_version,state,online_channel_state,event_channel_state,snapshot_state,source_queue,processing_queue,online_members,online_sessions,committed_messages,bad_messages,event_consecutive_failures,snapshot_consecutive_failures,last_event_at,last_snapshot_attempt_at,last_snapshot_at,last_error_type,started_at,heartbeat_at FROM identity_bridge_runtime WHERE bridge_id=$1`, defaults.BridgeID).Scan(&activeHost, &activeVersion, &state, &onlineState, &eventState, &snapshotState, &sourceQueue, &processingQueue, &onlineMembers, &onlineSessions, &committed, &bad, &eventFailures, &snapshotFailures, &lastEvent, &lastAttempt, &lastSnapshot, &errorType, &started, &heartbeat)
	if err != nil && err != sql.ErrNoRows {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_status_unavailable", "认证同步状态读取失败")
		return
	}
	if err == sql.ErrNoRows {
		state, onlineState, eventState, snapshotState = "starting", "pending", "pending", "pending"
	}
	now := time.Now().UTC()
	if heartbeat.Valid && now.Sub(heartbeat.Time) > 15*time.Second {
		state = "failed"
	}
	if lastSnapshot.Valid && now.Sub(lastSnapshot.Time) > time.Duration(3*defaults.ReconcileIntervalSeconds)*time.Second && state == "healthy" {
		state, snapshotState = "degraded", "stale"
	}
	var accounts, sessions int
	var latestProjection sql.NullTime
	_ = s.operations.db.QueryRowContext(r.Context(), `SELECT count(DISTINCT account_id),count(DISTINCT session_id),max(confirmed_at) FROM account_identity_session_projection WHERE source=$1 AND sensor_id=$2 AND COALESCE(document->>'ended_at','')=''`, defaults.Source, defaults.SensorID).Scan(&accounts, &sessions, &latestProjection)
	runtime := map[string]any{
		"state": state, "active_host": activeHost, "active_config_version": activeVersion,
		"active_online_redis_addr": func() string {
			if activeHost == "" {
				return ""
			}
			return net.JoinHostPort(activeHost, fmt.Sprintf("%d", defaults.OnlinePort))
		}(),
		"online_channel_state": onlineState, "event_channel_state": eventState, "snapshot_state": snapshotState,
		"source_queue": sourceQueue, "processing_queue": processingQueue, "online_members": onlineMembers,
		"online_sessions": onlineSessions, "committed_messages": committed, "bad_messages": bad,
		"event_consecutive_failures": eventFailures, "snapshot_consecutive_failures": snapshotFailures,
		"last_error_type": errorType, "accounts": accounts, "sessions": sessions,
	}
	putOptionalTime(runtime, "last_event_at", lastEvent)
	putOptionalTime(runtime, "last_snapshot_attempt_at", lastAttempt)
	putOptionalTime(runtime, "last_snapshot_at", lastSnapshot)
	putOptionalTime(runtime, "started_at", started)
	putOptionalTime(runtime, "heartbeat_at", heartbeat)
	putOptionalTime(runtime, "projection_at", latestProjection)
	writeJSON(w, http.StatusOK, map[string]any{"config": config, "runtime": runtime, "checked_at": now})
}

func putOptionalTime(target map[string]any, key string, value sql.NullTime) {
	if value.Valid {
		target[key] = value.Time.UTC()
	}
}

func (s *Server) handleIdentityBridgeRuns(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	offset, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", err.Error())
		return
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if kind != "" && kind != "event_batch" && kind != "snapshot" && kind != "config_switch" || status != "" && status != "completed" && status != "failed" && status != "running" {
		writeError(w, http.StatusBadRequest, "bad_identity_bridge_filter", "同步记录筛选条件无效")
		return
	}
	defaults := s.identityBridge.normalized()
	args := []any{defaults.Source, defaults.BridgeID, kind, status}
	base := ` FROM (SELECT batch_id AS run_id,'event_batch'::text AS kind,status,records_read,records_emitted,records_skipped,records_malformed,retry_count,COALESCE((EXTRACT(EPOCH FROM (completed_at-received_at))*1000)::bigint,0) AS duration_ms,CASE WHEN COALESCE(error_message,'')='' THEN '' ELSE 'ingest_error' END AS error_type,received_at AS started_at,completed_at FROM identity_ingest_batches WHERE source=$1 UNION ALL SELECT run_id,kind,status,records_read,records_emitted,records_skipped,records_malformed,retry_count,duration_ms,error_type,started_at,completed_at FROM identity_bridge_runs WHERE bridge_id=$2) runs WHERE ($3='' OR kind=$3) AND ($4='' OR status=$4)`
	var total int
	if err = s.operations.db.QueryRowContext(r.Context(), `SELECT count(*)`+base, args...).Scan(&total); err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_runs_unavailable", "同步记录读取失败")
		return
	}
	rows, err := s.operations.db.QueryContext(r.Context(), `SELECT run_id,kind,status,records_read,records_emitted,records_skipped,records_malformed,retry_count,duration_ms,error_type,started_at,completed_at`+base+` ORDER BY started_at DESC,run_id DESC LIMIT $5 OFFSET $6`, append(args, limit, offset)...)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_runs_unavailable", "同步记录读取失败")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, itemKind, itemStatus, itemError string
		var read, emitted, skipped, malformed, retries int
		var duration int64
		var started time.Time
		var completed sql.NullTime
		if rows.Scan(&id, &itemKind, &itemStatus, &read, &emitted, &skipped, &malformed, &retries, &duration, &itemError, &started, &completed) != nil {
			writeError(w, http.StatusServiceUnavailable, "identity_bridge_runs_unavailable", "同步记录读取失败")
			return
		}
		item := map[string]any{"run_id": id, "kind": itemKind, "status": itemStatus, "records_read": read, "records_emitted": emitted, "records_skipped": skipped, "records_malformed": malformed, "retry_count": retries, "duration_ms": duration, "started_at": started.UTC()}
		if itemError != "" {
			item["error_type"] = itemError
		}
		if completed.Valid {
			item["completed_at"] = completed.Time.UTC()
		}
		items = append(items, item)
	}
	var next *string
	if offset+len(items) < total {
		value := fmt.Sprintf("%d", offset+len(items))
		next = &value
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": Page{Limit: limit, NextCursor: next, Total: total}})
}
