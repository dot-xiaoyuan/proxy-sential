package controlplane

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"proxy-sentinel/internal/discovery"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request, path string) {
	if strings.HasPrefix(path, "/discovery/scan-profiles") {
		s.handleDiscoveryActive(w, r, path)
		return
	}
	if s.operations == nil || s.operations.db == nil {
		writeError(w, 503, "discovery_storage", "网络设备发现需要 PostgreSQL")
		return
	}
	if r.Method != "GET" && s.readOnly {
		writeError(w, 403, "read_only", "只读模式不允许配置发现任务")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	repo := discovery.Repository{DB: s.operations.db}
	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 200 {
			writeError(w, 400, "bad_page", "分页参数无效")
			return
		}
		limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 0 {
			writeError(w, 400, "bad_page", "分页参数无效")
			return
		}
		offset = n
	}
	switch {
	case path == "/discovery/nodes" && r.Method == "GET":
		rows, err := repo.DB.QueryContext(ctx, `SELECT node,last_seen,last_seen>now()-interval '30 seconds' FROM discovery_nodes ORDER BY node`)
		if err != nil {
			writeError(w, 500, "node_read", "读取采集节点失败")
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var node string
			var at time.Time
			var online bool
			if err = rows.Scan(&node, &at, &online); err != nil {
				writeError(w, 500, "node_read", "读取采集节点失败")
				return
			}
			items = append(items, map[string]any{"node": node, "last_seen": at, "available": online})
		}
		if rows.Err() != nil {
			writeError(w, 500, "node_read", "读取采集节点失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/endpoint-evidence" && r.Method == "GET":
		page, err := repo.EndpointEvidence(ctx, r.URL.Query().Get("endpoint_id"), limit, offset)
		if err != nil {
			writeError(w, 500, "discovery_read", "读取发现证据失败")
			return
		}
		writeJSON(w, 200, page)
	case path == "/discovery/sources" && r.Method == "GET":
		rows, err := repo.DB.QueryContext(ctx, `SELECT config FROM discovery_sources ORDER BY id`)
		if err != nil {
			writeError(w, 500, "discovery_read", "读取接入源失败")
			return
		}
		defer rows.Close()
		items := []json.RawMessage{}
		for rows.Next() {
			var b json.RawMessage
			if err = rows.Scan(&b); err != nil {
				writeError(w, 500, "discovery_read", "读取接入源失败")
				return
			}
			items = append(items, b)
		}
		if rows.Err() != nil {
			writeError(w, 500, "discovery_read", "读取接入源失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/sources" && r.Method == "POST":
		var req struct {
			Source          discovery.Source `json:"source"`
			Secret          discovery.Secret `json:"secret"`
			ExpectedVersion int              `json:"expected_version"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil {
			writeError(w, 400, "bad_source", "接入源配置无效")
			return
		}
		if err := req.Source.Validate(); err != nil {
			writeError(w, 400, "bad_source", err.Error())
			return
		}
		tx, err := repo.DB.BeginTx(ctx, nil)
		if err != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "discovery-source:"+req.Source.ID); err != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		var version int
		var encrypted string
		err = tx.QueryRowContext(ctx, `SELECT config_version,encrypted_secret FROM discovery_sources WHERE id=$1`, req.Source.ID).Scan(&version, &encrypted)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		if version != req.ExpectedVersion {
			writeError(w, 409, "version_conflict", "配置已变化，请刷新后重试")
			return
		}
		if req.Secret.Community != "" || req.Secret.Auth != "" || req.Secret.Privacy != "" {
			b, _ := json.Marshal(req.Secret)
			encrypted, err = s.encryptConnectorSecret(string(b))
			if err != nil {
				writeError(w, 503, "encryption_unavailable", "凭据加密不可用")
				return
			}
		}
		if encrypted == "" {
			writeError(w, 400, "secret_required", "需要 SNMP 只读凭据")
			return
		}
		req.Source.ConfigVersion = version + 1
		b, _ := json.Marshal(req.Source)
		_, err = tx.ExecContext(ctx, `INSERT INTO discovery_sources(id,config,encrypted_secret,config_version,node,enabled) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET config=EXCLUDED.config,encrypted_secret=EXCLUDED.encrypted_secret,config_version=EXCLUDED.config_version,node=EXCLUDED.node,enabled=EXCLUDED.enabled,updated_at=now(),next_poll=now()`, req.Source.ID, b, encrypted, req.Source.ConfigVersion, req.Source.Node, req.Source.Enabled)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'discovery.source.configure',$3,'saved',now())`, "discovery-"+shortToken(16), sessionFromContext(ctx).User.ID, req.Source.ID)
		}
		if err != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		if tx.Commit() != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		writeJSON(w, 200, req.Source)
	case strings.HasPrefix(path, "/discovery/sources/") && strings.HasSuffix(path, "/poll") && r.Method == "POST":
		source := strings.TrimSuffix(strings.TrimPrefix(path, "/discovery/sources/"), "/poll")
		id := "poll-" + shortToken(24)
		if err := repo.EnqueuePoll(ctx, id, source); err != nil {
			writeError(w, 409, "poll_pending", err.Error())
			return
		}
		s.appendAudit(ctx, "discovery.poll", source, "queued")
		writeJSON(w, 202, map[string]string{"id": id, "status": "pending"})
	case path == "/discovery/devices" && r.Method == "GET":
		window := 24 * time.Hour
		if value := r.URL.Query().Get("window"); value != "" {
			parsed, parseErr := time.ParseDuration(value)
			if parseErr != nil || parsed < 10*time.Minute || parsed > 30*24*time.Hour {
				writeError(w, 400, "bad_window", "时间窗口无效")
				return
			}
			window = parsed
		}
		page, err := repo.DevicesFiltered(ctx, discovery.DeviceQuery{Mode: r.URL.Query().Get("mode"), Window: window, Search: r.URL.Query().Get("search"), DeviceType: r.URL.Query().Get("type"), Category: r.URL.Query().Get("category"), Capability: r.URL.Query().Get("capability"), Limit: limit, Offset: offset})
		if err != nil {
			writeError(w, 500, "discovery_read", "读取发现结果失败")
			return
		}
		writeJSON(w, 200, page)
	case path == "/discovery/tasks" && r.Method == "GET":
		rows, err := repo.DB.QueryContext(ctx, `SELECT id,coalesce(source_id,''),node,kind,status,config_version,created_at,result,error,cancel_requested FROM discovery_tasks ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
		if err != nil {
			writeError(w, 500, "task_read", "读取任务失败")
			return
		}
		defer rows.Close()
		items := []discovery.Task{}
		for rows.Next() {
			var t discovery.Task
			if err = rows.Scan(&t.ID, &t.SourceID, &t.Node, &t.Kind, &t.Status, &t.Version, &t.CreatedAt, &t.Result, &t.Error, &t.CancelRequested); err != nil {
				writeError(w, 500, "task_read", "读取任务失败")
				return
			}
			items = append(items, t)
		}
		if rows.Err() != nil {
			writeError(w, 500, "task_read", "读取任务失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case strings.HasPrefix(path, "/discovery/tasks/") && strings.HasSuffix(path, "/stop") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/discovery/tasks/"), "/stop")
		_, err := repo.DB.ExecContext(ctx, `UPDATE discovery_tasks SET cancel_requested=true,status=CASE WHEN status='pending' THEN 'cancelled' ELSE status END WHERE id=$1 AND status IN ('pending','running')`, id)
		if err != nil {
			writeError(w, 500, "task_stop", "停止任务失败")
			return
		}
		s.appendAudit(ctx, "discovery.stop", id, "requested")
		writeJSON(w, 200, map[string]bool{"stopping": true})
	case path == "/discovery/preview" && r.Method == "POST":
		var cfg discovery.ScanConfig
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		dec.DisallowUnknownFields()
		if dec.Decode(&cfg) != nil {
			writeError(w, 400, "bad_scan", "探测配置无效")
			return
		}
		if err := cfg.Validate(); err != nil {
			writeError(w, 400, "bad_scan", err.Error())
			return
		}
		targets, err := cfg.Targets(nil)
		if err != nil {
			writeError(w, 400, "bad_scan", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"targets": targets, "total": len(targets), "active_enabled": false})
	case path == "/discovery/summary" && r.Method == "GET":
		var infrastructure, active, pending, passive, services, linked int
		err := repo.DB.QueryRowContext(ctx, `SELECT
 count(DISTINCT device_key) FILTER(WHERE origin IN ('fdb','neighbor','lldp','cdp')),
 count(DISTINCT device_key) FILTER(WHERE origin='active'),
	count(DISTINCT device_key) FILTER(WHERE NOT EXISTS(SELECT 1 FROM discovery_identity_links l WHERE l.observation_id=discovery_observations.id))
 FROM discovery_observations WHERE observed_at<=now() AND observed_at>=now()-interval '24 hours' AND NOT withdrawn`).Scan(&infrastructure, &active, &pending)
		if err != nil {
			writeError(w, 500, "summary_read", "读取汇总失败")
			return
		}
		passivePage, err := repo.DevicesFiltered(ctx, discovery.DeviceQuery{Mode: "passive", Window: 24 * time.Hour, Limit: 1})
		if err != nil {
			writeError(w, 500, "summary_read", "读取汇总失败")
			return
		}
		passive, _ = passivePage["total"].(int)
		services, _ = passivePage["service_devices"].(int)
		linked, _ = passivePage["linked_endpoints"].(int)
		var enabled bool
		if err = repo.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_scan_profiles WHERE enabled)`).Scan(&enabled); err != nil {
			writeError(w, 500, "summary_read", "读取汇总失败")
			return
		}
		var lastSuccess sql.NullTime
		var materializerStatus, materializerError string
		var protocolCounts, skipCounts json.RawMessage
		var processed, emitted, skipped int64
		_ = repo.DB.QueryRowContext(ctx, `SELECT last_success_at,CASE WHEN last_error<>'' THEN 'error' WHEN last_success_at IS NULL THEN 'waiting' WHEN last_success_at<now()-interval '2 minutes' THEN 'lagging' ELSE 'ready' END,last_error,protocol_counts,skip_counts,processed_events,emitted_observations,skipped_events FROM passive_discovery_state ORDER BY updated_at DESC LIMIT 1`).Scan(&lastSuccess, &materializerStatus, &materializerError, &protocolCounts, &skipCounts, &processed, &emitted, &skipped)
		response := map[string]any{"window": "24h", "infrastructure": infrastructure, "active_responses": active, "pending_association": pending, "passive_devices": passive, "service_devices": services, "linked_endpoints": linked, "active_enabled": enabled, "materializer_status": materializerStatus, "materializer_error": materializerError}
		if len(protocolCounts) > 0 {
			response["protocol_counts"] = protocolCounts
		}
		if len(skipCounts) > 0 {
			response["skip_counts"] = skipCounts
		}
		response["processed_events"], response["emitted_observations"], response["skipped_events"] = processed, emitted, skipped
		if lastSuccess.Valid {
			response["last_materialized_at"] = lastSuccess.Time
		}
		writeJSON(w, 200, response)
	default:
		writeError(w, 404, "not_found", "发现接口不存在")
	}
}
