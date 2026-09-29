package controlplane

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"proxy-sentinel/internal/discovery"
	"strings"
)

func (s *Server) handleDiscoveryActive(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations == nil || s.operations.db == nil {
		writeError(w, 503, "storage_required", "网络发现需要 PostgreSQL")
		return
	}
	if r.Method != "GET" && s.readOnly {
		writeError(w, 403, "read_only", "只读模式不允许探测配置")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	repo := discovery.Repository{DB: s.operations.db}
	if path == "/discovery/scan-profiles" && r.Method == "GET" {
		rows, e := repo.DB.QueryContext(ctx, `SELECT config,version,trial_version,enabled FROM discovery_scan_profiles ORDER BY id`)
		if e != nil {
			writeError(w, 500, "profile_read", "读取配置失败")
			return
		}
		defer rows.Close()
		items := []discovery.ScanProfile{}
		for rows.Next() {
			var b []byte
			var p discovery.ScanProfile
			var version, trial int
			var enabled bool
			if e = rows.Scan(&b, &version, &trial, &enabled); e != nil {
				writeError(w, 500, "profile_read", "读取配置失败")
				return
			}
			if json.Unmarshal(b, &p) != nil {
				writeError(w, 500, "profile_read", "配置格式异常")
				return
			}
			p.Version = version
			p.TrialVersion = trial
			p.Enabled = enabled
			items = append(items, p)
		}
		if rows.Err() != nil {
			writeError(w, 500, "profile_read", "读取配置失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}
	if path == "/discovery/scan-profiles" && r.Method == "POST" {
		var p discovery.ScanProfile
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&p) != nil || p.ID == "" || p.Node == "" || p.Site == "" || p.Domain == "" {
			writeError(w, 400, "bad_profile", "标识、采集节点、站点和网络范围必填")
			return
		}
		if p.Config.IntervalSeconds == 0 {
			p.Config.IntervalSeconds = 86400
		}
		if e := p.Config.Validate(); e != nil {
			writeError(w, 400, "bad_profile", e.Error())
			return
		}
		tx, e := repo.DB.BeginTx(ctx, nil)
		if e != nil {
			writeError(w, 500, "profile_save", "保存失败")
			return
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "discovery-profile:"+p.ID); e != nil {
			writeError(w, 500, "profile_save", "保存失败")
			return
		}
		var oldVersion int
		e = tx.QueryRowContext(ctx, `SELECT version FROM discovery_scan_profiles WHERE id=$1`, p.ID).Scan(&oldVersion)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			writeError(w, 500, "profile_save", "保存失败")
			return
		}
		if oldVersion != p.Version {
			writeError(w, 409, "version_conflict", "配置已变化，请刷新")
			return
		}
		p.Targets = nil
		p.Version++
		p.Enabled = false
		p.TrialVersion = 0
		b, _ := json.Marshal(p)
		_, e = tx.ExecContext(ctx, `INSERT INTO discovery_scan_profiles(id,node,config,version) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET node=EXCLUDED.node,config=EXCLUDED.config,version=EXCLUDED.version,trial_version=0,enabled=false,updated_at=now()`, p.ID, p.Node, b, p.Version)
		if e == nil {
			_, e = tx.ExecContext(ctx, `UPDATE discovery_tasks SET cancel_requested=true,status=CASE WHEN status='pending' THEN 'cancelled' ELSE status END WHERE profile_id=$1 AND status IN ('pending','running')`, p.ID)
		}
		if e == nil {
			_, e = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'discovery.scan.configure',$3,'saved-disabled',now())`, "discovery-"+shortToken(16), sessionFromContext(ctx).User.ID, p.ID)
		}
		if e != nil {
			writeError(w, 500, "profile_save", "保存失败")
			return
		}
		if tx.Commit() != nil {
			writeError(w, 500, "profile_save", "保存失败")
			return
		}
		writeJSON(w, 200, p)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/discovery/scan-profiles/"), "/")
	if len(parts) != 2 || r.Method != "POST" {
		writeError(w, 404, "not_found", "接口不存在")
		return
	}
	id, action := parts[0], parts[1]
	switch action {
	case "trial":
		task := "scan-" + shortToken(24)
		if e := repo.EnqueueScan(ctx, task, id); e != nil {
			writeError(w, 409, "scan_pending", e.Error())
			return
		}
		s.appendAudit(ctx, "discovery.scan.trial", id, "queued")
		writeJSON(w, 202, map[string]string{"id": task, "status": "pending"})
	case "schedule":
		var req struct {
			Enabled bool `json:"enabled"`
			Version int  `json:"version"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
			writeError(w, 400, "bad_schedule", "请求无效")
			return
		}
		result, e := repo.DB.ExecContext(ctx, `UPDATE discovery_scan_profiles SET enabled=$2,next_scan=now()+make_interval(secs=>greatest(3600,(config->'config'->>'interval_seconds')::int)) WHERE id=$1 AND version=$3 AND (NOT $2 OR trial_version=version)`, id, req.Enabled, req.Version)
		if e != nil {
			writeError(w, 500, "schedule_failed", "更新失败")
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			writeError(w, 409, "trial_required", "当前版本须先完成试扫")
			return
		}
		s.appendAudit(ctx, "discovery.scan.schedule", id, "updated")
		writeJSON(w, 200, map[string]bool{"enabled": req.Enabled})
	default:
		writeError(w, 404, "not_found", "接口不存在")
	}
}
