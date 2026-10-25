package controlplane

import (
	"context"
	"net/http"
	"proxy-sentinel/internal/discovery"
	"time"
)

func (s *Server) handleDiscoveryCoverage(w http.ResponseWriter, r *http.Request, repo discovery.Repository) {
	if !repo.PipelineV2 {
		writeJSON(w, 200, map[string]any{"enabled": false, "status": "legacy", "items": []any{}})
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	rows, err := repo.DB.QueryContext(ctx, `SELECT sensor_id,protocol,owner,enabled,received,parsed,rejected,admitted,last_seen,last_success,error,updated_at FROM discovery_protocol_runtime ORDER BY sensor_id,protocol`)
	if err != nil {
		writeError(w, 500, "coverage_read", "读取协议采集状态失败")
		return
	}
	columns, err := rows.Columns()
	if err != nil {
		rows.Close()
		writeError(w, 500, "coverage_read", "读取协议采集状态失败")
		return
	}
	items := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err = rows.Scan(pointers...); err != nil {
			break
		}
		item := map[string]any{}
		for i, k := range columns {
			item[k] = values[i]
		}
		items = append(items, item)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		writeError(w, 500, "coverage_read", "读取协议采集状态失败")
		return
	}
	freshness, err := repo.DiscoveryFreshness(ctx)
	if err != nil {
		writeError(w, 500, "coverage_read", "读取发现处理进度失败")
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": true, "scope": discovery.PrivateDiscoveryCIDRs, "items": items, "freshness": freshness, "enrichment": enrichmentCoverage(ctx, repo), "pipeline": discoveryCoveragePipeline(ctx, repo)})
}

func enrichmentCoverage(ctx context.Context, repo discovery.Repository) map[string]any {
	var pending, blocked, failed int64
	if e := repo.DB.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE error IN ('scope_path_unverified','invalid_target')),count(*) FILTER(WHERE error<>'' AND error NOT IN ('scope_path_unverified','invalid_target')) FROM discovery_enrichment_work WHERE next_attempt_at<=now() OR error<>''`).Scan(&pending, &blocked, &failed); e != nil {
		return map[string]any{"status": "failed"}
	}
	return map[string]any{"pending": pending, "blocked": blocked, "failed": failed}
}

func discoveryCoveragePipeline(ctx context.Context, repo discovery.Repository) any {
	c, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	status, err := repo.PipelineStatus(c)
	if err != nil {
		return map[string]any{"status": "unavailable", "error": "discovery_pipeline_read_failed"}
	}
	return status
}
