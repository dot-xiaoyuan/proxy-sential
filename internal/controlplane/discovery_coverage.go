package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"time"
)

type captureScopeExpiryState struct {
	Status     string `json:"status"`
	ValidUntil string `json:"valid_until,omitempty"`
}

func captureScopeExpiry(path string, now time.Time) captureScopeExpiryState {
	if path == "" {
		return captureScopeExpiryState{Status: "unconfigured"}
	}
	scope, err := normalized.LoadCaptureScope(path)
	if err != nil || scope == nil {
		return captureScopeExpiryState{Status: "invalid"}
	}
	state := captureScopeExpiryState{Status: "valid", ValidUntil: scope.ValidUntil.UTC().Format(time.RFC3339)}
	if !now.Before(scope.ValidUntil) {
		state.Status = "expired"
	} else if !now.Before(scope.ValidUntil.Add(-14 * 24 * time.Hour)) {
		state.Status = "expiring"
	}
	return state
}

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
	// The per-message DHCP source has its own durable cutover ledger. Legacy
	// Zeek protocol counters remain cumulative and may show enabled=false.
	messageRows, err := repo.DB.QueryContext(ctx, `SELECT DISTINCT ON (sensor_id) sensor_id,epoch FROM stream_source_cutovers WHERE state='active' AND parser_version='zeek-dhcp-message-v1' ORDER BY sensor_id,cutover_at DESC`)
	if err != nil {
		writeError(w, 500, "coverage_read", "读取逐消息采集源失败")
		return
	}
	messageEpochs := map[string]string{}
	for messageRows.Next() {
		var sensor, epoch string
		if err = messageRows.Scan(&sensor, &epoch); err != nil {
			break
		}
		messageEpochs[sensor] = epoch
	}
	if err == nil {
		err = messageRows.Err()
	}
	messageRows.Close()
	if err != nil {
		writeError(w, 500, "coverage_read", "读取逐消息采集源失败")
		return
	}
	var handshakeEpoch string
	if os.Getenv("PROXY_SENTINEL_DISCOVERY_HANDSHAKE_SCOPE_MAP") != "" {
		err = repo.DB.QueryRowContext(ctx, `SELECT epoch FROM stream_shared_source_cutovers WHERE sensor_id=$1 AND source_owner='handshake-sidecar' AND state='active'`, s.sensorID).Scan(&handshakeEpoch)
		if err != nil && err != sql.ErrNoRows {
			writeError(w, 500, "coverage_read", "读取握手侧车采集源失败")
			return
		}
	}
	for _, item := range items {
		if item["protocol"] == "dhcp" {
			if epoch := messageEpochs[fmt.Sprint(item["sensor_id"])]; epoch != "" {
				item["message_source_epoch"] = epoch
			}
		}
		if handshakeEpoch != "" && fmt.Sprint(item["sensor_id"]) == s.sensorID && (item["protocol"] == "http" || item["protocol"] == "tls") {
			item["handshake_source_epoch"] = handshakeEpoch
		}
	}
	freshness := coverageFreshness(ctx, repo)
	response := map[string]any{"enabled": true, "scope": discovery.PrivateDiscoveryCIDRs, "items": items, "freshness": freshness, "enrichment": enrichmentCoverage(ctx, repo), "capture_scope": captureScopeExpiry(os.Getenv("PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG"), time.Now().UTC()), "quarantine": discoveryQuarantineStatus(discoveryQuarantinePath())}
	// The event-bus read path does not use the legacy pipeline counters; avoid
	// blocking the coverage response on that historical query.
	if os.Getenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ") != "true" {
		response["pipeline"] = discoveryCoveragePipeline(ctx, repo)
	}
	writeJSON(w, 200, response)
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

func coverageFreshness(ctx context.Context, repo discovery.Repository) map[string]any {
	if os.Getenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ") == "true" {
		var last time.Time
		if err := repo.DB.QueryRowContext(ctx, `SELECT max(last_seen) FROM discovery_device_current_shadow`).Scan(&last); err != nil || last.IsZero() {
			return map[string]any{"status": "unavailable", "source": "eventbus"}
		}
		lag := time.Since(last).Seconds()
		status := "ready"
		if lag > 300 {
			status = "delayed"
		}
		return map[string]any{"status": status, "source": "eventbus", "lag_seconds": lag, "processed_at": last}
	}
	freshness, err := repo.DiscoveryFreshness(ctx)
	if err != nil {
		return map[string]any{"status": "unavailable", "source": "stream"}
	}
	return freshness
}
