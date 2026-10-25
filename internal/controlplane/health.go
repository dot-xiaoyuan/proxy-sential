package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/store"
)

type componentHealth struct {
	Status    string            `json:"status"`
	Error     string            `json:"error,omitempty"`
	UpdatedAt string            `json:"updated_at,omitempty"`
	Signals   []signalFreshness `json:"signals,omitempty"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, ready := s.healthSnapshot(ctx)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if os.Getenv("PROXY_SENTINEL_DISCOVERY_V2") == "true" {
		s.discoveryPipelineMetrics(ctx, w)
	}
	status, err := s.reader.IngestStatus(ctx)
	readyValue := 0
	if ready {
		readyValue = 1
	}
	fmt.Fprintf(w, "# HELP proxy_sentinel_ready Whether required control-plane components are ready.\n# TYPE proxy_sentinel_ready gauge\nproxy_sentinel_ready %d\n", readyValue)
	rootFilesystem, rootErr := readRootFilesystemStatus()
	writeRootFilesystemMetrics(w, rootFilesystem, errorString(rootErr))
	healthy := 0
	if err == nil && status.Healthy {
		healthy = 1
	}
	fmt.Fprintf(w, "# HELP proxy_sentinel_ingest_healthy Whether the latest ingest state is healthy.\n# TYPE proxy_sentinel_ingest_healthy gauge\nproxy_sentinel_ingest_healthy{sensor_id=%s} %d\n", strconv.Quote(status.SensorID), healthy)
	for _, name := range []string{"read", "emitted", "skipped", "malformed"} {
		fmt.Fprintf(w, "proxy_sentinel_ingest_last_batch_records{sensor_id=%s,result=%s} %d\n", strconv.Quote(status.SensorID), strconv.Quote(name), status.LastCounters[name])
	}
	if timestamp, parseErr := time.Parse(time.RFC3339Nano, status.LatestRunAt); parseErr == nil {
		fmt.Fprintf(w, "proxy_sentinel_ingest_last_activity_timestamp_seconds{sensor_id=%s} %d\n", strconv.Quote(status.SensorID), timestamp.Unix())
	}
	diagnostics, diagnosticErr := s.reader.ListIngestDiagnostics(ctx, store.Query{SensorID: status.SensorID, Limit: 100})
	if diagnosticErr == nil {
		seen := map[string]bool{}
		for _, item := range diagnostics {
			key := item.Collector.Kind
			if key == "" || seen[key] || item.Stage != "realtime_ingest" {
				continue
			}
			seen[key] = true
			labels := fmt.Sprintf("sensor_id=%s,source_kind=%s", strconv.Quote(status.SensorID), strconv.Quote(key))
			fmt.Fprintf(w, "proxy_sentinel_ingest_lag_bytes{%s} %.0f\n", labels, metricNumber(item.Details["lag_bytes"]))
			fmt.Fprintf(w, "proxy_sentinel_ingest_clickhouse_write_milliseconds{%s} %.0f\n", labels, metricNumber(item.Details["clickhouse_event_write_ms"]))
			fmt.Fprintf(w, "proxy_sentinel_ingest_postgresql_write_milliseconds{%s} %.0f\n", labels, metricNumber(item.Details["postgres_collector_write_ms"]))
			read := item.Counters["read"]
			badRate := 0.0
			if read > 0 {
				badRate = float64(item.Counters["malformed"]) / float64(read)
			}
			fmt.Fprintf(w, "proxy_sentinel_ingest_malformed_ratio{%s} %g\n", labels, badRate)
		}
	}
	s.signalMetrics(w)
	s.applicationMetrics(ctx, w)
	s.identityMetrics(ctx, w)
}

func (s *Server) signalMetrics(w http.ResponseWriter) {
	if s.signalFreshness == nil {
		return
	}
	snapshot := s.signalFreshness.current()
	if len(snapshot.signals) == 0 {
		return
	}
	fmt.Fprint(w, "# HELP proxy_sentinel_signal_age_seconds Seconds since the newest normalized event of an expected signal; absent when none arrived in the lookback window.\n# TYPE proxy_sentinel_signal_age_seconds gauge\n")
	for _, item := range snapshot.signals {
		if item.AgeSeconds != nil {
			fmt.Fprintf(w, "proxy_sentinel_signal_age_seconds{signal=%s} %d\n", strconv.Quote(item.Signal), *item.AgeSeconds)
		}
	}
	fmt.Fprint(w, "# HELP proxy_sentinel_signal_stale Whether an expected signal is older than its configured maximum age or missing.\n# TYPE proxy_sentinel_signal_stale gauge\n")
	for _, item := range snapshot.signals {
		stale := 0
		if item.Status != "ready" {
			stale = 1
		}
		fmt.Fprintf(w, "proxy_sentinel_signal_stale{signal=%s} %d\n", strconv.Quote(item.Signal), stale)
	}
}

func metricNumber(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	}
	return 0
}

// Independent health probes share the request deadline, but never wait behind
// optional read-model work before checking mandatory storage or authentication.
func (s *Server) healthSnapshot(ctx context.Context) (map[string]componentHealth, bool) {
	components := map[string]componentHealth{}
	ready := true
	type probeResult struct {
		name   string
		health componentHealth
	}
	results := make(chan probeResult, 12)
	pending := map[string]bool{}
	launch := func(name string, required bool, probe func() componentHealth) {
		pending[name] = required
		go func() { results <- probeResult{name: name, health: probe()} }()
	}
	check := func(name string, required bool, probe func() error) {
		launch(name, required, func() componentHealth {
			item := componentHealth{Status: "ready"}
			if err := probe(); err != nil {
				item.Status = "delayed"
				if required {
					item.Status = "unavailable"
				}
				item.Error = err.Error()
			}
			return item
		})
	}
	check("operations", true, func() error { return s.operations.health(ctx) })
	if models, ok := s.reader.(interface{ StatisticsReadModelHealth(context.Context) error }); ok {
		check("statistics_read_model", false, func() error { return models.StatisticsReadModelHealth(ctx) })
	}
	if checker, ok := s.reader.(interface{ Health(context.Context) error }); ok {
		check("storage", true, func() error { return checker.Health(ctx) })
	} else {
		components["storage"] = componentHealth{Status: "file_mode"}
	}
	if s.applications != nil && s.applications.Status().Enabled {
		if models, ok := s.reader.(interface{ ApplicationReadModelHealth(context.Context) error }); ok {
			check("application_read_model", false, func() error { return models.ApplicationReadModelHealth(ctx) })
		}
	}
	if s.auth != nil && s.auth.db != nil {
		check("authentication", true, func() error { return s.auth.db.PingContext(ctx) })
	} else if s.auth != nil && s.auth.enabled {
		components["authentication"] = componentHealth{Status: "file_mode"}
	} else {
		components["authentication"] = componentHealth{Status: "disabled"}
	}
	if s.oidcError != "" {
		components["authentication_oidc"] = componentHealth{Status: "unavailable", Error: s.oidcError}
		ready = false
	} else if s.oidc != nil {
		components["authentication_oidc"] = componentHealth{Status: "ready"}
	} else {
		components["authentication_oidc"] = componentHealth{Status: "disabled"}
	}
	if s.operations != nil && s.operations.db != nil {
		if os.Getenv("PROXY_SENTINEL_DISCOVERY_V2") == "true" {
			launch("discovery_pipeline", false, func() componentHealth { return s.discoveryPipelineHealth(ctx) })
		}
		launch("inventory_projection", false, func() componentHealth { return inventoryProjectionHealth(ctx, s.operations.db) })
	}
	if s.identityIngest != nil && s.identityIngest.db != nil {
		check("identity_ingest", true, func() error { return s.identityIngest.db.PingContext(ctx) })
		// Acceptance only needs the database; processing progress is reported separately so
		// a stalled inbox is visible instead of hiding behind a successful ping. The field
		// reported identity_ingest ready while 62k records waited for 2.5 hours.
		launch("identity_pipeline", false, func() componentHealth { return identityPipelineHealth(ctx, s.identityIngest.db) })
	} else {
		components["identity_ingest"] = componentHealth{Status: "memory_mode"}
	}
	// Signal arrival is reported but never required: readiness gates release
	// switches, and an intentionally disabled collector or a quiet campus must
	// not roll a healthy release back. The system status reports it as degraded.
	if s.signalFreshness != nil {
		snapshot := s.signalFreshness.current()
		health := snapshot.health
		health.Signals = snapshot.signals
		components["signals"] = health
	}
	launch("collector", true, func() componentHealth {
		var runs []store.Run
		var err error
		if scoped, ok := s.reader.(interface {
			ListSensorRuns(context.Context, string, int) ([]store.Run, error)
		}); ok {
			runs, err = scoped.ListSensorRuns(ctx, s.sensorID, 1)
		} else {
			runs, err = s.reader.ListRuns(ctx, 1)
			// Legacy readers may lack a scoped path. An unrelated latest run
			// is not evidence that the configured sensor is active.
			if len(runs) > 0 && runs[0].SensorID != s.sensorID {
				runs = nil
			}
		}
		if err != nil {
			return componentHealth{Status: "unavailable", Error: err.Error()}
		}
		if len(runs) == 0 {
			return componentHealth{Status: "no_data"}
		}
		status := "ready"
		finished, parseErr := time.Parse(time.RFC3339Nano, runs[0].FinishedAt)
		if parseErr != nil {
			return componentHealth{Status: "unavailable", Error: "collector completion timestamp is invalid"}
		}
		if finished.After(time.Now().Add(5 * time.Second)) {
			return componentHealth{Status: "unavailable", Error: "collector completion timestamp is in the future", UpdatedAt: runs[0].FinishedAt}
		}
		if time.Since(finished) > 30*time.Minute {
			status = "stale"
		} else if runs[0].Normalized.Read == 0 {
			status = "idle"
		}
		return componentHealth{Status: status, UpdatedAt: runs[0].FinishedAt}
	})
	accept := func(result probeResult) {
		required, exists := pending[result.name]
		if !exists {
			return
		}
		if required && result.health.Status == "unavailable" {
			ready = false
		}
		components[result.name] = result.health
		delete(pending, result.name)
	}
	for len(pending) > 0 {
		select {
		case result := <-results:
			accept(result)
		case <-ctx.Done():
			// Results completed before the deadline can already be buffered. Preserve
			// those successes before marking only unfinished probes as timed out.
			for {
				select {
				case result := <-results:
					accept(result)
				default:
					for name, required := range pending {
						status := "delayed"
						if required {
							status = "unavailable"
							ready = false
						}
						components[name] = componentHealth{Status: status, Error: ctx.Err().Error()}
					}
					return components, ready
				}
			}
		}
	}
	return components, ready
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	components, ready := s.healthSnapshot(ctx)
	statusCode := http.StatusOK
	status := "ready"
	if !ready {
		statusCode = http.StatusServiceUnavailable
		status = "not_ready"
	}
	writeJSON(w, statusCode, map[string]any{"status": status, "components": components, "checked_at": time.Now().UTC().Format(time.RFC3339Nano)})
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	components, ready := s.healthSnapshot(ctx)
	status := "ready"
	if !ready || components["signals"].Status == "stale" {
		status = "degraded"
	}
	ingestStatus, ingestErr := s.reader.IngestStatus(ctx)
	readModels := map[string]any{}
	if statusReader, ok := s.reader.(interface {
		ReadModelStatus(context.Context) (map[string]any, error)
	}); ok {
		var statusErr error
		readModels, statusErr = statusReader.ReadModelStatus(ctx)
		if statusErr != nil {
			readModels = map[string]any{"error": statusErr.Error()}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                   status,
		"components":               components,
		"fingerprint_library":      s.fingerprints.Status(),
		"fingerprint_offline_mode": s.fingerprintOffline,
		"global_read_only":         s.readOnly,
		"ingest":                   ingestStatus,
		"ingest_error":             errorString(ingestErr),
		"read_models":              readModels,
		"runtime":                  captureRuntimeStatus(s.runtimeSampler, s.startedAt),
		"checked_at":               time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// identityPipelineHealth classifies inbox processing by backlog age, never by liveness.
func identityPipelineHealth(ctx context.Context, db *sql.DB) componentHealth {
	var pending int64
	var oldest sql.NullTime
	var lastError string
	err := db.QueryRowContext(ctx, store.IdentityScopeStatusSQL(`SELECT COALESCE(sum(pending_records),0),min(oldest_pending_at) FILTER (WHERE pending_records>0),COALESCE(string_agg(DISTINCT nullif(last_error,''),','),'') FROM identity_pipeline_scopes WHERE enabled`)).Scan(&pending, &oldest, &lastError)
	if err != nil {
		return componentHealth{Status: "unavailable", Error: err.Error()}
	}
	return classifyIdentityPipeline(pending, oldest, lastError, time.Now())
}

func classifyIdentityPipeline(pending int64, oldest sql.NullTime, lastError string, now time.Time) componentHealth {
	if pending == 0 || !oldest.Valid {
		return componentHealth{Status: "ready"}
	}
	age := now.Sub(oldest.Time)
	item := componentHealth{Status: "ready", UpdatedAt: oldest.Time.UTC().Format(time.RFC3339Nano)}
	switch {
	case age > 5*time.Minute:
		item.Status = "stale"
	case age > 5*time.Second:
		item.Status = "delayed"
	}
	if lastError != "" && item.Status != "ready" {
		item.Status = "failed"
	}
	if item.Status != "ready" {
		item.Error = fmt.Sprintf("pending_records=%d oldest_pending_age=%s last_error=%s", pending, age.Round(time.Second), lastError)
	}
	return item
}

// inventoryProjectionHealth reports the terminal read model updater's progress: failed
// while its last round errored, stale/delayed by the age of its last successful round.
func inventoryProjectionHealth(ctx context.Context, db *sql.DB) componentHealth {
	var lastError string
	var success sql.NullTime
	var complete bool
	err := db.QueryRowContext(ctx, `SELECT bootstrap_complete,last_error,last_success_at FROM endpoint_state_watermark WHERE singleton`).Scan(&complete, &lastError, &success)
	if err == sql.ErrNoRows {
		return componentHealth{Status: "no_data"}
	}
	if err != nil {
		return componentHealth{Status: "unavailable", Error: err.Error()}
	}
	item := classifyInventoryProjection(success, lastError != "", time.Now())
	if item.Status == "ready" && !complete {
		item.Status, item.Error = "delayed", "endpoint state bootstrap in progress"
	}
	return item
}

func classifyInventoryProjection(lastSuccess sql.NullTime, failed bool, now time.Time) componentHealth {
	item := componentHealth{Status: "ready"}
	if !lastSuccess.Valid {
		item.Status, item.Error = "stale", "endpoint state updater has not completed a round"
	} else {
		item.UpdatedAt = lastSuccess.Time.UTC().Format(time.RFC3339Nano)
		switch age := now.Sub(lastSuccess.Time); {
		case age > 5*time.Minute:
			item.Status, item.Error = "stale", fmt.Sprintf("last_success_age=%s", age.Round(time.Second))
		case age > 90*time.Second:
			item.Status, item.Error = "delayed", fmt.Sprintf("last_success_age=%s", age.Round(time.Second))
		}
	}
	// A failing endpoint is reported even when the healthy queue is empty.
	if failed {
		item.Status = "failed"
		item.Error = strings.TrimSpace(item.Error + " projection_failed")
	}
	return item
}
