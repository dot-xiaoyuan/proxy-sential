package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"proxy-sentinel/internal/store"
)

type componentHealth struct {
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, ready := s.healthSnapshot(ctx)
	status, err := s.reader.IngestStatus(ctx)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	readyValue := 0
	if ready {
		readyValue = 1
	}
	fmt.Fprintf(w, "# HELP proxy_sentinel_ready Whether required control-plane components are ready.\n# TYPE proxy_sentinel_ready gauge\nproxy_sentinel_ready %d\n", readyValue)
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
	s.applicationMetrics(ctx, w)
	s.identityMetrics(ctx, w)
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

func (s *Server) healthSnapshot(ctx context.Context) (map[string]componentHealth, bool) {
	components := map[string]componentHealth{}
	ready := true
	check := func(name string, err error) {
		item := componentHealth{Status: "ready"}
		if err != nil {
			item.Status = "unavailable"
			item.Error = err.Error()
			ready = false
		}
		components[name] = item
	}
	observe := func(name string, err error) {
		item := componentHealth{Status: "ready"}
		if err != nil {
			item.Status = "delayed"
			item.Error = err.Error()
		}
		components[name] = item
	}
	check("operations", s.operations.health(ctx))
	if models, ok := s.reader.(interface{ StatisticsReadModelHealth(context.Context) error }); ok {
		observe("statistics_read_model", models.StatisticsReadModelHealth(ctx))
	}
	if checker, ok := s.reader.(interface{ Health(context.Context) error }); ok {
		check("storage", checker.Health(ctx))
	} else {
		components["storage"] = componentHealth{Status: "file_mode"}
	}
	if s.applications != nil && s.applications.Status().Enabled {
		if models, ok := s.reader.(interface{ ApplicationReadModelHealth(context.Context) error }); ok {
			observe("application_read_model", models.ApplicationReadModelHealth(ctx))
		}
	}

	if s.auth != nil && s.auth.db != nil {
		check("authentication", s.auth.db.PingContext(ctx))
	} else if s.auth != nil && s.auth.enabled {
		components["authentication"] = componentHealth{Status: "file_mode"}
	} else {
		components["authentication"] = componentHealth{Status: "disabled"}
	}
	if s.oidcError != "" {
		check("authentication_oidc", fmt.Errorf("%s", s.oidcError))
	} else if s.oidc != nil {
		components["authentication_oidc"] = componentHealth{Status: "ready"}
	} else {
		components["authentication_oidc"] = componentHealth{Status: "disabled"}
	}
	if s.identityIngest != nil && s.identityIngest.db != nil {
		check("identity_ingest", s.identityIngest.db.PingContext(ctx))
	} else {
		components["identity_ingest"] = componentHealth{Status: "memory_mode"}
	}
	runs, err := s.reader.ListRuns(ctx, 1)
	if err != nil {
		check("collector", err)
	} else if len(runs) == 0 {
		components["collector"] = componentHealth{Status: "no_data"}
	} else {
		status := "ready"
		finished, parseErr := time.Parse(time.RFC3339Nano, runs[0].FinishedAt)
		if parseErr == nil && time.Since(finished) > 30*time.Minute {
			status = "stale"
		} else if runs[0].Normalized.Read == 0 {
			status = "idle"
		}
		components["collector"] = componentHealth{Status: status, UpdatedAt: runs[0].FinishedAt}
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
	if !ready {
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
		"checked_at":               time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
