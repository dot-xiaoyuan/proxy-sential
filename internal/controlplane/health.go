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

// Independent health probes share the request deadline, but never wait behind
// optional read-model work before checking mandatory storage or authentication.
func (s *Server) healthSnapshot(ctx context.Context) (map[string]componentHealth, bool) {
	components := map[string]componentHealth{}
	ready := true
	type probeResult struct {
		name   string
		health componentHealth
	}
	results := make(chan probeResult, 8)
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
	if s.identityIngest != nil && s.identityIngest.db != nil {
		check("identity_ingest", true, func() error { return s.identityIngest.db.PingContext(ctx) })
	} else {
		components["identity_ingest"] = componentHealth{Status: "memory_mode"}
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
