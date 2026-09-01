package controlplane

import (
	"context"
	"net/http"
	"time"
)

type componentHealth struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
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
	check("operations", s.operations.health(ctx))
	if checker, ok := s.reader.(interface{ Health(context.Context) error }); ok {
		check("storage", checker.Health(ctx))
	} else {
		components["storage"] = componentHealth{Status: "file_mode"}
	}
	if s.auth != nil && s.auth.db != nil {
		check("authentication", s.auth.db.PingContext(ctx))
	} else if s.auth != nil && s.auth.enabled {
		components["authentication"] = componentHealth{Status: "file_mode"}
	} else {
		components["authentication"] = componentHealth{Status: "disabled"}
	}
	if s.identityIngest != nil && s.identityIngest.db != nil {
		check("identity_ingest", s.identityIngest.db.PingContext(ctx))
	} else {
		components["identity_ingest"] = componentHealth{Status: "memory_mode"}
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
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                   status,
		"components":               components,
		"fingerprint_library":      s.fingerprints.Status(),
		"fingerprint_offline_mode": s.fingerprintOffline,
		"global_read_only":         s.readOnly,
		"checked_at":               time.Now().UTC().Format(time.RFC3339Nano),
	})
}
