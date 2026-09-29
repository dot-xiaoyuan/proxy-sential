package controlplane

import (
	"net/http"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

func (s *Server) handleSharedAccessStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	sources, err := s.managedIdentityRegistrations(ctx)
	if err != nil {
		writeError(w, 503, "identity_status_unavailable", "身份同步状态读取失败")
		return
	}
	now := time.Now().UTC()
	identities := []map[string]any{}
	for _, source := range sources {
		state := source.State
		blocker := source.Blocker
		fresh := source.Config.Enabled && state == "healthy" && source.ObservedAt.Valid && !source.ObservedAt.Time.After(now) && now.Sub(source.ObservedAt.Time) <= 5*time.Second
		if !source.Config.Enabled {
			state = "disabled"
			blocker = "identity_source_disabled"
		} else if state == "healthy" && !fresh {
			state = "stale"
			blocker = "identity_source_stale"
		}
		identities = append(identities, map[string]any{"connector_id": source.ID, "config_version": source.Version, "scope": source.Config.IdentityScope, "kind": source.Config.Kind, "state": state, "blocker": blocker, "fresh": fresh, "complete": fresh, "observed_at": source.ObservedAt.Time, "interval_seconds": 5, "last_success_at": source.LastSuccess.Time, "last_attempt_at": source.LastAttempt.Time, "record_count": source.RecordCount})
	}
	diagnostics, healthErr := s.sharedCoverageDiagnostics(ctx)
	coverage := []map[string]any{}
	collectionState, collectionBlocker := "unknown", "capture_coverage_not_verified"
	for _, source := range s.sharedConfig.Sources {
		window := sharedaccess.Window{SensorID: source.SensorID, CampusID: source.CampusID, AccessDomain: source.AccessDomain, Sources: []string{source.Source}, From: now.Add(-5 * time.Second), To: now.Add(-time.Second)}
		reasons := coverageBlockers(window, diagnostics, now)
		if healthErr != nil {
			reasons = []string{"capture_health_query_failed"}
		}
		state := "healthy"
		if len(reasons) > 0 {
			state = "insufficient"
		}
		coverage = append(coverage, map[string]any{"scope": source, "state": state, "blockers": reasons})
	}
	if len(coverage) > 0 {
		collectionState = "healthy"
		collectionBlocker = ""
		for _, item := range coverage {
			if item["state"] != "healthy" {
				collectionState = "insufficient"
				collectionBlocker = "capture_coverage_not_verified"
				break
			}
		}
	}
	// Configuration is not evidence of live capture coverage, policy readiness or
	// a verified controller. Until those gates are measured, return them explicitly.
	writeJSON(w, 200, map[string]any{"checked_at": now, "identity": identities, "collection": map[string]any{"state": collectionState, "blocker": collectionBlocker, "sources": coverage}, "materialization": map[string]any{"configured": len(s.sharedConfig.Sources) > 0, "state": "unknown", "blocker": "materialization_freshness_not_verified"}, "policy": map[string]any{"state": "blocked", "blocker": "shared_review_gate_not_verified"}, "controller": map[string]any{"state": "blocked", "blocker": "manual_action_not_verified"}})
}
