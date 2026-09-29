package controlplane

import (
	"context"
	"encoding/json"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
)

// A collector heartbeat alone is not proof that an evidence window was covered.
// Coverage facts must identify the same source/scope and the entire measured interval.
type sharedCaptureCoverage struct {
	SchemaVersion string    `json:"schema_version"`
	CampusID      string    `json:"campus_id"`
	AccessDomain  string    `json:"access_domain"`
	CoveredFrom   time.Time `json:"covered_from"`
	CoveredTo     time.Time `json:"covered_to"`
	Complete      *bool     `json:"complete"`
	Stopped       *bool     `json:"stopped"`
	Truncated     *bool     `json:"query_truncated"`
	Dropped       *int64    `json:"dropped_packets"`
}

func coverageBlockers(w sharedaccess.Window, diagnostics []ingest.Diagnostic, now time.Time) []string {
	if len(w.Sources) == 0 || w.CampusID == "" || w.AccessDomain == "" {
		return []string{"capture_scope_missing"}
	}
	blockers := []string{}
	for _, source := range w.Sources {
		var chosen *ingest.Diagnostic
		var timestamp time.Time
		var coverage sharedCaptureCoverage
		for i := range diagnostics {
			d := &diagnostics[i]
			if d.SensorID != w.SensorID || d.Collector.Kind != source || d.Stage != "capture_health" || d.Type != "capture_coverage" {
				continue
			}
			raw, err := json.Marshal(d.Details)
			if err != nil {
				continue
			}
			var c sharedCaptureCoverage
			if d.Details["schema_version"] != "capture-coverage/v1" || d.Details["campus_id"] != w.CampusID || d.Details["access_domain"] != w.AccessDomain {
				continue
			}
			if json.Unmarshal(raw, &c) != nil {
				c = sharedCaptureCoverage{}
			}
			at, err := time.Parse(time.RFC3339Nano, d.Timestamp)
			if err != nil {
				continue
			}
			if chosen == nil || at.After(timestamp) || (at.Equal(timestamp) && d.DiagnosticID > chosen.DiagnosticID) {
				chosen = d
				timestamp = at
				coverage = c
			}
		}
		reason := ""
		switch {
		case chosen == nil:
			reason = "capture_coverage_not_verified"
		case timestamp.After(now) || now.Sub(timestamp) > 5*time.Second:
			reason = "capture_heartbeat_stale"
		case coverage.Complete == nil || coverage.Stopped == nil || coverage.Truncated == nil || coverage.Dropped == nil:
			reason = "capture_health_fields_missing"
		case *coverage.Stopped:
			reason = "capture_stopped"
		case *coverage.Dropped < 0:
			reason = "capture_health_invalid"
		case *coverage.Dropped > 0:
			reason = "capture_packets_dropped"
		case *coverage.Truncated:
			reason = "capture_query_truncated"
		case !*coverage.Complete:
			reason = "capture_coverage_incomplete"
		case coverage.CoveredFrom.IsZero() || coverage.CoveredTo.IsZero() || coverage.CoveredTo.Before(coverage.CoveredFrom) || coverage.CoveredTo.After(timestamp) || coverage.CoveredFrom.After(w.From) || coverage.CoveredTo.Before(w.To):
			reason = "capture_window_not_covered"
		}
		if reason != "" {
			blockers = appendUnique(blockers, reason)
		}
	}
	return blockers
}
func (s *Server) sharedCoverageDiagnostics(ctx context.Context) ([]ingest.Diagnostic, error) {
	// Per configured sensor reads are bounded. Hitting the bound invalidates coverage,
	// because a source's latest health fact could have been excluded.
	result := []ingest.Diagnostic{}
	seen := map[string]bool{}
	for _, source := range s.sharedConfig.Sources {
		if seen[source.SensorID] {
			continue
		}
		seen[source.SensorID] = true
		items, err := s.reader.ListIngestDiagnostics(ctx, store.Query{SensorID: source.SensorID, DiagnosticStage: "capture_health", DiagnosticType: "capture_coverage", From: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), Limit: 100})
		if err != nil {
			return nil, err
		}
		if len(items) >= 100 {
			return nil, errSharedCoverageTruncated{}
		}
		result = append(result, items...)
	}
	return result, nil
}

type errSharedCoverageTruncated struct{}

func (errSharedCoverageTruncated) Error() string { return "capture diagnostic query truncated" }
