package controlplane

import (
	"net/http"
	"strconv"
	"time"

	"proxy-sentinel/internal/store"
)

func (s *Server) handleAttributionDiagnostics(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(store.AttributionDiagnosticReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "attribution_diagnostics_unavailable", "attribution diagnostics require database storage")
		return
	}
	params := r.URL.Query()
	now := time.Now().UTC()
	from, to := params.Get("from"), params.Get("to")
	if from == "" {
		from = now.Add(-24 * time.Hour).Format(time.RFC3339)
	}
	if to == "" {
		to = now.Format(time.RFC3339)
	}
	limit, err := boundedInt(params.Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	offset, err := cursorOffset(params.Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", err.Error())
		return
	}
	query := store.AttributionDiagnosticQuery{From: from, To: to, SensorID: params.Get("sensor_id"), Status: params.Get("status"), Reason: params.Get("reason"), RuleVersion: params.Get("rule_version"), Limit: limit, Offset: offset}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	result, err := reader.ListAttributionDiagnostics(ctx, query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_attribution_query", err.Error())
		return
	}
	var next *string
	if offset+len(result.Items) < result.Total {
		value := strconv.Itoa(offset + len(result.Items))
		next = &value
	}
	writeJSON(w, http.StatusOK, struct {
		Items []store.AttributionDiagnostic `json:"items"`
		Page  Page                          `json:"page"`
	}{Items: result.Items, Page: Page{Limit: limit, NextCursor: next, Total: result.Total}})
}

func (s *Server) handleAttributionComparison(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(store.AttributionComparisonReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "attribution_comparison_unavailable", "attribution comparison requires database storage")
		return
	}
	params := r.URL.Query()
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	result, err := reader.CompareAttributionVersions(ctx, params.Get("from"), params.Get("to"), params.Get("sensor_id"), params.Get("before_version"), params.Get("after_version"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_attribution_comparison", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
