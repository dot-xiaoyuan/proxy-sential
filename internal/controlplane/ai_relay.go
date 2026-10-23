package controlplane

import (
	"context"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/airelay"
	"proxy-sentinel/internal/store"
)

func (s *Server) handleAIRelayIndicators(w http.ResponseWriter, r *http.Request) {
	m := airelay.Default()
	writeJSON(w, http.StatusOK, map[string]any{
		"version": m.Version(), "updated_at": m.UpdatedAt(),
		"indicators": m.Indicators(), "official_domains": m.OfficialDomains(), "sources": m.Sources(),
	})
}

func (s *Server) handleAIRelayUsages(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(interface {
		ListAIRelayUsage(context.Context, store.AIRelayUsageQuery) (store.AIRelayUsagePage, error)
	})
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "ai_relay_unavailable", "AI relay query is unavailable")
		return
	}
	now := time.Now().UTC()
	q := store.AIRelayUsageQuery{From: now.Add(-24 * time.Hour), To: now, IP: strings.TrimSpace(r.URL.Query().Get("ip")), Domain: strings.TrimSpace(r.URL.Query().Get("domain")), CampusID: strings.TrimSpace(r.URL.Query().Get("campus_id")), SensorID: strings.TrimSpace(r.URL.Query().Get("sensor_id")), Cursor: strings.TrimSpace(r.URL.Query().Get("cursor"))}
	if q.Cursor != "" {
		q.Cursor = strings.TrimSpace(q.Cursor)
	}
	var err error
	q.Limit, err = boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	if raw := r.URL.Query().Get("from"); raw != "" {
		q.From, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_from", "from must be RFC3339")
			return
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		q.To, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_to", "to must be RFC3339")
			return
		}
	}
	if !q.From.Before(q.To) || q.To.After(now.Add(time.Minute)) || q.To.Sub(q.From) > 7*24*time.Hour || q.From.Before(now.Add(-7*24*time.Hour-time.Minute)) {
		writeError(w, http.StatusBadRequest, "bad_time_range", "range must be within retained 7 days")
		return
	}
	page, err := reader.ListAIRelayUsage(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_relay_query_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}
