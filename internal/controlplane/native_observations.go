package controlplane

import (
	"context"
	"net/http"
	"proxy-sentinel/internal/srunapi"
	"strconv"
	"time"
)

func (s *Server) handleNativeActionObservations(w http.ResponseWriter, r *http.Request, id string) {
	s.operations.mu.Lock()
	action, ok := s.operations.doc.Actions[id]
	db := s.operations.db
	s.operations.mu.Unlock()
	if !ok {
		writeError(w, 404, "action_not_found", "action not found")
		return
	}
	var before int64
	limit := 50
	var err error
	if value := r.URL.Query().Get("before"); value != "" {
		before, err = strconv.ParseInt(value, 10, 64)
		if err != nil || before <= 0 {
			writeError(w, 400, "invalid_cursor", "before must be a positive observation ID")
			return
		}
	}
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 100 {
			writeError(w, 400, "invalid_limit", "limit must be between 1 and 100")
			return
		}
	}
	if action.AccountID == "" || action.SessionID == "" {
		writeJSON(w, 200, srunapi.ObservationPage{Items: []srunapi.Observation{}})
		return
	}
	if db == nil {
		writeError(w, 503, "native_observations_unavailable", "database-backed native observations are unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	page, err := (srunapi.Journal{DB: db}).Observations(ctx, action.IdempotencyKey, action.ConnectorID, action.AccountID, action.SessionID, before, limit)
	if err != nil {
		writeError(w, 503, "native_observations_unavailable", "native observations could not be read")
		return
	}
	writeJSON(w, 200, page)
}
