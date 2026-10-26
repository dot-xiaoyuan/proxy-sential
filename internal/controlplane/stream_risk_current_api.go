package controlplane

import (
	"context"
	"errors"
	"net/http"

	"proxy-sentinel/internal/store"
)

type streamRiskCurrentReader interface {
	ListStreamRiskCurrent(context.Context, string, string, string, string, int) (store.StreamRiskCurrentPage, error)
}

func (s *Server) handleStreamRiskCurrent(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(streamRiskCurrentReader)
	if !ok {
		writeError(w, http.StatusNotImplemented, "stream_risk_unavailable", "scoped risk results are unavailable")
		return
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	kind := r.URL.Query().Get("subject_type")
	if kind == "" {
		kind = "ip"
	}
	if kind != "ip" && kind != "account" {
		writeError(w, http.StatusBadRequest, "bad_subject_type", "subject_type must be ip or account")
		return
	}
	level := r.URL.Query().Get("level")
	if level != "" && level != "normal" && level != "suspicious" && level != "high" && level != "confirmed" {
		writeError(w, http.StatusBadRequest, "bad_risk_level", "invalid risk level")
		return
	}
	page, err := reader.ListStreamRiskCurrent(r.Context(), s.sensorID, kind, level, r.URL.Query().Get("cursor"), limit)
	if errors.Is(err, store.ErrStreamRiskCursor) {
		writeError(w, http.StatusBadRequest, "bad_risk_cursor", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_stream_risks_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}
