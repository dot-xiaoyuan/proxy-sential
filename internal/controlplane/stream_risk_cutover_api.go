package controlplane

import (
	"context"
	"net/http"

	"proxy-sentinel/internal/store"
)

type streamRiskCutoverStatusReader interface {
	GetStreamRiskCutoverStatus(context.Context, string) (store.StreamRiskCutoverStatus, bool, error)
}

func (s *Server) handleStreamRiskCutover(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(streamRiskCutoverStatusReader)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	status, active, err := reader.GetStreamRiskCutoverStatus(r.Context(), s.sensorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "risk_cutover_status_failed", err.Error())
		return
	}
	if !active {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Active bool                          `json:"active"`
		Status store.StreamRiskCutoverStatus `json:"status"`
	}{Active: true, Status: status})
}
