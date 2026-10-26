package controlplane

import (
	"context"
	"net/http"

	"proxy-sentinel/internal/store"
)

type streamRiskSubjectReader interface {
	GetStreamRiskSubjectState(context.Context, string, string, string) (store.StreamRiskSubjectState, error)
}

func (s *Server) handleStreamRiskSubject(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(streamRiskSubjectReader)
	if !ok {
		writeError(w, http.StatusNotImplemented, "stream_risk_unavailable", "scoped risk results are unavailable")
		return
	}
	kind := r.URL.Query().Get("subject_type")
	if kind == "" {
		kind = "ip"
	}
	id := r.URL.Query().Get("subject_id")
	if (kind != "ip" && kind != "account") || id == "" || len(id) > 256 {
		writeError(w, http.StatusBadRequest, "bad_risk_subject", "subject_type and subject_id must identify one IP or account")
		return
	}
	state, err := reader.GetStreamRiskSubjectState(r.Context(), s.sensorID, kind, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_stream_risk_subject_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}
