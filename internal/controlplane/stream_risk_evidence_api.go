package controlplane

import (
	"context"
	"net/http"

	"proxy-sentinel/internal/evidence"
)

type streamRiskEvidenceReader interface {
	GetStreamRiskEvidence(context.Context, string, string, string, string) (evidence.Evidence, bool, error)
}

func (s *Server) handleStreamRiskEvidence(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(streamRiskEvidenceReader)
	if !ok {
		writeError(w, http.StatusNotImplemented, "stream_risk_unavailable", "scoped risk evidence is unavailable")
		return
	}
	query := r.URL.Query()
	kind := query.Get("subject_type")
	if kind == "" {
		kind = "ip"
	}
	subjectID, factID := query.Get("subject_id"), query.Get("evidence_id")
	if (kind != "ip" && kind != "account") || subjectID == "" || len(subjectID) > 256 || factID == "" || len(factID) > 256 {
		writeError(w, http.StatusBadRequest, "bad_risk_evidence", "subject_type, subject_id and evidence_id must identify one current fact")
		return
	}
	item, found, err := reader.GetStreamRiskEvidence(r.Context(), s.sensorID, kind, subjectID, factID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_stream_risk_evidence_failed", err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "stream_risk_evidence_not_current", "risk evidence is not current")
		return
	}
	writeJSON(w, http.StatusOK, item)
}
