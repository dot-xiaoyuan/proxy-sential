package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"proxy-sentinel/internal/store"
)

func (s *Server) handleAccountAssessments(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(store.AccountAssessmentReader)
	if !ok {
		writeError(w, http.StatusNotImplemented, "account_assessments_unavailable", "account assessment projection is unavailable")
		return
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_page", err.Error())
		return
	}
	cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_page", err.Error())
		return
	}
	tags := []string{}
	for _, value := range r.URL.Query()["tag"] {
		for _, tag := range strings.Split(value, ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	for _, tag := range tags {
		if !validAccountTag(tag) {
			writeError(w, http.StatusBadRequest, "bad_account_assessment_query", "invalid tag")
			return
		}
	}
	query := store.AccountAssessmentQuery{Keyword: strings.TrimSpace(r.URL.Query().Get("q")), Tags: tags, EvidenceLevel: r.URL.Query().Get("evidence_level"), ReviewState: r.URL.Query().Get("review_state"), State: r.URL.Query().Get("state"), Limit: limit, Cursor: cursor}
	if query.EvidenceLevel != "" && query.EvidenceLevel != "confirmed" && query.EvidenceLevel != "likely" && query.EvidenceLevel != "clue" {
		writeError(w, http.StatusBadRequest, "bad_account_assessment_query", "invalid evidence level")
		return
	}
	if query.ReviewState != "" && query.ReviewState != "pending" && query.ReviewState != "confirm" && query.ReviewState != "reject" {
		writeError(w, http.StatusBadRequest, "bad_account_assessment_query", "invalid review state")
		return
	}
	if query.State != "" && query.State != "current" && query.State != "historical" {
		writeError(w, http.StatusBadRequest, "bad_account_assessment_query", "invalid state")
		return
	}
	result, err := reader.ListAccountAssessments(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_account_assessments_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAccountAssessment(w http.ResponseWriter, r *http.Request, raw string) {
	account, err := store.DecodePathIP(raw)
	if err != nil || strings.TrimSpace(account) == "" {
		writeError(w, http.StatusBadRequest, "bad_account_id", "account id is required")
		return
	}
	reader, ok := s.reader.(store.AccountAssessmentReader)
	if !ok {
		writeError(w, http.StatusNotImplemented, "account_assessments_unavailable", "account assessment projection is unavailable")
		return
	}
	result, found, err := reader.GetAccountAssessment(r.Context(), account)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_account_assessment_failed", err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "account_assessment_not_found", "account assessment not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAccountTagReview(w http.ResponseWriter, r *http.Request, rest string) {
	if s.readOnly {
		writeError(w, http.StatusForbidden, "read_only", "account tag reviews are disabled in read-only mode")
		return
	}
	raw := strings.TrimSuffix(rest, "/tag-reviews")
	account, err := store.DecodePathIP(raw)
	if err != nil || strings.TrimSpace(account) == "" {
		writeError(w, http.StatusBadRequest, "bad_account_id", "account id is required")
		return
	}
	var request store.AccountTagReviewRequest
	if err = json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_account_tag_review", err.Error())
		return
	}
	if !validAccountTag(request.TagType) || (request.Decision != "confirm" && request.Decision != "reject") || request.AssessmentVersion == "" || len(strings.TrimSpace(request.Reason)) < 2 {
		writeError(w, http.StatusBadRequest, "bad_account_tag_review", "tag_type, assessment_version, confirm/reject decision and reason are required")
		return
	}
	writer, ok := s.reader.(store.AccountAssessmentWriter)
	if !ok {
		writeError(w, http.StatusNotImplemented, "account_assessments_unavailable", "account assessment reviews are unavailable")
		return
	}
	request.CreatedBy = sessionFromContext(r.Context()).User.ID
	review, err := writer.CreateAccountTagReview(r.Context(), account, request)
	if errors.Is(err, store.ErrAccountAssessmentVersionChanged) {
		writeError(w, http.StatusConflict, "account_assessment_version_changed", "assessment changed; refresh before reviewing")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create_account_tag_review_failed", err.Error())
		return
	}
	s.appendAudit(r.Context(), "account_tag.review", account+":"+request.TagType, "succeeded")
	writeJSON(w, http.StatusCreated, review)
}

func validAccountTag(value string) bool {
	return value == "proxy" || value == "router" || value == "mobile" || value == "pc"
}
