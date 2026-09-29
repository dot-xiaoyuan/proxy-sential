package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"proxy-sentinel/internal/store"
	"strconv"
	"strings"
)

func (s *Server) handleDeviceNameNote(w http.ResponseWriter, r *http.Request, rest string) {
	if s.readOnly {
		writeError(w, http.StatusForbidden, "read_only", "device name editing is disabled")
		return
	}
	id, err := store.DecodePathIP(strings.TrimSuffix(rest, "/name-note"))
	if err != nil || id == "" {
		writeError(w, 400, "bad_endpoint_id", "endpoint id required")
		return
	}
	writer, ok := s.reader.(interface {
		UpdateDeviceNameNote(context.Context, string, string, string) error
	})
	if !ok {
		writeError(w, 501, "unsupported", "device name editing requires PostgreSQL")
		return
	}
	var request struct {
		Value string `json:"value"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&request); err != nil {
		writeError(w, 400, "bad_name_note", "invalid name note")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if err = writer.UpdateDeviceNameNote(ctx, id, strings.TrimSpace(request.Value), sessionFromContext(r.Context()).User.ID); err != nil {
		writeError(w, 400, "update_name_failed", err.Error())
		return
	}
	s.appendAudit(ctx, "device_name_note", id, "updated")
	writeJSON(w, 200, map[string]bool{"updated": true})
}

func (s *Server) handleDeviceNameEvidence(w http.ResponseWriter, r *http.Request, rest string) {
	id, err := store.DecodePathIP(strings.TrimSuffix(rest, "/name-evidence"))
	if err != nil || id == "" {
		writeError(w, 400, "bad_endpoint_id", "endpoint id required")
		return
	}
	reader, ok := s.reader.(interface {
		ListDeviceNameEvidence(context.Context, string, int, int) (store.DeviceNameEvidencePage, error)
	})
	if !ok {
		writeJSON(w, 200, store.DeviceNameEvidencePage{Items: []store.DeviceNameEvidence{}})
		return
	}
	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, 400, "bad_limit", "invalid limit")
			return
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, 400, "bad_offset", "invalid offset")
			return
		}
	}
	if limit < 1 || limit > 200 || offset < 0 {
		writeError(w, 400, "bad_page", "invalid pagination")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := reader.ListDeviceNameEvidence(ctx, id, limit, offset)
	if err != nil {
		writeError(w, 500, "name_evidence_failed", err.Error())
		return
	}
	writeJSON(w, 200, page)
}
