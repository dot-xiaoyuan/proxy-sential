package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxy-sentinel/internal/evaluation"
	"proxy-sentinel/internal/store"
)

type shadowReviewSamplesResponse struct {
	Date    string              `json:"date"`
	Level   string              `json:"level,omitempty"`
	Samples []evaluation.Sample `json:"samples"`
	Page    Page                `json:"page"`
}

func (s *Server) handleShadowReviewSamples(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	date := query.Get("date")
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil || parsed.Format("2006-01-02") != date {
		writeError(w, http.StatusBadRequest, "bad_date", "date must be YYYY-MM-DD")
		return
	}
	level := strings.ToLower(strings.TrimSpace(query.Get("level")))
	switch level {
	case "", "normal", "suspicious", "high", "confirmed":
	default:
		writeError(w, http.StatusBadRequest, "bad_level", "unsupported review level")
		return
	}
	limit, err := boundedInt(query.Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	offset, err := cursorOffset(query.Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", err.Error())
		return
	}
	path := filepath.Join(s.shadowDir, "review-exports", date+"-review-samples.json")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "review_samples_not_found", "daily review samples have not been generated")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_review_samples_failed", "daily review samples could not be read")
		return
	}
	defer file.Close()
	var export struct {
		Date    string              `json:"date"`
		Samples []evaluation.Sample `json:"samples"`
	}
	if err := json.NewDecoder(file).Decode(&export); err != nil || export.Date != date {
		writeError(w, http.StatusInternalServerError, "decode_review_samples_failed", "invalid daily review sample export")
		return
	}
	if labelReader, ok := s.reader.(store.LabelReader); ok {
		ctx, cancel := contextWithRequestTimeout(r.Context())
		defer cancel()
		labels, err := labelReader.ListLabels(ctx, 0)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "read_labels_failed", "review labels could not be read")
			return
		}
		export.Samples = evaluation.ReviewSamplesWithLabels(export.Samples, labels)
	}
	filtered := make([]evaluation.Sample, 0, len(export.Samples))
	for _, sample := range export.Samples {
		if level == "" || sample.Level == level {
			filtered = append(filtered, sample)
		}
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	var next *string
	if end < len(filtered) {
		value := fmt.Sprintf("%d", end)
		next = &value
	}
	writeJSON(w, http.StatusOK, shadowReviewSamplesResponse{
		Date: date, Level: level, Samples: filtered[offset:end],
		Page: Page{Limit: limit, NextCursor: next, Total: len(filtered)},
	})
}
