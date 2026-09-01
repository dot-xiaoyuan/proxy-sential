package controlplane

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type identityIngestState struct {
	mu       sync.Mutex
	key      string
	batches  map[string]IdentityIngestBatch
	lastSeen string
}

type IdentityIngestBatch struct {
	BatchID    string `json:"batch_id"`
	Source     string `json:"source"`
	Status     string `json:"status"`
	Read       int    `json:"read"`
	Emitted    int    `json:"emitted"`
	Skipped    int    `json:"skipped"`
	Malformed  int    `json:"malformed"`
	ReceivedAt string `json:"received_at"`
	Error      string `json:"error,omitempty"`
}

type identityIngestRequest struct {
	Source   string              `json:"source"`
	SensorID string              `json:"sensor_id"`
	Records  []map[string]string `json:"records"`
}

func newIdentityIngestState(key string) *identityIngestState {
	return &identityIngestState{key: strings.TrimSpace(key), batches: map[string]IdentityIngestBatch{}}
}

func (s *identityIngestState) authorized(r *http.Request) bool {
	if s == nil || s.key == "" {
		return false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return presented != "" && hmac.Equal([]byte(presented), []byte(s.key))
}

func (s *Server) handleIdentityIngest(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, http.StatusUnauthorized, "integration_auth_failed", "valid integration bearer token is required")
		return
	}
	batchID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if batchID == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.identityIngest.mu.Lock()
	if existing, ok := s.identityIngest.batches[batchID]; ok {
		s.identityIngest.mu.Unlock()
		writeJSON(w, http.StatusOK, existing)
		return
	}
	s.identityIngest.mu.Unlock()

	var request identityIngestRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_identity_batch", err.Error())
		return
	}
	if len(request.Records) == 0 || len(request.Records) > 10000 {
		writeError(w, http.StatusBadRequest, "bad_identity_batch", "records must contain between 1 and 10000 items")
		return
	}
	request.Source = firstNonEmptyString(strings.TrimSpace(request.Source), "radius")
	request.SensorID = firstNonEmptyString(strings.TrimSpace(request.SensorID), s.sensorID)
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	for _, record := range request.Records {
		if err := encoder.Encode(record); err != nil {
			writeError(w, http.StatusBadRequest, "bad_identity_record", err.Error())
			return
		}
	}
	var normalizedJSON bytes.Buffer
	stats, err := identityadapter.Convert(&raw, &normalizedJSON, identityadapter.Options{SensorID: request.SensorID, Source: request.Source})
	batch := IdentityIngestBatch{BatchID: batchID, Source: request.Source, Status: "accepted", Read: stats.Read, Emitted: stats.Emitted, Skipped: stats.Skipped, Malformed: stats.Malformed, ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		batch.Status = "failed"
		batch.Error = err.Error()
		s.recordIdentityBatch(batch)
		writeJSON(w, http.StatusUnprocessableEntity, batch)
		return
	}
	events := []normalized.Event{}
	scanner := bufio.NewScanner(&normalizedJSON)
	for scanner.Scan() {
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			batch.Status = "failed"
			batch.Error = err.Error()
			s.recordIdentityBatch(batch)
			writeJSON(w, http.StatusUnprocessableEntity, batch)
			return
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batch_scan_failed", err.Error())
		return
	}
	ingester, ok := s.reader.(store.IdentityEventIngester)
	if !ok {
		writeError(w, http.StatusConflict, "identity_ingest_unavailable", "identity ingestion requires db or dual storage mode")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if err := ingester.IngestIdentityEvents(ctx, events); err != nil {
		batch.Status = "failed"
		batch.Error = fmt.Sprintf("persist identity batch: %v", err)
		s.recordIdentityBatch(batch)
		writeJSON(w, http.StatusInternalServerError, batch)
		return
	}
	batch.Status = "completed"
	s.recordIdentityBatch(batch)
	writeJSON(w, http.StatusAccepted, batch)
}

func (s *Server) recordIdentityBatch(batch IdentityIngestBatch) {
	s.identityIngest.mu.Lock()
	s.identityIngest.batches[batch.BatchID] = batch
	s.identityIngest.lastSeen = batch.ReceivedAt
	s.identityIngest.mu.Unlock()
}

func (s *Server) handleIdentityIngestStatus(w http.ResponseWriter, _ *http.Request) {
	s.identityIngest.mu.Lock()
	defer s.identityIngest.mu.Unlock()
	completed, failed := 0, 0
	for _, batch := range s.identityIngest.batches {
		if batch.Status == "completed" {
			completed++
		} else if batch.Status == "failed" {
			failed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.identityIngest.key != "", "last_received_at": s.identityIngest.lastSeen, "completed_batches": completed, "failed_batches": failed})
}
