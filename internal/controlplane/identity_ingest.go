package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"database/sql"
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
	db       *sql.DB
}

type IdentityIngestBatch struct {
	BatchID    string `json:"batch_id"`
	Source     string `json:"source"`
	SensorID   string `json:"sensor_id"`
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

func newIdentityIngestState(key, postgresDSN string) (*identityIngestState, error) {
	state := &identityIngestState{key: strings.TrimSpace(key), batches: map[string]IdentityIngestBatch{}}
	if strings.TrimSpace(postgresDSN) == "" {
		return state, nil
	}
	db, err := sql.Open("pgx", postgresDSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	ctx, cancel := contextWithRequestTimeout(context.Background())
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect PostgreSQL identity batch repository: %w", err)
	}
	state.db = db
	return state, nil
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
	if existing, ok, err := s.identityIngest.getBatch(r.Context(), batchID); err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batch_lookup_failed", err.Error())
		return
	} else if ok {
		writeJSON(w, http.StatusOK, existing)
		return
	}

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
	batch := IdentityIngestBatch{BatchID: batchID, Source: request.Source, SensorID: request.SensorID, Status: "accepted", Read: stats.Read, Emitted: stats.Emitted, Skipped: stats.Skipped, Malformed: stats.Malformed, ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		batch.Status = "failed"
		batch.Error = err.Error()
		if persistErr := s.recordIdentityBatch(batch); persistErr != nil {
			writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", persistErr.Error())
			return
		}
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
			if persistErr := s.recordIdentityBatch(batch); persistErr != nil {
				writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", persistErr.Error())
				return
			}
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
		if persistErr := s.recordIdentityBatch(batch); persistErr != nil {
			writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", persistErr.Error())
			return
		}
		writeJSON(w, http.StatusInternalServerError, batch)
		return
	}
	batch.Status = "completed"
	if err := s.recordIdentityBatch(batch); err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, batch)
}

func (s *Server) recordIdentityBatch(batch IdentityIngestBatch) error {
	if s.identityIngest.db != nil {
		ctx, cancel := contextWithRequestTimeout(context.Background())
		defer cancel()
		_, err := s.identityIngest.db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,records_skipped,records_malformed,error_message,received_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10::timestamptz,CASE WHEN $4 IN ('completed','failed') THEN now() ELSE NULL END) ON CONFLICT(batch_id) DO UPDATE SET status=EXCLUDED.status,records_read=EXCLUDED.records_read,records_emitted=EXCLUDED.records_emitted,records_skipped=EXCLUDED.records_skipped,records_malformed=EXCLUDED.records_malformed,error_message=EXCLUDED.error_message,completed_at=EXCLUDED.completed_at`, batch.BatchID, batch.Source, batch.SensorID, batch.Status, batch.Read, batch.Emitted, batch.Skipped, batch.Malformed, batch.Error, batch.ReceivedAt)
		return err
	}
	s.identityIngest.mu.Lock()
	s.identityIngest.batches[batch.BatchID] = batch
	s.identityIngest.lastSeen = batch.ReceivedAt
	s.identityIngest.mu.Unlock()
	return nil
}

func (s *Server) handleIdentityIngestStatus(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest.db != nil {
		var completed, failed int
		var lastSeen sql.NullTime
		err := s.identityIngest.db.QueryRowContext(r.Context(), `SELECT count(*) FILTER (WHERE status='completed'), count(*) FILTER (WHERE status='failed'), max(received_at) FROM identity_ingest_batches`).Scan(&completed, &failed, &lastSeen)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "identity_status_failed", err.Error())
			return
		}
		last := ""
		if lastSeen.Valid {
			last = lastSeen.Time.UTC().Format(time.RFC3339Nano)
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": s.identityIngest.key != "", "last_received_at": last, "completed_batches": completed, "failed_batches": failed})
		return
	}
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

func (s *identityIngestState) getBatch(ctx context.Context, batchID string) (IdentityIngestBatch, bool, error) {
	if s.db == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		item, ok := s.batches[batchID]
		return item, ok, nil
	}
	var item IdentityIngestBatch
	var receivedAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT batch_id,source,sensor_id,status,records_read,records_emitted,records_skipped,records_malformed,COALESCE(error_message,''),received_at FROM identity_ingest_batches WHERE batch_id=$1`, batchID).Scan(&item.BatchID, &item.Source, &item.SensorID, &item.Status, &item.Read, &item.Emitted, &item.Skipped, &item.Malformed, &item.Error, &receivedAt)
	if err == sql.ErrNoRows {
		return IdentityIngestBatch{}, false, nil
	}
	if err != nil {
		return IdentityIngestBatch{}, false, err
	}
	item.ReceivedAt = receivedAt.UTC().Format(time.RFC3339Nano)
	return item, true, nil
}
