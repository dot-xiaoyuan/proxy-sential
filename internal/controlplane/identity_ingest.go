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
	"sort"
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
	RetryCount int    `json:"retry_count"`
	LastRetry  string `json:"last_retried_at,omitempty"`
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
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if err := ctx.Err(); err != nil {
		writeIdentityAuthorityError(w, err)
		return
	}
	if existing, ok, err := s.identityIngest.getBatch(ctx, batchID); err != nil {
		if ctx.Err() != nil {
			writeIdentityAuthorityError(w, ctx.Err())
			return
		}
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
		if err := ctx.Err(); err != nil {
			writeIdentityAuthorityError(w, err)
			return
		}
		if err := encoder.Encode(record); err != nil {
			writeError(w, http.StatusBadRequest, "bad_identity_record", err.Error())
			return
		}
	}
	var normalizedJSON bytes.Buffer
	events := []normalized.Event{}
	stats, err := identityadapter.Convert(&raw, &normalizedJSON, identityadapter.Options{SensorID: request.SensorID, Source: request.Source})
	batch := IdentityIngestBatch{BatchID: batchID, Source: request.Source, SensorID: request.SensorID, Status: "accepted", Read: stats.Read, Emitted: stats.Emitted, Skipped: stats.Skipped, Malformed: stats.Malformed, ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		batch.Status = "failed"
		batch.Error = err.Error()
		if persistErr := s.recordIdentityBatch(batch, events); persistErr != nil {
			writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", persistErr.Error())
			return
		}
		writeJSON(w, http.StatusUnprocessableEntity, batch)
		return
	}
	scanner := bufio.NewScanner(&normalizedJSON)
	authority := newIdentityAuthorityResolver(s)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			writeIdentityAuthorityError(w, err)
			return
		}
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			batch.Status = "failed"
			batch.Error = err.Error()
			if persistErr := s.recordIdentityBatch(batch, events); persistErr != nil {
				writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", persistErr.Error())
				return
			}
			writeJSON(w, http.StatusUnprocessableEntity, batch)
			return
		}
		if err := authority.apply(ctx, &event); err != nil {
			writeIdentityAuthorityError(w, err)
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
	if err := ctx.Err(); err != nil {
		writeIdentityAuthorityError(w, err)
		return
	}
	if err := ingester.IngestIdentityEvents(ctx, events); err != nil {
		batch.Status = "failed"
		batch.Error = fmt.Sprintf("persist identity batch: %v", err)
		if persistErr := s.recordIdentityBatch(batch, events); persistErr != nil {
			writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", persistErr.Error())
			return
		}
		writeJSON(w, http.StatusInternalServerError, batch)
		return
	}
	batch.Status = "completed"
	if err := s.recordIdentityBatch(batch, events); err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, batch)
}

func (s *Server) recordIdentityBatch(batch IdentityIngestBatch, events []normalized.Event) error {
	if s.identityIngest.db != nil {
		ctx, cancel := contextWithRequestTimeout(context.Background())
		defer cancel()
		eventsJSON, _ := json.Marshal(events)
		_, err := s.identityIngest.db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,records_skipped,records_malformed,error_message,received_at,completed_at,normalized_events) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10::timestamptz,CASE WHEN $4 IN ('completed','failed') THEN now() ELSE NULL END,$11) ON CONFLICT(batch_id) DO UPDATE SET status=EXCLUDED.status,records_read=EXCLUDED.records_read,records_emitted=EXCLUDED.records_emitted,records_skipped=EXCLUDED.records_skipped,records_malformed=EXCLUDED.records_malformed,error_message=EXCLUDED.error_message,completed_at=EXCLUDED.completed_at,normalized_events=CASE WHEN jsonb_array_length(EXCLUDED.normalized_events)>0 THEN EXCLUDED.normalized_events ELSE identity_ingest_batches.normalized_events END`, batch.BatchID, batch.Source, batch.SensorID, batch.Status, batch.Read, batch.Emitted, batch.Skipped, batch.Malformed, batch.Error, batch.ReceivedAt, eventsJSON)

		if err != nil {
			return err
		}
		if batch.Status == "completed" && hasRecentAccountingLifecycle(events, time.Now().UTC()) {
			_, err = s.identityIngest.db.ExecContext(ctx, `UPDATE srun4k_integrations SET event_channel_state='healthy',last_identity_event_at=$3::timestamptz WHERE source=$1 AND sensor_id=$2 AND (last_identity_event_at IS NULL OR last_identity_event_at<=$3::timestamptz)`, batch.Source, batch.SensorID, batch.ReceivedAt)
		}
		return err
	}
	s.identityIngest.mu.Lock()
	s.identityIngest.batches[batch.BatchID] = batch
	s.identityIngest.lastSeen = batch.ReceivedAt
	s.identityIngest.mu.Unlock()
	return nil
}

func (s *Server) handleIdentityIngestStatus(w http.ResponseWriter, r *http.Request) {
	sources := []store.IdentitySourceStatus{}
	backend, supported := s.reader.(store.IdentityReconciler)
	if supported {
		var err error
		sources, err = backend.IdentitySources(r.Context(), time.Now().UTC())
		if err != nil {
			writeError(w, 503, "identity_sources_unavailable", err.Error())
			return
		}
	}
	var mergeError error
	sources, mergeError = s.mergeManagedIdentitySources(r.Context(), sources, time.Now().UTC())
	if mergeError != nil {
		writeError(w, 503, "identity_sources_unavailable", "身份来源状态不可用")
		return
	}
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
		materializer := map[string]any{}
		if reader, ok := s.reader.(interface {
			IdentityMaterializerStatus(context.Context) (map[string]any, error)
		}); ok {
			var err error
			materializer, err = reader.IdentityMaterializerStatus(r.Context())
			if err != nil {
				writeError(w, 503, "identity_materializer_status_failed", err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"materializer": materializer, "enabled": s.identityIngest.key != "", "last_received_at": last, "completed_batches": completed, "failed_batches": failed, "reconciliation_supported": supported, "sources": sources})
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
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.identityIngest.key != "", "last_received_at": s.identityIngest.lastSeen, "completed_batches": completed, "failed_batches": failed, "reconciliation_supported": supported, "sources": sources})
}

func (s *Server) handleIdentityBatches(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest.db == nil {
		s.identityIngest.mu.Lock()
		items := make([]IdentityIngestBatch, 0, len(s.identityIngest.batches))
		for _, item := range s.identityIngest.batches {
			items = append(items, item)
		}
		s.identityIngest.mu.Unlock()
		sort.Slice(items, func(i, j int) bool { return items[i].ReceivedAt > items[j].ReceivedAt })
		limit, _ := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
		cursor, _ := cursorOffset(r.URL.Query().Get("cursor"))
		pageItems, page := paginate(items, cursor, limit)
		writeJSON(w, http.StatusOK, map[string]any{"items": pageItems, "page": page})
		return
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", err.Error())
		return
	}
	var total int
	if err := s.identityIngest.db.QueryRowContext(r.Context(), `SELECT count(*) FROM identity_ingest_batches`).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batches_failed", err.Error())
		return
	}
	rows, err := s.identityIngest.db.QueryContext(r.Context(), `SELECT batch_id,source,sensor_id,status,records_read,records_emitted,records_skipped,records_malformed,COALESCE(error_message,''),received_at,retry_count,last_retried_at FROM identity_ingest_batches ORDER BY received_at DESC LIMIT $1 OFFSET $2`, limit, cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batches_failed", err.Error())
		return
	}
	defer rows.Close()
	items := []IdentityIngestBatch{}
	for rows.Next() {
		var item IdentityIngestBatch
		var receivedAt time.Time
		var lastRetry sql.NullTime
		if err := rows.Scan(&item.BatchID, &item.Source, &item.SensorID, &item.Status, &item.Read, &item.Emitted, &item.Skipped, &item.Malformed, &item.Error, &receivedAt, &item.RetryCount, &lastRetry); err != nil {
			writeError(w, http.StatusInternalServerError, "identity_batches_failed", err.Error())
			return
		}
		item.ReceivedAt = receivedAt.UTC().Format(time.RFC3339Nano)
		if lastRetry.Valid {
			item.LastRetry = lastRetry.Time.UTC().Format(time.RFC3339Nano)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batches_failed", err.Error())
		return
	}
	var next *string
	if cursor+len(items) < total {
		value := fmt.Sprintf("%d", cursor+len(items))
		next = &value
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": Page{Limit: limit, NextCursor: next, Total: total}})
}

func (s *Server) handleIdentityBatchReplay(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest.db == nil {
		writeError(w, http.StatusConflict, "identity_replay_unavailable", "identity batch replay requires PostgreSQL storage")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if err := ctx.Err(); err != nil {
		writeIdentityAuthorityError(w, err)
		return
	}
	batchID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/integrations/identity/batches/"), "/replay")
	if strings.TrimSpace(batchID) == "" || strings.Contains(batchID, "/") {
		writeError(w, http.StatusBadRequest, "bad_identity_batch_id", "identity batch id is invalid")
		return
	}
	var batch IdentityIngestBatch
	var eventsJSON []byte
	var receivedAt time.Time
	err := s.identityIngest.db.QueryRowContext(ctx, `SELECT batch_id,source,sensor_id,status,records_read,records_emitted,records_skipped,records_malformed,COALESCE(error_message,''),received_at,normalized_events FROM identity_ingest_batches WHERE batch_id=$1`, batchID).Scan(&batch.BatchID, &batch.Source, &batch.SensorID, &batch.Status, &batch.Read, &batch.Emitted, &batch.Skipped, &batch.Malformed, &batch.Error, &receivedAt, &eventsJSON)
	if ctx.Err() != nil {
		writeIdentityAuthorityError(w, ctx.Err())
		return
	}
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "identity_batch_not_found", "identity batch not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batch_read_failed", err.Error())
		return
	}
	events := []normalized.Event{}
	if err := json.Unmarshal(eventsJSON, &events); err != nil || len(events) == 0 {
		writeError(w, http.StatusConflict, "identity_batch_not_replayable", "identity batch has no retained normalized events")
		return
	}
	authority := newIdentityAuthorityResolver(s)
	for i := range events {
		if err := authority.apply(ctx, &events[i]); err != nil {
			writeIdentityAuthorityError(w, err)
			return
		}
	}
	ingester, ok := s.reader.(store.IdentityEventIngester)
	if !ok {
		writeError(w, http.StatusConflict, "identity_ingest_unavailable", "identity ingestion requires database storage")
		return
	}
	if err := ctx.Err(); err != nil {
		writeIdentityAuthorityError(w, err)
		return
	}
	if err := ingester.IngestIdentityEvents(ctx, events); err != nil {
		_, _ = s.identityIngest.db.ExecContext(r.Context(), `UPDATE identity_ingest_batches SET status='failed',error_message=$2,retry_count=retry_count+1,last_retried_at=now() WHERE batch_id=$1`, batchID, err.Error())
		writeError(w, http.StatusInternalServerError, "identity_batch_replay_failed", err.Error())
		return
	}
	_, err = s.identityIngest.db.ExecContext(r.Context(), `UPDATE identity_ingest_batches SET status='completed',error_message=NULL,completed_at=now(),retry_count=retry_count+1,last_retried_at=now() WHERE batch_id=$1`, batchID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "identity_batch_status_failed", err.Error())
		return
	}
	batch.Status = "completed"
	batch.Error = ""
	batch.ReceivedAt = receivedAt.UTC().Format(time.RFC3339Nano)
	s.appendAudit(r.Context(), "identity.batch_replayed", batchID, "succeeded")
	writeJSON(w, http.StatusOK, batch)
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

func hasRecentAccountingLifecycle(events []normalized.Event, now time.Time) bool {
	for _, event := range events {
		action, _ := event.Payload["action"].(string)
		observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		account, _ := event.Subject["account_id"].(string)
		session, _ := event.Payload["session_id"].(string)
		if err == nil && !observed.After(now.Add(time.Second)) && !observed.Before(now.Add(-2*time.Minute)) && account != "" && session != "" && event.Type == "identity" && (action == "start" || action == "interim" || action == "stop") {
			return true
		}
	}
	return false
}
