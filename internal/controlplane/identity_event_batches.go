package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/identityprotocol"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

func (s *Server) handleDurableIdentityBatch(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, 401, "integration_auth_failed", "valid integration bearer token is required")
		return
	}
	if os.Getenv("PROXY_SENTINEL_IDENTITY_DURABLE_ACCEPT") == "false" {
		writeError(w, 503, "identity_inbox_paused", "durable acceptance paused; retain source messages")
		return
	}
	id := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if id == "" || len(id) > 256 {
		writeError(w, 400, "idempotency_key_required", "bounded Idempotency-Key required")
		return
	}
	backend, ok := s.reader.(store.DurableIdentityIngester)
	if !ok {
		writeError(w, 503, "identity_inbox_unavailable", "durable database inbox is required")
		return
	}
	var request identityprotocol.Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, 400, "bad_identity_batch", "invalid identity batch")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "bad_identity_batch", "one JSON document required")
		return
	}
	if request.Source == "" || request.SensorID == "" || len(request.Records) == 0 || len(request.Records) > 10000 {
		writeError(w, 400, "bad_identity_batch", "source, sensor and 1–10000 records required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Once accepted, changes to source registration cannot invalidate its receipt.
	if receipts, ok := s.reader.(store.DurableIdentityReceiptReader); ok {
		receipt, found, readErr := receipts.LookupIdentityReceipt(ctx, id, request.Hash(), len(request.Records))
		if readErr != nil {
			status, code := 503, "identity_inbox_unavailable"
			if errors.Is(readErr, store.ErrIdentityBatchConflict) {
				status, code = 409, "identity_batch_conflict"
			}
			writeError(w, status, code, "retain the same batch until its receipt can be verified")
			return
		}
		if found {
			writeJSON(w, http.StatusAccepted, receipt)
			return
		}
	}
	var raw, converted bytes.Buffer
	encoder := json.NewEncoder(&raw)
	for _, record := range request.Records {
		_ = encoder.Encode(record)
	}
	stats, err := identityadapter.Convert(&raw, &converted, identityadapter.Options{Source: request.Source, SensorID: request.SensorID})
	if err != nil || stats.Emitted != len(request.Records) || stats.Skipped != 0 || stats.Malformed != 0 {
		writeError(w, 422, "bad_identity_batch", "every record must normalize successfully")
		return
	}
	events := make([]normalized.Event, 0, len(request.Records))
	scanner := bufio.NewScanner(&converted)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	authority := newIdentityAuthorityResolver(s)
	var scope store.IdentityScope
	for scanner.Scan() {
		var event normalized.Event
		if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
			writeError(w, 422, "bad_identity_batch", "invalid normalized event")
			return
		}
		if err = authority.apply(ctx, &event); err != nil {
			writeIdentityAuthorityError(w, err)
			return
		}
		campus, _ := event.Subject["campus_id"].(string)
		domain, _ := event.Payload["access_domain"].(string)
		candidate := store.IdentityScope{Source: request.Source, SensorID: request.SensorID, CampusID: campus, AccessDomain: domain}
		if campus == "" || domain == "" || (len(events) > 0 && candidate != scope) {
			writeError(w, 422, "mixed_identity_scope", "one complete authority scope required")
			return
		}
		scope = candidate
		events = append(events, event)
	}
	if scanner.Err() != nil {
		writeError(w, 422, "bad_identity_batch", "normalized batch exceeds limits")
		return
	}
	receipt, err := backend.AcceptIdentityBatch(ctx, id, request.Hash(), scope, events, len(request.Records))
	if err != nil {
		status, code := http.StatusServiceUnavailable, "identity_inbox_unavailable"
		if errors.Is(err, store.ErrIdentityBatchConflict) {
			status, code = http.StatusConflict, "identity_batch_conflict"
		}
		if errors.Is(err, store.ErrInvalidIdentityBatch) {
			status, code = http.StatusUnprocessableEntity, "bad_identity_batch"
		}
		if errors.Is(err, store.ErrIdentityInboxFull) {
			status, code = http.StatusTooManyRequests, "identity_inbox_full"
		}
		if errors.Is(err, store.ErrIdentityCutoverNotActive) {
			status, code = http.StatusServiceUnavailable, "identity_cutover_not_active"
		}
		w.Header().Set("Retry-After", "2")
		writeError(w, status, code, "batch was not acknowledged; retain and retry the same batch")
		return
	}
	writeJSON(w, http.StatusAccepted, receipt)
}

// GET is a bounded, per-batch receipt. Durable HTTP 202 acknowledges only
// acceptance; these two phases must never be inferred from that response.
func (s *Server) handleDurableIdentityBatchStatus(w http.ResponseWriter, r *http.Request, id string) {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, http.StatusUnauthorized, "integration_auth_failed", "valid integration bearer token is required")
		return
	}
	if id == "" || len(id) > 256 || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "bad_identity_batch_id", "identity batch id is invalid")
		return
	}
	if s.identityIngest.db == nil {
		writeError(w, http.StatusServiceUnavailable, "identity_inbox_unavailable", "durable batch status requires PostgreSQL")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var batchID, status, exportState, contentHash, errorMessage, exportError, payloadFormat string
	var accepted time.Time
	var count, projected, derivedPending, derivedFailed int
	err := s.identityIngest.db.QueryRowContext(ctx, `SELECT b.batch_id,b.status,b.export_state,COALESCE(b.content_sha256,''),COALESCE(b.accepted_at,b.received_at),b.records_emitted,b.processed_offset,COALESCE(b.error_message,''),COALESCE(b.export_error,''),b.payload_format,COALESCE((SELECT sum(f.record_count) FROM identity_ingest_fragments f WHERE f.batch_id=b.batch_id AND f.derived_state<>'completed'),0),COALESCE((SELECT count(*) FROM identity_ingest_fragments f WHERE f.batch_id=b.batch_id AND f.derived_state='failed'),0) FROM identity_ingest_batches b WHERE b.batch_id=$1 AND b.protocol_version=2`, id).Scan(&batchID, &status, &exportState, &contentHash, &accepted, &count, &projected, &errorMessage, &exportError, &payloadFormat, &derivedPending, &derivedFailed)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "identity_batch_not_found", "identity batch not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_batch_status_unavailable", "batch status is temporarily unavailable")
		return
	}
	archive, projection := identityBatchPhases(status, exportState, projected, count)
	if payloadFormat == "fragments" && derivedPending > 0 {
		projection = "pending"
		if derivedFailed > 0 {
			projection = "failed"
		}
	}
	if errorMessage == "" {
		errorMessage = exportError
	}
	if errorMessage == "" && derivedFailed > 0 {
		errorMessage = "identity_derived_failed"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"batch_id": batchID, "content_sha256": contentHash,
		"durably_accepted": true, "accepted_at": accepted.UTC().Format(time.RFC3339Nano),
		"record_count": count, "projected_count": projected,
		"archive_status": archive, "projection_status": projection,
		"failed": archive == "failed" || projection == "failed",
		"error":  errorMessage,
	})
}

func identityBatchPhases(status, exportState string, projected, count int) (archive, projection string) {
	archive, projection = "pending", "pending"
	if exportState == "completed" {
		archive = "completed"
	} else if exportState == "failed" {
		archive = "failed"
	}
	if status == "completed" && projected >= count {
		projection = "completed"
	} else if status == "failed" {
		projection = "failed"
	}
	return
}
