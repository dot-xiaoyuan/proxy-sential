package controlplane

import (
	"bufio"
	"bytes"
	"context"
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
		w.Header().Set("Retry-After", "2")
		writeError(w, status, code, "batch was not acknowledged; retain and retry the same batch")
		return
	}
	writeJSON(w, http.StatusAccepted, receipt)
}
