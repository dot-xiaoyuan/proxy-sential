package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type identitySnapshotRequest struct {
	store.IdentityScope
	ObservedAt      time.Time           `json:"observed_at"`
	IntervalSeconds int                 `json:"reconcile_interval_seconds"`
	Complete        bool                `json:"complete"`
	ExpectedCount   *int                `json:"expected_count"`
	Records         []map[string]string `json:"records"`
}

func prepareIdentitySnapshot(request identitySnapshotRequest, id string, now time.Time) (store.IdentitySnapshot, error) {
	return prepareIdentitySnapshotWithLimit(request, id, now, 10000)
}

func prepareIdentitySnapshotWithLimit(request identitySnapshotRequest, id string, now time.Time, maxRecords int) (store.IdentitySnapshot, error) {
	return prepareIdentitySnapshotContext(context.Background(), request, id, now, maxRecords)
}

func prepareIdentitySnapshotContext(ctx context.Context, request identitySnapshotRequest, id string, now time.Time, maxRecords int) (store.IdentitySnapshot, error) {
	result := store.IdentitySnapshot{IdentityScope: request.IdentityScope, SnapshotID: id, ObservedAt: request.ObservedAt.UTC(), IntervalSeconds: request.IntervalSeconds, Events: []normalized.Event{}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if request.Records == nil || !request.Complete || request.ExpectedCount == nil || *request.ExpectedCount != len(request.Records) || len(request.Records) > maxRecords {
		return result, fmt.Errorf("complete inventory and matching expected_count (0..%d) required", maxRecords)
	}
	for _, value := range []string{id, request.Source, request.SensorID} {
		if strings.TrimSpace(value) == "" || len(value) > 200 || value != strings.TrimSpace(value) {
			return result, fmt.Errorf("explicit source, sensor and snapshot ID required (maximum 200 characters)")
		}
	}
	for _, value := range []string{request.CampusID, request.AccessDomain} {
		if len(value) > 200 || value != strings.TrimSpace(value) {
			return result, fmt.Errorf("invalid optional identity scope")
		}
	}
	if (request.CampusID == "" || request.AccessDomain == "") && !strings.HasPrefix(request.Source, "srun4k:") {
		return result, fmt.Errorf("campus_id and access_domain are required outside managed srun4k sources")
	}
	// Redis TIME comes from the authentication server; use the same bounded
	// clock skew as upload metadata and product snapshots without rewriting it.
	if result.ObservedAt.IsZero() || result.ObservedAt.After(now.Add(time.Second)) || result.ObservedAt.Before(now.Add(-7*24*time.Hour)) || result.ObservedAt.Nanosecond()%1000 != 0 {
		return result, fmt.Errorf("observed_at must be within the past seven days, with at most one second of clock skew and microsecond precision")
	}
	maxInterval := 86400
	if strings.HasPrefix(request.Source, "srun4k:") {
		maxInterval = 604800
	}
	if request.IntervalSeconds < 1 || request.IntervalSeconds > maxInterval {
		return result, fmt.Errorf("reconcile_interval_seconds must be between 1 and %d", maxInterval)
	}
	fixed := map[string]string{"entity_role": "endpoint", "source": request.Source, "sensor_id": request.SensorID, "campus_id": request.CampusID, "access_domain": request.AccessDomain, "timestamp": result.ObservedAt.Format(time.RFC3339Nano), "session_status": "reconcile", "action": "reconcile", "heartbeat_interval_seconds": strconv.Itoa(request.IntervalSeconds), "reconcile_interval_seconds": strconv.Itoa(request.IntervalSeconds)}
	seen := make(map[[2]string]struct{}, len(request.Records))
	events := make([]normalized.Event, 0, len(request.Records))
	for i, record := range request.Records {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		fields := make(map[string]string, len(record)+len(fixed))
		copied := 0
		for k, v := range record {
			if copied%64 == 0 {
				if err := ctx.Err(); err != nil {
					return result, err
				}
			}
			fields[k] = v
			copied++
		}
		ip, err := netip.ParseAddr(fields["ip"])
		if err != nil || ip.IsUnspecified() || ip.Zone() != "" || strings.TrimSpace(fields["session_id"]) == "" || strings.TrimSpace(fields["account_id"]) == "" || fields["session_id"] != strings.TrimSpace(fields["session_id"]) || fields["account_id"] != strings.TrimSpace(fields["account_id"]) {
			return result, fmt.Errorf("record %d requires session_id, account_id and a valid IP", i+1)
		}
		fields["ip"] = ip.Unmap().String()
		key := [2]string{fields["session_id"], fields["ip"]}
		if _, exists := seen[key]; exists {
			return result, fmt.Errorf("duplicate session at record %d", i+1)
		}
		seen[key] = struct{}{}
		for k, v := range fixed {
			if old := fields[k]; old != "" && old != v {
				return result, fmt.Errorf("record %d conflicts with snapshot field %s", i+1, k)
			}
			fields[k] = v
		}
		event, err := identityadapter.NormalizeRecord(fields, i+1, identityadapter.Options{Source: request.Source, SensorID: request.SensorID})
		if err != nil {
			return result, fmt.Errorf("inventory contains invalid identity record %d: %w", i+1, err)
		}
		event.RawRef = map[string]any{"snapshot_id": id, "source": request.Source, "sensor_id": request.SensorID, "campus_id": request.CampusID, "access_domain": request.AccessDomain}
		events = append(events, event)
	}
	// Publish only after every record has passed; errors return the empty result.
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Events = events
	return result, nil
}

type identitySnapshotUploadCreate struct {
	store.IdentityScope
	UploadID        string    `json:"upload_id"`
	ObservedAt      time.Time `json:"observed_at"`
	IntervalHours   int       `json:"reconcile_interval_hours,omitempty"`
	IntervalSeconds int       `json:"reconcile_interval_seconds,omitempty"`
	ExpectedCount   int       `json:"expected_count"`
	ExpectedChunks  int       `json:"expected_chunks"`
	ExpectedSHA256  string    `json:"expected_sha256"`
}

func (r identitySnapshotUploadCreate) intervalSeconds() (int, error) {
	seconds := r.IntervalSeconds
	if r.IntervalHours > 0 {
		hourSeconds := r.IntervalHours * 3600
		if seconds > 0 && seconds != hourSeconds {
			return 0, fmt.Errorf("reconciliation interval fields disagree")
		}
		seconds = hourSeconds
	}
	if seconds < 1 || seconds > 7*24*3600 {
		return 0, fmt.Errorf("invalid reconciliation interval")
	}
	return seconds, nil
}

func identitySnapshotUploadPath(path string) (id string, chunk *int, commit bool, ok bool) {
	path = strings.TrimPrefix(path, "/api/v1")
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/integrations/identity/snapshot-uploads"), "/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		return parts[0], nil, false, true
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "commit" {
		return parts[0], nil, true, true
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] == "chunks" {
		index, err := strconv.Atoi(parts[2])
		if err == nil && index >= 0 {
			return parts[0], &index, false, true
		}
	}
	return "", nil, false, false
}

func (s *Server) handleIdentitySnapshotUploadCreate(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, http.StatusUnauthorized, "integration_auth_failed", "valid integration bearer token required")
		return
	}
	if (s.readOnly && !s.allowIdentityIngest) || s.operations.db == nil {
		writeError(w, http.StatusConflict, "identity_upload_unavailable", "database identity ingestion is unavailable")
		return
	}
	var request identitySnapshotUploadCreate
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_identity_upload", err.Error())
		return
	}
	request.UploadID = strings.TrimSpace(request.UploadID)
	request.ExpectedSHA256 = strings.ToLower(strings.TrimSpace(request.ExpectedSHA256))
	intervalSeconds, intervalErr := request.intervalSeconds()
	if request.UploadID == "" || len(request.UploadID) > 200 || request.Source == "" || request.SensorID == "" || intervalErr != nil || request.ExpectedCount < 0 || request.ExpectedCount > legacy4k.MaxIdentityAddressRecords || request.ExpectedChunks < 1 || request.ExpectedChunks > 200 || len(request.ExpectedSHA256) != 64 {
		writeError(w, http.StatusBadRequest, "bad_identity_upload", "invalid upload identity, size, digest or reconciliation interval")
		return
	}
	if _, err := hex.DecodeString(request.ExpectedSHA256); err != nil {
		writeError(w, http.StatusBadRequest, "bad_identity_upload", "expected_sha256 must be lowercase hexadecimal")
		return
	}
	if (request.CampusID == "" || request.AccessDomain == "") && !strings.HasPrefix(request.Source, "srun4k:") {
		writeError(w, http.StatusBadRequest, "bad_identity_upload", "explicit campus and access domain required for this source")
		return
	}
	if request.ObservedAt.IsZero() || request.ObservedAt.After(time.Now().UTC().Add(time.Second)) || request.ObservedAt.Before(time.Now().UTC().Add(-7*24*time.Hour)) {
		writeError(w, http.StatusBadRequest, "bad_identity_upload", "invalid observation time")
		return
	}
	_, err := s.operations.db.ExecContext(r.Context(), `INSERT INTO identity_snapshot_uploads(upload_id,source,sensor_id,campus_id,access_domain,observed_at,interval_seconds,expected_count,expected_chunks,expected_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(upload_id) DO NOTHING`, request.UploadID, request.Source, request.SensorID, request.CampusID, request.AccessDomain, request.ObservedAt.UTC(), intervalSeconds, request.ExpectedCount, request.ExpectedChunks, request.ExpectedSHA256)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_upload_create_failed", err.Error())
		return
	}
	var status string
	err = s.operations.db.QueryRowContext(r.Context(), `SELECT status FROM identity_snapshot_uploads WHERE upload_id=$1 AND source=$2 AND sensor_id=$3 AND campus_id=$4 AND access_domain=$5 AND observed_at=$6 AND interval_seconds=$7 AND expected_count=$8 AND expected_chunks=$9 AND expected_sha256=$10`, request.UploadID, request.Source, request.SensorID, request.CampusID, request.AccessDomain, request.ObservedAt.UTC(), intervalSeconds, request.ExpectedCount, request.ExpectedChunks, request.ExpectedSHA256).Scan(&status)
	if err != nil {
		writeError(w, http.StatusConflict, "identity_upload_conflict", "upload identity already belongs to different immutable content")
		return
	}
	code := http.StatusAccepted
	if status == "completed" {
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{"upload_id": request.UploadID, "status": status})
}

func (s *Server) handleIdentitySnapshotUpload(w http.ResponseWriter, r *http.Request, path string) {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, http.StatusUnauthorized, "integration_auth_failed", "valid integration bearer token required")
		return
	}
	if (s.readOnly && !s.allowIdentityIngest) || s.operations.db == nil {
		writeError(w, http.StatusConflict, "identity_upload_unavailable", "database identity ingestion is unavailable")
		return
	}
	id, chunk, commit, ok := identitySnapshotUploadPath(path)
	if !ok {
		writeError(w, http.StatusNotFound, "identity_upload_not_found", "identity upload endpoint not found")
		return
	}
	if chunk != nil && r.Method == http.MethodPut {
		s.handleIdentitySnapshotChunk(w, r, id, *chunk)
		return
	}
	if commit && r.Method == http.MethodPost {
		s.handleIdentitySnapshotCommit(w, r, id)
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported identity upload operation")
}

func (s *Server) handleIdentitySnapshotChunk(w http.ResponseWriter, r *http.Request, uploadID string, index int) {
	var records []map[string]string
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := decoder.Decode(&records); err != nil || len(records) > 2000 {
		writeError(w, http.StatusBadRequest, "bad_identity_chunk", "chunk must contain at most 2000 identity records")
		return
	}
	raw, err := json.Marshal(records)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_identity_chunk", err.Error())
		return
	}
	digest := sha256.Sum256(raw)
	contentHash := hex.EncodeToString(digest[:])
	var expectedChunks int
	var status string
	if err = s.operations.db.QueryRowContext(r.Context(), `SELECT expected_chunks,status FROM identity_snapshot_uploads WHERE upload_id=$1`, uploadID).Scan(&expectedChunks, &status); err != nil || index >= expectedChunks || status != "uploading" {
		writeError(w, http.StatusConflict, "identity_upload_not_writable", "identity upload is missing, complete or chunk index is outside its manifest")
		return
	}
	result, err := s.operations.db.ExecContext(r.Context(), `INSERT INTO identity_snapshot_upload_chunks(upload_id,chunk_index,record_count,content_sha256,records) VALUES($1,$2,$3,$4,$5) ON CONFLICT(upload_id,chunk_index) DO UPDATE SET received_at=identity_snapshot_upload_chunks.received_at WHERE identity_snapshot_upload_chunks.content_sha256=EXCLUDED.content_sha256`, uploadID, index, len(records), contentHash, raw)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_chunk_save_failed", err.Error())
		return
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		writeError(w, http.StatusConflict, "identity_chunk_conflict", "chunk index already contains different content")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"upload_id": uploadID, "chunk_index": index, "record_count": len(records), "content_sha256": contentHash})
}

func (s *Server) handleIdentitySnapshotCommit(w http.ResponseWriter, r *http.Request, uploadID string) {
	backend, ok := s.reader.(store.IdentityReconciler)
	if !ok {
		writeError(w, http.StatusConflict, "identity_reconciliation_unavailable", "full reconciliation requires database storage")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_upload_commit_failed", err.Error())
		return
	}
	defer tx.Rollback()
	var request identitySnapshotRequest
	var expectedChunks int
	var expectedHash, status string
	err = tx.QueryRowContext(ctx, `SELECT source,sensor_id,campus_id,access_domain,observed_at,interval_seconds,expected_count,expected_chunks,expected_sha256,status FROM identity_snapshot_uploads WHERE upload_id=$1 FOR UPDATE`, uploadID).Scan(&request.Source, &request.SensorID, &request.CampusID, &request.AccessDomain, &request.ObservedAt, &request.IntervalSeconds, &request.ExpectedCount, &expectedChunks, &expectedHash, &status)
	if err != nil {
		writeError(w, http.StatusNotFound, "identity_upload_not_found", "identity upload not found")
		return
	}
	if status == "completed" {
		writeJSON(w, http.StatusOK, map[string]any{"upload_id": uploadID, "status": "completed", "replayed": true})
		return
	}
	rows, err := tx.QueryContext(ctx, `SELECT chunk_index,records FROM identity_snapshot_upload_chunks WHERE upload_id=$1 ORDER BY chunk_index`, uploadID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_upload_commit_failed", err.Error())
		return
	}
	request.Records = []map[string]string{}
	hash := sha256.New()
	index := 0
	for rows.Next() {
		var chunkIndex int
		var raw []byte
		if err = rows.Scan(&chunkIndex, &raw); err != nil || chunkIndex != index {
			rows.Close()
			writeError(w, http.StatusConflict, "identity_upload_incomplete", "identity chunks are not contiguous")
			return
		}
		var chunk []map[string]string
		if err = json.Unmarshal(raw, &chunk); err != nil {
			rows.Close()
			writeError(w, http.StatusConflict, "identity_upload_invalid", "stored identity chunk is invalid")
			return
		}
		canonical, _ := json.Marshal(chunk)
		_, _ = hash.Write(canonical)
		request.Records = append(request.Records, chunk...)
		index++
	}
	rows.Close()
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if index != expectedChunks || request.ExpectedCount == nil || len(request.Records) != *request.ExpectedCount || actualHash != expectedHash {
		writeError(w, http.StatusConflict, "identity_upload_incomplete", "identity chunk count, record count or digest differs from the upload manifest")
		return
	}
	request.Complete = true
	snapshotID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if snapshotID == "" {
		snapshotID = "srun4k-snapshot-" + actualHash[:32]
	}
	snapshot, err := prepareIdentitySnapshotContext(ctx, request, snapshotID, time.Now().UTC(), legacy4k.MaxIdentityAddressRecords)
	if err != nil {
		if writeIdentityPreparationInterruption(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "bad_identity_snapshot", err.Error())
		return
	}
	if err = s.validateIdentitySourceContext(ctx, snapshot.IdentityScope, snapshot.IntervalSeconds); err != nil {
		writeIdentityAuthorityError(w, err)
		return
	}
	if _, err = backend.CommitIdentitySnapshot(ctx, snapshot); err != nil && !errors.Is(err, store.ErrIdentitySnapshotConflict) {
		writeError(w, http.StatusServiceUnavailable, "identity_snapshot_commit_failed", err.Error())
		return
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_snapshot_uploads SET status='completed',snapshot_id=$2,completed_at=now() WHERE upload_id=$1`, uploadID, snapshotID); err != nil || tx.Commit() != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_upload_commit_failed", "identity upload completion could not be persisted")
		return
	}
	_, _ = s.operations.db.ExecContext(context.Background(), `DELETE FROM identity_snapshot_upload_chunks WHERE upload_id=$1`, uploadID)
	writeJSON(w, http.StatusAccepted, map[string]any{"upload_id": uploadID, "snapshot_id": snapshotID, "status": "completed", "session_count": len(snapshot.Events)})
}

func (s *Server) handleIdentitySnapshot(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, 401, "integration_auth_failed", "valid integration bearer token required")
		return
	}
	if s.readOnly && !s.allowIdentityIngest {
		writeError(w, 403, "read_only", "identity ingestion disabled")
		return
	}
	backend, ok := s.reader.(store.IdentityReconciler)
	if !ok {
		writeError(w, 409, "identity_reconciliation_unavailable", "full reconciliation requires database storage")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	var request identitySnapshotRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, 400, "bad_identity_snapshot", err.Error())
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, 400, "bad_identity_snapshot", "exactly one JSON document required")
		return
	}
	snapshot, err := prepareIdentitySnapshotContext(ctx, request, r.Header.Get("Idempotency-Key"), time.Now().UTC(), 10000)
	if err != nil {
		if writeIdentityPreparationInterruption(w, err) {
			return
		}
		writeError(w, 400, "bad_identity_snapshot", err.Error())
		return
	}
	if err = s.validateIdentitySourceContext(ctx, snapshot.IdentityScope, snapshot.IntervalSeconds); err != nil {
		writeIdentityAuthorityError(w, err)
		return
	}
	if err := ctx.Err(); err != nil {
		writeIdentityAuthorityError(w, err)
		return
	}
	created, err := backend.CommitIdentitySnapshot(ctx, snapshot)
	if errors.Is(err, store.ErrIdentitySnapshotConflict) {
		writeError(w, 409, "identity_snapshot_conflict", err.Error())
		return
	}
	if err != nil {
		writeError(w, 503, "identity_snapshot_commit_failed", err.Error())
		return
	}
	code := http.StatusAccepted
	if !created {
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{"snapshot_id": snapshot.SnapshotID, "status": "completed", "observed_at": snapshot.ObservedAt, "session_count": len(snapshot.Events), "replayed": !created})
}
