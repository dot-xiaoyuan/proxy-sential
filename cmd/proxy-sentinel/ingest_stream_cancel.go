package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

// stream-cancel closes a stopped epoch with pending sinks without draining,
// releasing or rewriting its journal. Fresh preparation separately certifies
// unread files/rotation; this command does not authorize moving a source cursor.
func runIngestStreamCancel(args []string) error {
	fs := flag.NewFlagSet("ingest stream-cancel", flag.ContinueOnError)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered sensor")
	kind := fs.String("source-kind", "", "device-signals, zeek-dhcp-binding or passive-discovery")
	path := fs.String("source-path", "", "exact stopped source path")
	dir := fs.String("journal-dir", "", "retained stopped journal")
	dsn := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	id := fs.String("cancel-id", "", "immutable cancellation identifier")
	reason := fs.String("reason", "", "audited reason for abandoning old processing")
	cutoffText := fs.String("cutoff-at", "", "immutable RFC3339 cutoff, after stopping the reader")
	fileAuditPath := fs.String("source-file-audit", "", "immutable compact unread-file audit JSON; created once, retained for retries")
	apply := fs.Bool("apply", false, "persist cancellation and close the epoch; default is preview")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cutoff, err := time.Parse(time.RFC3339Nano, *cutoffText)
	if err != nil || cutoff.IsZero() || cutoff.After(time.Now()) || fs.NArg() != 0 || *sensor == "" || *path == "" || *dir == "" || *dsn == "" || *id == "" || len(*id) > 128 || strings.TrimSpace(*reason) == "" || len(*reason) > 512 ||
		(*kind != "device-signals" && *kind != "zeek-dhcp-binding" && *kind != "passive-discovery") {
		return errors.New("stream-cancel requires a supported stopped source, journal, sensor, database, fixed cutoff, cancellation ID and reason")
	}
	j, err := streamlog.Open(*dir)
	if err != nil {
		return err
	}
	release, err := j.AcquireSourceLease(*kind, *path)
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	leaseStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: *dsn, SensorID: *sensor})
	if err != nil {
		return err
	}
	defer leaseStore.Close()
	releaseDB, err := leaseStore.AcquireIngestSourceLease(ctx, *kind, *path)
	if err != nil {
		return err
	}
	defer releaseDB()
	cursor, segments, err := j.SnapshotCancellation(*kind, *path, cutoff)
	if err != nil {
		return err
	}
	var fileAudit *cancelledSourceFiles
	if *fileAuditPath != "" {
		if *kind == "passive-discovery" {
			return errors.New("packet source has no unread file audit")
		}
		fileAudit, err = loadOrSnapshotCancelledFiles(*fileAuditPath, cursor)
		if err != nil {
			return err
		}
	} else if *kind != "passive-discovery" && *apply {
		return errors.New("file source cancellation requires --source-file-audit to preserve a fixed fresh boundary")
	}
	db, err := sql.Open("pgx", *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	manifest, err := auditPendingStreamCancellation(ctx, db, *sensor, *id, *reason, cutoff, cursor, segments, *apply, fileAudit)
	if err != nil {
		return err
	}
	state := "preview"
	if *apply {
		state = "closed_cancelled_unprocessed"
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"state": state, "epoch": cursor.Epoch, "cursor": cursor,
		"pending_segments": segments, "retirement_manifest_sha256": manifest, "cancel_id": *id, "cutoff_at": cutoff.UTC(),
		"journal_retained": true, "unread_source_audit_required": fileAudit == nil && *kind != "passive-discovery", "source_file_audit": fileAudit})
}

func auditPendingStreamCancellation(ctx context.Context, db *sql.DB, sensor, cancelID, reason string, cutoff time.Time, cursor streamlog.SourceCursor, segments []streamlog.CancellationSegment, apply bool, fileAudits ...*cancelledSourceFiles) (string, error) {
	var fileAudit *cancelledSourceFiles
	if len(fileAudits) > 1 {
		return "", streamlog.ErrContentConflict
	}
	if len(fileAudits) == 1 {
		fileAudit = fileAudits[0]
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: !apply})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	query := `SELECT sensor_id,parser_version,cancel_manifest_sha256,state FROM stream_source_cutovers WHERE epoch=$1 AND source_kind=$2 AND source_path=$3`
	if apply {
		query += " FOR UPDATE"
	}
	var owner, parser, originalManifest, state string
	if err := tx.QueryRowContext(ctx, query, cursor.Epoch, cursor.Source, cursor.Path).Scan(&owner, &parser, &originalManifest, &state); err != nil {
		return "", err
	}
	if owner != sensor || parser != cursor.ParserVersion || len(originalManifest) != 64 || state != "active" && state != "closed" {
		return "", streamlog.ErrContentConflict
	}
	body, err := json.Marshal(struct {
		Sensor, CancelID, Reason, OriginalManifest string
		Cutoff                                     time.Time
		Cursor                                     streamlog.SourceCursor
		Segments                                   []streamlog.CancellationSegment
		Files                                      *cancelledSourceFiles `json:",omitempty"`
	}{sensor, cancelID, reason, originalManifest, cutoff.UTC(), cursor, segments, fileAudit})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	manifest := hex.EncodeToString(sum[:])
	var existing int
	var existingRef, existingHash string
	rows, err := tx.QueryContext(ctx, `SELECT legacy_reference,content_sha256 FROM stream_discard_manifest WHERE epoch=$1 AND source_kind=$2 AND source_path=$3 AND legacy_kind='stream_retirement_manifest' LIMIT 2`, cursor.Epoch, cursor.Source, cursor.Path)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		if err := rows.Scan(&existingRef, &existingHash); err != nil {
			rows.Close()
			return "", err
		}
		existing++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if state == "closed" {
		if existing != 1 || existingRef != cancelID || existingHash != manifest {
			return "", streamlog.ErrContentConflict
		}
		return manifest, tx.Commit()
	}
	if existing != 0 {
		return "", streamlog.ErrContentConflict
	}
	if !apply {
		return manifest, tx.Commit()
	}
	retiredFile, retiredOffset := cursor.FileID, cursor.Offset
	if fileAudit != nil {
		retiredFile, retiredOffset = fileAudit.FileID, fileAudit.Offset
	}
	entries := []zeekDiscardEntry{
		{LegacyKind: "stream_retirement_cursor", LegacyReference: fmt.Sprint(retiredOffset), LegacyStatus: "closed_audited", ContentSHA256: manifest},
		{LegacyKind: "stream_retirement_file_id", LegacyReference: retiredFile, LegacyStatus: "closed_audited", ContentSHA256: manifest},
		{LegacyKind: "stream_retirement_manifest", LegacyReference: cancelID, LegacyStatus: "closed_audited", ContentSHA256: manifest},
		{LegacyKind: "stream_retirement_reason", LegacyReference: reason, LegacyStatus: "cancelled_unprocessed", ContentSHA256: manifest},
	}
	if fileAudit != nil {
		entries = append(entries, fileAudit.Entries...)
		entries = append(entries, zeekDiscardEntry{LegacyKind: "stream_cancelled_original_cursor", LegacyReference: fmt.Sprintf("%s:%d", cursor.FileID, cursor.Offset), LegacyStatus: "cancelled_unprocessed", ContentSHA256: manifest})
		for _, path := range fileAudit.RetainedFiles {
			entries = append(entries, zeekDiscardEntry{LegacyKind: "stream_retained_source_file", LegacyReference: path, LegacyStatus: "retained", ContentSHA256: manifest})
		}
	}
	for _, s := range segments {
		encoded, err := json.Marshal(s)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(encoded)
		entries = append(entries, zeekDiscardEntry{LegacyKind: "stream_pending_segment", LegacyReference: s.ID,
			LegacyStatus: "cancelled_unprocessed", ContentSHA256: s.ContentSHA256, UnprocessedRecords: int64(s.Events),
			UnprocessedBytes: s.EndOffset - s.StartOffset, FirstUnprocessedAt: &s.AcceptedAt, LastUnprocessedAt: &s.AcceptedAt})
		entries = append(entries, zeekDiscardEntry{LegacyKind: "stream_pending_checkpoint", LegacyReference: s.ID, LegacyStatus: "retained", ContentSHA256: hex.EncodeToString(sum[:])})
		for lane, status := range s.Acks {
			entries = append(entries, zeekDiscardEntry{LegacyKind: "stream_pending_lane", LegacyReference: s.ID + ":" + string(lane), LegacyStatus: string(status), ContentSHA256: s.ContentSHA256})
		}
	}
	// At most 500 segments; persist at most 500 compact audit rows per query.
	for start := 0; start < len(entries); start += 500 {
		end := min(start+500, len(entries))
		payload, err := json.Marshal(entries[start:end])
		if err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest(epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records,unprocessed_bytes,first_unprocessed_at,last_unprocessed_at)
 SELECT $1,$2,$3,v.legacy_kind,v.legacy_reference,v.legacy_status,v.content_sha256,v.unprocessed_records,v.unprocessed_bytes,v.first_unprocessed_at,v.last_unprocessed_at
 FROM jsonb_to_recordset($4::jsonb) AS v(legacy_kind text,legacy_reference text,legacy_status text,content_sha256 text,unprocessed_records bigint,unprocessed_bytes bigint,first_unprocessed_at timestamptz,last_unprocessed_at timestamptz)`, cursor.Epoch, cursor.Source, cursor.Path, payload); err != nil {
			return "", err
		}
	}
	if cursor.Source == "device-signals" {
		result, err := tx.ExecContext(ctx, `UPDATE stream_shared_source_cutovers SET state='closed' WHERE sensor_id=$1 AND epoch=$2 AND source_path=$3 AND state='active'`, sensor, cursor.Epoch, cursor.Path)
		if err != nil {
			return "", err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return "", errors.New("shared source has no unique active generation")
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='closed' WHERE epoch=$1 AND source_kind=$2 AND source_path=$3 AND state='active'`, cursor.Epoch, cursor.Source, cursor.Path)
	if err != nil {
		return "", err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return "", errors.New("source lost its active cancellation scope")
	}
	return manifest, tx.Commit()
}

// The saved compact snapshot makes preview/apply/retry use the same byte
// boundary even while the producer appends. It contains no source records.
func loadOrSnapshotCancelledFiles(path string, cursor streamlog.SourceCursor) (*cancelledSourceFiles, error) {
	type snapshot struct {
		Cursor streamlog.SourceCursor
		Files  *cancelledSourceFiles
	}
	saved, err := os.Open(path)
	if err == nil {
		defer saved.Close()
		var value snapshot
		decoder := json.NewDecoder(io.LimitReader(saved, 2<<20))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&value); err != nil {
			return nil, err
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return nil, streamlog.ErrContentConflict
		}
		original, _ := json.Marshal(cursor)
		recorded, _ := json.Marshal(value.Cursor)
		if string(original) != string(recorded) || value.Files == nil {
			return nil, streamlog.ErrContentConflict
		}
		if err = validateCancellationBoundary(cursor, value.Files); err != nil {
			return nil, err
		}
		if err = validateRetainedCancellationFiles(cursor, value.Files); err != nil {
			return nil, err
		}
		return value.Files, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	files, err := snapshotCancelledSourceFiles(cursor, 16<<30)
	if err != nil {
		return nil, err
	}
	if err = retainCancellationFiles(files, path+".sources"); err != nil {
		return nil, err
	}
	if err = validateRetainedCancellationFiles(cursor, files); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(snapshot{cursor, files})
	if err != nil {
		return nil, err
	}
	if len(raw) > 2<<20 {
		return nil, errors.New("compact source audit exceeds 2 MiB")
	}
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, err = output.Write(raw)
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return nil, err
	}
	return files, nil
}
