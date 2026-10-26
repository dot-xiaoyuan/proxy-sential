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
	"os"
	"time"

	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

// Retire a stopped file reader only after every accepted journal segment has
// reached its sinks. Unread source bytes are audited by the following prepare.
func runIngestStreamRetire(args []string) error {
	fs := flag.NewFlagSet("ingest stream-retire", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered sensor")
	path := fs.String("device-signals", "", "stopped sidecar source file")
	rotationSource := fs.String("rotation-source", "", "retained uncompressed rotated file when the cursor is behind rotation")
	journalDir := fs.String("journal-dir", "", "stopped source journal")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	cancelID := fs.String("cancel-id", "", "immutable new cancellation identifier")
	cutoffText := fs.String("cutoff-at", "", "RFC3339 audit cutoff")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sensor == "" || *path == "" || *journalDir == "" || *postgresDSN == "" || *cancelID == "" || *cutoffText == "" {
		return errors.New("stream-retire requires sensor, source, journal, database and cutoff")
	}
	cutoff, err := time.Parse(time.RFC3339Nano, *cutoffText)
	if err != nil || cutoff.After(time.Now()) {
		return errors.New("invalid retirement cutoff")
	}
	journal, err := streamlog.Open(*journalDir)
	if err != nil {
		return err
	}
	releaseJournal, err := journal.AcquireSourceLease("device-signals", *path)
	if err != nil {
		return err
	}
	defer releaseJournal()
	ctx := context.Background()
	leaseStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: *postgresDSN, SensorID: *sensor})
	if err != nil {
		return err
	}
	defer leaseStore.Close()
	releaseDB, err := leaseStore.AcquireIngestSourceLease(ctx, "device-signals", *path)
	if err != nil {
		return err
	}
	defer releaseDB()
	cursor, err := journal.LoadSource("device-signals", *path)
	if err != nil {
		return err
	}
	pending, err := journal.PendingSegments()
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return fmt.Errorf("retirement requires drained journal: %d pending segments", len(pending))
	}
	if *rotationSource != "" && *rotationSource != *path+".1" {
		return errors.New("rotation source must be the retained .1 file")
	}
	evidencePath := *path
	if *rotationSource != "" {
		evidencePath = *rotationSource
	}
	file, err := os.Open(evidencePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || realtime.FileIdentity(*path, info) != cursor.FileID || cursor.Offset > info.Size() {
		return errors.New("retirement cursor does not match the current source file")
	}
	var rotatedUnread zeekCutoverBytes
	var rotatedChunks []zeekCutoverBytes
	if *rotationSource != "" {
		current, err := os.Stat(*path)
		if err != nil {
			return err
		}
		if !current.Mode().IsRegular() || realtime.FileIdentity(*path, current) == cursor.FileID {
			return streamlog.ErrContentConflict
		}
		rotatedUnread, rotatedChunks, err = scanFileCutoverChunks(file, cursor.Offset, info.Size(), false, 8<<20)
		if err != nil {
			return err
		}
		if rotatedUnread.Offset != info.Size() {
			return errors.New("rotated source has an incomplete final record")
		}
		stable, err := os.Stat(evidencePath)
		if err != nil || !os.SameFile(info, stable) || stable.Size() != info.Size() {
			return errors.New("rotation evidence changed during retirement")
		}
	}
	if cursor.TailBytes > 0 {
		if cursor.TailBytes > streamlog.SourceTailProofBytes || int64(cursor.TailBytes) > cursor.Offset {
			return streamlog.ErrContentConflict
		}
		tail := make([]byte, cursor.TailBytes)
		if _, err := file.ReadAt(tail, cursor.Offset-int64(cursor.TailBytes)); err != nil {
			return err
		}
		sum := sha256.Sum256(tail)
		if hex.EncodeToString(sum[:]) != cursor.TailSHA256 {
			return streamlog.ErrContentConflict
		}
	}
	db, err := sql.Open("pgx", *postgresDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var registeredSensor, originalFile, originalCancel, originalManifest, state string
	err = tx.QueryRowContext(ctx, `SELECT sensor_id,file_id,legacy_cancel_id,cancel_manifest_sha256,state FROM stream_source_cutovers WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 FOR UPDATE`, cursor.Epoch, *path).Scan(&registeredSensor, &originalFile, &originalCancel, &originalManifest, &state)
	if err != nil {
		return err
	}
	if registeredSensor != *sensor || state != "active" || originalManifest == "" || originalCancel == "" || originalFile == "" {
		return streamlog.ErrContentConflict
	}
	var sharedOwner, sharedCancel, sharedState string
	err = tx.QueryRowContext(ctx, `SELECT source_owner,cancel_id,state FROM stream_shared_source_cutovers WHERE sensor_id=$1 AND epoch=$2 AND source_path=$3 FOR UPDATE`, *sensor, cursor.Epoch, *path).Scan(&sharedOwner, &sharedCancel, &sharedState)
	if err != nil {
		return err
	}
	if sharedState != "active" || sharedCancel == "" || sharedOwner != "packet-sidecar" && sharedOwner != "handshake-sidecar" {
		return streamlog.ErrContentConflict
	}
	encoded, err := json.Marshal(struct {
		Sensor, Epoch, Path, OriginalFile, CurrentFile, OriginalManifest, SharedCancel, CancelID, LastSegmentID, TailSHA256, RotatedUnreadSHA256 string
		Offset                                                                                                                                   int64
		RotatedUnreadEnd                                                                                                                         int64
		Cutoff                                                                                                                                   time.Time
	}{*sensor, cursor.Epoch, *path, originalFile, cursor.FileID, originalManifest, sharedCancel, *cancelID, cursor.LastSegmentID, cursor.TailSHA256, rotatedUnread.SHA256, cursor.Offset, rotatedUnread.Offset, cutoff.UTC()})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	manifest := hex.EncodeToString(sum[:])
	for _, entry := range []struct{ kind, ref string }{{"stream_retirement_cursor", fmt.Sprint(cursor.Offset)}, {"stream_retirement_file_id", cursor.FileID}, {"stream_retirement_manifest", *cancelID}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest(epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records,unprocessed_bytes,first_unprocessed_at) VALUES($1,'device-signals',$2,$3,$4,'closed_audited',$5,0,0,$6)`, cursor.Epoch, *path, entry.kind, entry.ref, manifest, cutoff.UTC()); err != nil {
			return err
		}
	}
	start := cursor.Offset
	for _, chunk := range rotatedChunks {
		ref := cursor.FileID + ":" + fmt.Sprint(start) + ":" + fmt.Sprint(chunk.Offset)
		if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest(epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records,unprocessed_bytes,first_unprocessed_at) VALUES($1,'device-signals',$2,'stream_retirement_unread_chunk',$3,'cancelled_unprocessed',$4,$5,$6,$7)`, cursor.Epoch, *path, ref, chunk.SHA256, chunk.Records, chunk.Bytes, cutoff.UTC()); err != nil {
			return err
		}
		start = chunk.Offset
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stream_shared_source_cutovers SET state='closed' WHERE sensor_id=$1 AND epoch=$2 AND source_path=$3 AND state='active'`, *sensor, cursor.Epoch, *path); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='closed' WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 AND state='active'`, cursor.Epoch, *path); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"epoch": cursor.Epoch, "source_path": *path, "cursor_file_id": cursor.FileID, "cursor_offset": cursor.Offset, "last_segment_id": cursor.LastSegmentID, "source_size_at_retirement": info.Size(), "rotated_unread_records": rotatedUnread.Records, "rotated_unread_bytes": rotatedUnread.Bytes, "rotated_audit_batches": len(rotatedChunks), "retirement_manifest_sha256": manifest, "cutoff_at": cutoff.UTC(), "state": "closed"})
}
