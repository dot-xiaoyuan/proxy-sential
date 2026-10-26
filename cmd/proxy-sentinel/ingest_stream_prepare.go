package main

import (
	"bufio"
	"bytes"
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
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

type zeekCutoverBytes struct {
	Offset  int64
	Records int64
	Bytes   int64
	SHA256  string
}

func captureScopeFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return "", err
	}
	if len(raw) > 65536 {
		return "", errors.New("capture scope exceeds hash bound")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func loadCaptureScopeWithHash(path string) (*normalized.CaptureScope, string, error) {
	first, err := captureScopeFileHash(path)
	if err != nil {
		return nil, "", err
	}
	scope, err := normalized.LoadCaptureScope(path)
	if err != nil {
		return nil, "", err
	}
	second, err := captureScopeFileHash(path)
	if err != nil {
		return nil, "", err
	}
	if first != second {
		return nil, "", errors.New("capture scope changed during validation")
	}
	return scope, first, nil
}

// Leave an incomplete trailing line for the fresh reader. The old range is
// hashed and counted only through the last complete record boundary.
func scanZeekCutoverBytes(file *os.File, from, size int64) (zeekCutoverBytes, error) {
	return scanFileCutoverBytes(file, from, size, true)
}

func scanFileCutoverBytes(file *os.File, from, size int64, zeek bool) (zeekCutoverBytes, error) {
	result, _, err := scanFileCutoverChunks(file, from, size, zeek, 0)
	return result, err
}

// Chunk hashes make a large canceled range independently verifiable without
// treating any of its records as successfully consumed.
func scanFileCutoverChunks(file *os.File, from, size int64, zeek bool, chunkLimit int64) (zeekCutoverBytes, []zeekCutoverBytes, error) {
	if file == nil || from < 0 || size < from {
		return zeekCutoverBytes{}, nil, errors.New("invalid file cutover range")
	}
	if _, err := file.Seek(from, io.SeekStart); err != nil {
		return zeekCutoverBytes{}, nil, err
	}
	reader := bufio.NewReaderSize(io.LimitReader(file, size-from), 1<<20)
	hash := sha256.New()
	result := zeekCutoverBytes{Offset: from}
	chunkHash := sha256.New()
	chunk := zeekCutoverBytes{Offset: from}
	chunks := []zeekCutoverBytes{}
	finishChunk := func() {
		if chunk.Bytes == 0 {
			return
		}
		chunk.SHA256 = hex.EncodeToString(chunkHash.Sum(nil))
		chunks = append(chunks, chunk)
		chunk = zeekCutoverBytes{Offset: result.Offset}
		chunkHash.Reset()
	}
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return zeekCutoverBytes{}, nil, errors.New("source line exceeds cutover audit bound")
		}
		if err != nil {
			return zeekCutoverBytes{}, nil, err
		}
		if _, err := hash.Write(line); err != nil {
			return zeekCutoverBytes{}, nil, err
		}
		if chunkLimit > 0 {
			_, _ = chunkHash.Write(line)
			chunk.Bytes += int64(len(line))
			chunk.Offset += int64(len(line))
		}
		result.Offset += int64(len(line))
		result.Bytes += int64(len(line))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 && (!zeek || trimmed[0] != '#') {
			result.Records++
			if chunkLimit > 0 {
				chunk.Records++
			}
		}
		if chunkLimit > 0 && chunk.Bytes >= chunkLimit {
			finishChunk()
		}
	}
	if chunkLimit > 0 {
		finishChunk()
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, chunks, nil
}

type zeekDiscardEntry struct {
	LegacyKind         string     `json:"legacy_kind"`
	LegacyReference    string     `json:"legacy_reference"`
	LegacyStatus       string     `json:"legacy_status"`
	ContentSHA256      string     `json:"content_sha256"`
	UnprocessedRecords int64      `json:"unprocessed_records"`
	UnprocessedBytes   int64      `json:"unprocessed_bytes"`
	FirstUnprocessedAt *time.Time `json:"first_unprocessed_at,omitempty"`
	LastUnprocessedAt  *time.Time `json:"last_unprocessed_at,omitempty"`
}

func legacyZeekDiscardEntries(ctx context.Context, db *sql.DB, sensor, path, fileID string, from int64, scan zeekCutoverBytes, cutoff time.Time) ([]zeekDiscardEntry, error) {
	return legacyFileDiscardEntries(ctx, db, "zeek-dhcp", sensor, path, fileID, from, scan, cutoff)
}

func legacyFileDiscardEntries(ctx context.Context, db *sql.DB, kind, sensor, path, fileID string, from int64, scan zeekCutoverBytes, cutoff time.Time, chunks ...zeekCutoverBytes) ([]zeekDiscardEntry, error) {
	legacyKind := "unread_zeek_file"
	if kind == "device-signals" || kind == "shared-device-signals" {
		legacyKind = "unread_device_signal_file"
	}
	entries := []zeekDiscardEntry{{
		LegacyKind: legacyKind, LegacyReference: fileID + ":" + strconv.FormatInt(from, 10) + ":" + strconv.FormatInt(scan.Offset, 10),
		LegacyStatus: "cancelled_unprocessed", ContentSHA256: scan.SHA256,
		UnprocessedRecords: scan.Records, UnprocessedBytes: scan.Bytes,
	}}
	if len(chunks) > 0 {
		entries = entries[:0]
		start := from
		for _, chunk := range chunks {
			entries = append(entries, zeekDiscardEntry{LegacyKind: legacyKind + "_chunk", LegacyReference: fileID + ":" + strconv.FormatInt(start, 10) + ":" + strconv.FormatInt(chunk.Offset, 10), LegacyStatus: "cancelled_unprocessed", ContentSHA256: chunk.SHA256, UnprocessedRecords: chunk.Records, UnprocessedBytes: chunk.Bytes})
			start = chunk.Offset
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT batch_id,status,checksum,start_offset,end_offset,event_count,started_at
 FROM ingest_batches WHERE sensor_id=$1 AND source_kind=$2 AND source_path=$3
 AND status<>'committed' AND started_at<=$4 ORDER BY batch_id LIMIT 501`, sensor, kind, path, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status, checksum string
		var start, end, count int64
		var started time.Time
		if err = rows.Scan(&id, &status, &checksum, &start, &end, &count, &started); err != nil {
			return nil, err
		}
		if len(entries) > 500 {
			return nil, errors.New("legacy cancellation audit exceeds bounded batch")
		}
		if end < start {
			return nil, errors.New("invalid old file batch offsets")
		}
		at := started.UTC()
		entries = append(entries, zeekDiscardEntry{LegacyKind: "ingest_batch", LegacyReference: id,
			LegacyStatus: "cancelled_unprocessed:" + status, ContentSHA256: checksum,
			UnprocessedRecords: count, UnprocessedBytes: end - start, FirstUnprocessedAt: &at})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

type zeekCutoverRecord struct {
	Epoch, Source, Path, Sensor, FileID, Parser, PreviousRelease, CancelID, ManifestHash, ScopeHash, State string
	Offset                                                                                                 int64
	Cutoff                                                                                                 time.Time
}

func loadZeekCutover(ctx context.Context, db *sql.DB, epoch, path string) (zeekCutoverRecord, bool, error) {
	return loadFileCutover(ctx, db, "zeek-dhcp", epoch, path)
}

func loadFileCutover(ctx context.Context, db *sql.DB, kind, epoch, path string) (zeekCutoverRecord, bool, error) {
	var item zeekCutoverRecord
	err := db.QueryRowContext(ctx, `SELECT epoch,source_kind,source_path,sensor_id,file_id,start_offset,parser_version,previous_release,legacy_cutoff_at,legacy_cancel_id,cancel_manifest_sha256,capture_scope_sha256,state
 FROM stream_source_cutovers WHERE epoch=$1 AND source_kind=$2 AND source_path=$3`, epoch, kind, path).
		Scan(&item.Epoch, &item.Source, &item.Path, &item.Sensor, &item.FileID, &item.Offset, &item.Parser, &item.PreviousRelease, &item.Cutoff, &item.CancelID, &item.ManifestHash, &item.ScopeHash, &item.State)
	if errors.Is(err, sql.ErrNoRows) {
		return zeekCutoverRecord{}, false, nil
	}
	if err != nil {
		return zeekCutoverRecord{}, false, err
	}
	return item, true, nil
}

func prepareZeekDHCPStream(ctx context.Context, db *sql.DB, journal *streamlog.Journal, sensor, path, epoch, cancelID, previousRelease, scopeHash string, cutoff time.Time) (zeekCutoverBytes, string, error) {
	return prepareControlledFileStream(ctx, db, journal, "zeek-dhcp", sensor, path, epoch, cancelID, previousRelease, scopeHash, cutoff)
}

func prepareControlledFileStream(ctx context.Context, db *sql.DB, journal *streamlog.Journal, kind, sensor, path, epoch, cancelID, previousRelease, scopeHash string, cutoff time.Time) (zeekCutoverBytes, string, error) {
	return prepareControlledFileStreamAfterClosed(ctx, db, journal, kind, sensor, path, epoch, cancelID, previousRelease, scopeHash, cutoff, "", "")
}

func prepareControlledFileStreamAfterClosed(ctx context.Context, db *sql.DB, journal *streamlog.Journal, kind, sensor, path, epoch, cancelID, previousRelease, scopeHash string, cutoff time.Time, priorEpoch, priorManifest string) (zeekCutoverBytes, string, error) {
	return prepareControlledFileStreamAfterClosedWithRotation(ctx, db, journal, kind, sensor, path, epoch, cancelID, previousRelease, scopeHash, cutoff, priorEpoch, priorManifest, "")
}

func prepareControlledFileStreamAfterClosedWithRotation(ctx context.Context, db *sql.DB, journal *streamlog.Journal, kind, sensor, path, epoch, cancelID, previousRelease, scopeHash string, cutoff time.Time, priorEpoch, priorManifest, rotationArchive string) (zeekCutoverBytes, string, error) {
	parser := streamParserForSource(kind)
	if parser == "" || db == nil || journal == nil || sensor == "" || path == "" || epoch == "" || len(epoch) > 128 || cancelID == "" || previousRelease == "" || len(scopeHash) != 64 || cutoff.IsZero() || cutoff.After(time.Now()) || (priorEpoch == "") != (priorManifest == "") || (priorEpoch != "" && (kind != "zeek-dhcp-binding" && kind != "device-signals" || priorEpoch == epoch || len(priorManifest) != 64)) || (rotationArchive != "" && (priorEpoch == "" || kind != "zeek-dhcp-binding" && kind != "device-signals")) {
		return zeekCutoverBytes{}, "", errors.New("invalid controlled file fresh-cutover parameters")
	}
	existing, found, err := loadFileCutover(ctx, db, kind, epoch, path)
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	var otherActive int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM stream_source_cutovers WHERE source_kind=$1 AND source_path=$2 AND state='active' AND epoch<>$3`, kind, path, epoch).Scan(&otherActive); err != nil {
		return zeekCutoverBytes{}, "", err
	}
	if otherActive != 0 {
		return zeekCutoverBytes{}, "", errors.New("another epoch owns this file source")
	}
	var lateBatches int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM ingest_batches WHERE sensor_id=$1 AND source_kind=$2 AND source_path=$3 AND started_at>$4`, sensor, kind, path, cutoff).Scan(&lateBatches); err != nil {
		return zeekCutoverBytes{}, "", err
	}
	if lateBatches != 0 {
		return zeekCutoverBytes{}, "", errors.New("legacy file batches exist after the declared cutoff")
	}
	file, err := os.Open(path)
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	if !before.Mode().IsRegular() {
		return zeekCutoverBytes{}, "", errors.New("source is not a regular file")
	}
	fileID := realtime.FileIdentity(path, before)
	if found && (existing.Sensor != sensor || existing.FileID != fileID || existing.Parser != parser || existing.PreviousRelease != previousRelease || existing.CancelID != cancelID || existing.ScopeHash != scopeHash || !existing.Cutoff.Equal(cutoff) || (existing.State != "prepared" && existing.State != "active")) {
		return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
	}
	var oldFile string
	var from int64
	var priorRetiredFile string
	if priorEpoch != "" {
		rows, queryErr := db.QueryContext(ctx, `SELECT c.sensor_id,c.file_id,d.legacy_reference,d.content_sha256,coalesce(f.legacy_reference,'')
 FROM stream_source_cutovers c JOIN stream_discard_manifest d
  ON d.epoch=c.epoch AND d.source_kind=c.source_kind AND d.source_path=c.source_path
 LEFT JOIN stream_discard_manifest f
  ON f.epoch=c.epoch AND f.source_kind=c.source_kind AND f.source_path=c.source_path
  AND f.legacy_kind='stream_retirement_file_id' AND f.content_sha256=d.content_sha256
 WHERE c.epoch=$1 AND c.source_kind=$2 AND c.source_path=$3 AND c.state='closed'
  AND d.legacy_kind='stream_retirement_cursor' AND d.content_sha256=$4
  AND EXISTS (SELECT 1 FROM stream_discard_manifest m WHERE m.epoch=c.epoch AND m.source_kind=c.source_kind AND m.source_path=c.source_path
    AND m.legacy_kind='stream_retirement_manifest' AND m.content_sha256=d.content_sha256) LIMIT 2`, priorEpoch, kind, path, priorManifest)
		if queryErr != nil {
			return zeekCutoverBytes{}, "", queryErr
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var priorSensor, offsetText, recordedHash string
			if err := rows.Scan(&priorSensor, &oldFile, &offsetText, &recordedHash, &priorRetiredFile); err != nil {
				return zeekCutoverBytes{}, "", err
			}
			if priorSensor != sensor || recordedHash != priorManifest ||
				(oldFile != fileID && priorRetiredFile != fileID && rotationArchive == "") {
				return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
			}
			from, err = strconv.ParseInt(offsetText, 10, 64)
			if err != nil || from < 0 {
				return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
			}
			count++
		}
		if err := rows.Err(); err != nil {
			return zeekCutoverBytes{}, "", err
		}
		if count != 1 {
			return zeekCutoverBytes{}, "", errors.New("prior closed stream has no unique audited retirement cursor")
		}
		if rotationArchive != "" {
			if oldFile == fileID || kind == "zeek-dhcp-binding" && priorRetiredFile != "" || kind == "device-signals" && (rotationArchive != path+".1" || priorRetiredFile == "") {
				return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
			}
		}
	} else {
		err = db.QueryRowContext(ctx, `SELECT file_id,committed_offset FROM ingest_checkpoints WHERE sensor_id=$1 AND source_kind=$2 AND source_path=$3`, sensor, kind, path).Scan(&oldFile, &from)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return zeekCutoverBytes{}, "", err
		}
		if oldFile != "" && oldFile != fileID {
			return zeekCutoverBytes{}, "", errors.New("old checkpoint belongs to another file; audit rotated gap first")
		}
	}
	rotationEntries := []zeekDiscardEntry{}
	if rotationArchive != "" {
		if kind == "device-signals" {
			rotationEntries, err = verifyClosedDeviceRotation(ctx, db, path, rotationArchive, priorRetiredFile, from, priorEpoch)
		} else {
			rotationEntries, err = verifyClosedRotationArchive(ctx, db, path, rotationArchive, oldFile, from, priorEpoch)
		}
		if err != nil {
			return zeekCutoverBytes{}, "", err
		}
		from = 0
	}
	size := before.Size()
	if found {
		size = existing.Offset
	}
	if size < from || size > before.Size() {
		return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
	}
	chunkLimit := int64(0)
	if kind == "device-signals" && priorEpoch != "" {
		chunkLimit = 8 << 20
	}
	scan, chunks, err := scanFileCutoverChunks(file, from, size, kind == "zeek-dhcp" || kind == "zeek-dhcp-binding", chunkLimit)
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	if found && scan.Offset != existing.Offset {
		return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() < before.Size() {
		return zeekCutoverBytes{}, "", errors.New("file source changed during cutover audit")
	}
	entries, err := legacyFileDiscardEntries(ctx, db, kind, sensor, path, fileID, from, scan, cutoff, chunks...)
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	if priorEpoch != "" {
		entries = append(entries, zeekDiscardEntry{LegacyKind: "previous_closed_stream", LegacyReference: priorEpoch, LegacyStatus: "closed_audited", ContentSHA256: priorManifest})
	}
	entries = append(entries, rotationEntries...)
	encoded, err := json.Marshal(struct {
		Epoch, Source, Path, Sensor, FileID, CancelID, ScopeHash string
		Cutoff                                                   time.Time
		Entries                                                  []zeekDiscardEntry
	}{epoch, kind, path, sensor, fileID, cancelID, scopeHash, cutoff.UTC(), entries})
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	sum := sha256.Sum256(encoded)
	manifest := hex.EncodeToString(sum[:])
	if found && existing.ManifestHash != manifest {
		return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_source_cutovers(epoch,source_kind,source_path,sensor_id,file_id,start_offset,parser_version,previous_release,legacy_cutoff_at,legacy_cancel_id,cancel_manifest_sha256,capture_scope_sha256,state)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'prepared') ON CONFLICT DO NOTHING`, epoch, kind, path, sensor, fileID, scan.Offset, parser, previousRelease, cutoff, cancelID, manifest, scopeHash)
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	for start := 0; start < len(entries); start += 500 {
		end := start + 500
		if end > len(entries) {
			end = len(entries)
		}
		payload, marshalErr := json.Marshal(entries[start:end])
		if marshalErr != nil {
			return zeekCutoverBytes{}, "", marshalErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest(epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records,unprocessed_bytes,first_unprocessed_at,last_unprocessed_at)
 SELECT $1,$2,$3,v.legacy_kind,v.legacy_reference,v.legacy_status,v.content_sha256,v.unprocessed_records,v.unprocessed_bytes,v.first_unprocessed_at,v.last_unprocessed_at
 FROM jsonb_to_recordset($4::jsonb) AS v(legacy_kind text,legacy_reference text,legacy_status text,content_sha256 text,unprocessed_records bigint,unprocessed_bytes bigint,first_unprocessed_at timestamptz,last_unprocessed_at timestamptz)
 ON CONFLICT DO NOTHING`, epoch, kind, path, payload)
		if err != nil {
			return zeekCutoverBytes{}, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return zeekCutoverBytes{}, "", err
	}
	cursor := streamlog.SourceCursor{Epoch: epoch, Source: kind, Path: path, FileID: fileID, Offset: scan.Offset, ParserVersion: parser}
	if kind == "zeek-dhcp-binding" && parser == "zeek-dhcp-binding-v2" {
		cursor.KeyScheme, cursor.Generation = "generation-v2", 1
	}
	if kind == "zeek-dhcp-binding" && scan.Offset > 0 {
		tailBytes := int(scan.Offset)
		if tailBytes > streamlog.SourceTailProofBytes {
			tailBytes = streamlog.SourceTailProofBytes
		}
		tail := make([]byte, tailBytes)
		if _, err := file.ReadAt(tail, scan.Offset-int64(tailBytes)); err != nil {
			return zeekCutoverBytes{}, "", err
		}
		sum := sha256.Sum256(tail)
		cursor.TailBytes, cursor.TailSHA256 = tailBytes, hex.EncodeToString(sum[:])
	}
	old, loadErr := journal.LoadSource(cursor.Source, cursor.Path)
	if errors.Is(loadErr, os.ErrNotExist) {
		if err := journal.StartFreshSource(cursor); err != nil {
			return zeekCutoverBytes{}, "", err
		}
	} else if loadErr != nil {
		return zeekCutoverBytes{}, "", loadErr
	} else if old.Epoch != epoch || old.ParserVersion != cursor.ParserVersion || old.KeyScheme != cursor.KeyScheme || old.DiscardedBeforeOffset != scan.Offset || (old.LastSegmentID == "" && (old.FileID != fileID || old.Generation != cursor.Generation)) {
		return zeekCutoverBytes{}, "", streamlog.ErrContentConflict
	}
	result, err := db.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='active' WHERE epoch=$1 AND source_kind=$2 AND source_path=$3 AND state IN ('prepared','active') AND cancel_manifest_sha256=$4`, epoch, kind, path, manifest)
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return zeekCutoverBytes{}, "", err
	}
	if rows != 1 {
		return zeekCutoverBytes{}, "", streamlog.ErrUnconfirmed
	}
	for _, entry := range rotationEntries {
		scan.Records += entry.UnprocessedRecords
		scan.Bytes += entry.UnprocessedBytes
	}
	return scan, manifest, nil
}

func runIngestStreamPrepare(args []string) error {
	fs := flag.NewFlagSet("ingest stream-prepare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered capture sensor")
	path := fs.String("zeek-dhcp", "", "existing Zeek DHCP log")
	bindingPath := fs.String("zeek-dhcp-binding", "", "same-scope Zeek DHCP binding log")
	ttlPath := fs.String("device-signals", "", "existing controlled TTL signal log")
	handshakePath := fs.String("handshake-signals", "", "existing controlled handshake signal log")
	routerProbePath := fs.String("router-probe-signals", "", "existing controlled router probe signal log")
	controlledInterface := fs.String("controlled-interface", "", "operator-verified source interface")
	journalDir := fs.String("journal-dir", "", "durable source journal")
	scopeFile := fs.String("capture-scope-config", os.Getenv("PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG"), "controlled capture scope")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	epoch := fs.String("epoch", "", "fresh source epoch")
	cancelID := fs.String("cancel-id", "", "immutable old-input cancellation identifier")
	previousRelease := fs.String("previous-release", "", "compatible application release")
	cutoffText := fs.String("cutoff-at", "", "fixed RFC3339 old-input cutoff")
	priorEpoch := fs.String("resume-closed-epoch", "", "prior closed stream on this exact file")
	priorManifest := fs.String("prior-retirement-sha256", "", "verified immutable retirement manifest")
	rotationArchive := fs.String("rotation-archive", "", "verified retained file across rotation (Zeek gzip or device .1)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kind, sourcePath, sourceCount := "", "", 0
	for _, item := range []struct{ kind, path string }{{"zeek-dhcp", *path}, {"zeek-dhcp-binding", *bindingPath}, {"device-signals", *ttlPath}, {"device-signals", *handshakePath}, {"device-signals", *routerProbePath}} {
		if item.path != "" {
			kind, sourcePath = item.kind, item.path
			sourceCount++
		}
	}
	if fs.NArg() != 0 || *sensor == "" || sourceCount != 1 || *journalDir == "" || *scopeFile == "" || *postgresDSN == "" || *epoch == "" || *cancelID == "" || *previousRelease == "" || *cutoffText == "" {
		return errors.New("stream-prepare requires source, scope, journal, database and immutable cancellation inputs")
	}
	cutoff, err := time.Parse(time.RFC3339Nano, *cutoffText)
	if err != nil {
		return fmt.Errorf("invalid stream cutoff: %w", err)
	}
	scope, scopeHash, err := loadCaptureScopeWithHash(*scopeFile)
	if err != nil {
		return err
	}
	if scope == nil || scope.SensorID != *sensor || scope.CollectorInstanceID == "" || time.Now().Before(scope.ValidFrom) || !time.Now().Before(scope.ValidUntil) {
		return errors.New("stream-prepare requires a currently valid matching capture scope")
	}
	if *controlledInterface == "" {
		*controlledInterface = scope.InterfaceName
	}
	if *controlledInterface == "" || (scope.InterfaceName != "" && *controlledInterface != scope.InterfaceName) {
		return errors.New("stream-prepare requires an operator-verified matching interface")
	}
	scopeHash = controlledScopeBindingHash(scopeHash, *controlledInterface)
	journal, err := streamlog.Open(*journalDir)
	if err != nil {
		return err
	}
	releaseJournal, err := journal.AcquireSourceLease(kind, sourcePath)
	if err != nil {
		return err
	}
	defer releaseJournal()
	db, err := sql.Open("pgx", *postgresDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	leaseStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: *postgresDSN, SensorID: *sensor})
	if err != nil {
		return err
	}
	defer leaseStore.Close()
	releaseLegacy, err := leaseStore.AcquireIngestSourceLease(ctx, kind, sourcePath)
	if err != nil {
		return err
	}
	defer releaseLegacy()
	scan, manifest, err := prepareControlledFileStreamAfterClosedWithRotation(ctx, db, journal, kind, *sensor, sourcePath, *epoch, *cancelID, *previousRelease, scopeHash, cutoff, *priorEpoch, *priorManifest, *rotationArchive)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"epoch": *epoch, "source": kind, "file": sourcePath, "start_offset": scan.Offset, "discarded_records": scan.Records, "discarded_bytes": scan.Bytes, "manifest_sha256": manifest})
}
