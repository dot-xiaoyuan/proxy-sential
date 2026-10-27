package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

type streamDiscardRow struct {
	LegacyKind         string     `json:"legacy_kind"`
	LegacyReference    string     `json:"legacy_reference"`
	LegacyStatus       string     `json:"legacy_status"`
	ContentSHA256      string     `json:"content_sha256"`
	UnprocessedRecords int64      `json:"unprocessed_records"`
	UnprocessedBytes   int64      `json:"unprocessed_bytes"`
	FirstUnprocessedAt *time.Time `json:"first_unprocessed_at"`
	LastUnprocessedAt  *time.Time `json:"last_unprocessed_at"`
}

var passiveSpoolFilename = regexp.MustCompile(`^[0-9a-f]{32}\.json(?:\.tmp)?$`)

func collectPassiveSpoolRows(dir string) ([]streamDiscardRow, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rows := make([]streamDiscardRow, 0)
	for _, entry := range entries {
		name := entry.Name()
		if !passiveSpoolFilename.MatchString(name) {
			if strings.HasSuffix(name, ".tmp") {
				return nil, fmt.Errorf("unexpected passive spool temporary file %s", name)
			}
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("passive spool entry %s is not a regular file", name)
		}
		path := filepath.Join(dir, name)
		before, err := entry.Info()
		if err != nil {
			return nil, err
		}
		partial := strings.HasSuffix(name, ".tmp")
		if partial && time.Since(before.ModTime()) < time.Minute {
			return nil, fmt.Errorf("in-flight passive spool file %s", name)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(raw) == 0 || len(raw) > 8<<20 {
			return nil, fmt.Errorf("passive spool file %s exceeds audit budget", name)
		}
		after, err := os.Stat(path)
		if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != after.Size() {
			return nil, fmt.Errorf("passive spool file %s changed during audit", name)
		}
		var events []struct {
			Timestamp string `json:"timestamp"`
		}
		parseErr := json.Unmarshal(raw, &events)
		if !partial && (parseErr != nil || len(events) == 0 || len(events) > 2000) {
			return nil, fmt.Errorf("passive spool file %s cannot be audited", name)
		}
		sum := sha256.Sum256(raw)
		row := streamDiscardRow{LegacyKind: "passive_spool", LegacyReference: path, LegacyStatus: "unprocessed", ContentSHA256: hex.EncodeToString(sum[:]), UnprocessedRecords: int64(len(events)), UnprocessedBytes: int64(len(raw))}
		if partial {
			row.LegacyKind, row.LegacyStatus = "passive_spool_partial", "unprocessed_tmp"
			if parseErr != nil || len(events) == 0 || len(events) > 2000 {
				row.LegacyStatus, row.UnprocessedRecords, events = "partial_unknown_count", 0, nil
			}
		}
		for _, event := range events {
			at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
			if err != nil {
				continue
			}
			at = at.UTC()
			if row.FirstUnprocessedAt == nil || at.Before(*row.FirstUnprocessedAt) {
				copy := at
				row.FirstUnprocessedAt = &copy
			}
			if row.LastUnprocessedAt == nil || at.After(*row.LastUnprocessedAt) {
				copy := at
				row.LastUnprocessedAt = &copy
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].LegacyReference < rows[j].LegacyReference })
	return rows, nil
}

func loadCancelledDiscoveryRows(ctx context.Context, db *sql.DB, cutoff time.Time) ([]streamDiscardRow, error) {
	// A prior cancellation can predate this source cutover. Include every
	// cancelled batch, not only the last cancellation ID, so the fresh-start
	// manifest describes the entire abandoned discovery history.
	rows, err := db.QueryContext(ctx, `SELECT m.cancel_id,m.batch_id,m.original_lane,m.remaining_events,m.original_created_at,b.checksum,m.cutoff_at
 FROM discovery_cancel_manifest m JOIN ingest_batches b USING(batch_id)
 JOIN discovery_batch_work w USING(batch_id)
 WHERE m.cutoff_at<=$1 AND w.lane='cancelled' ORDER BY m.batch_id`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []streamDiscardRow{}
	for rows.Next() {
		var row streamDiscardRow
		var recordedID, originalLane string
		var created, recordedCutoff time.Time
		if err = rows.Scan(&recordedID, &row.LegacyReference, &originalLane, &row.UnprocessedRecords, &created, &row.ContentSHA256, &recordedCutoff); err != nil {
			return nil, err
		}
		row.LegacyKind = "discovery_batch_work"
		row.LegacyStatus = "cancelled:" + recordedID + ":" + originalLane
		row.FirstUnprocessedAt = &created
		out = append(out, row)
	}
	return out, rows.Err()
}

func preparePassiveStreamCutover(ctx context.Context, db *sql.DB, journal *streamlog.Journal, source discovery.Source, scope *normalized.CaptureScope, spoolDir, epoch, cancelID, previousRelease string, cutoff time.Time) (string, error) {
	if db == nil || journal == nil || scope == nil || epoch == "" || len(epoch) > 128 || cancelID == "" || previousRelease == "" || cutoff.IsZero() || cutoff.After(time.Now()) ||
		source.Node != scope.SensorID || source.Site != scope.CampusID || source.Domain != scope.AccessDomain || source.Address != scope.InterfaceName || scope.CollectorInstanceID == "" ||
		time.Now().Before(scope.ValidFrom) || !time.Now().Before(scope.ValidUntil) {
		return "", errors.New("invalid passive stream cutover parameters")
	}
	var outstanding int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_batch_work WHERE lane IN ('realtime','backfill','rules') AND NOT completed`).Scan(&outstanding); err != nil {
		return "", err
	}
	if outstanding != 0 {
		return "", fmt.Errorf("%d old discovery batches remain uncompleted and uncancelled", outstanding)
	}
	cancelled, err := loadCancelledDiscoveryRows(ctx, db, cutoff)
	if err != nil {
		return "", err
	}
	spool, err := collectPassiveSpoolRows(spoolDir)
	if err != nil {
		return "", err
	}
	rows := append(cancelled, spool...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].LegacyKind != rows[j].LegacyKind {
			return rows[i].LegacyKind < rows[j].LegacyKind
		}
		return rows[i].LegacyReference < rows[j].LegacyReference
	})
	path := discovery.PassiveStreamSourcePath(source)
	encoded, err := json.Marshal(struct {
		Epoch, Source, Path, CancelID string
		Cutoff                        time.Time
		Rows                          []streamDiscardRow
	}{epoch, "passive-discovery", path, cancelID, cutoff.UTC(), rows})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	manifestHash := hex.EncodeToString(sum[:])
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_source_cutovers(epoch,source_kind,source_path,sensor_id,file_id,start_offset,parser_version,previous_release,legacy_cutoff_at,legacy_cancel_id,cancel_manifest_sha256,state)
 VALUES($1,'passive-discovery',$2,$3,$4,0,$5,$6,$7,$8,$9,'prepared') ON CONFLICT DO NOTHING`, epoch, path, source.Node, scope.CollectorInstanceID, discovery.PassiveStreamParserVersion, previousRelease, cutoff, cancelID, manifestHash)
	if err != nil {
		return "", err
	}
	var oldSensor, oldFile, oldParser, oldRelease, oldCancel, oldHash, state string
	var oldStart int64
	var oldCutoff time.Time
	err = tx.QueryRowContext(ctx, `SELECT sensor_id,file_id,start_offset,parser_version,previous_release,legacy_cutoff_at,legacy_cancel_id,cancel_manifest_sha256,state
 FROM stream_source_cutovers WHERE epoch=$1 AND source_kind='passive-discovery' AND source_path=$2 FOR UPDATE`, epoch, path).
		Scan(&oldSensor, &oldFile, &oldStart, &oldParser, &oldRelease, &oldCutoff, &oldCancel, &oldHash, &state)
	if err != nil {
		return "", err
	}
	if oldSensor != source.Node || oldFile != scope.CollectorInstanceID || oldStart != 0 || oldParser != discovery.PassiveStreamParserVersion || oldRelease != previousRelease ||
		!oldCutoff.Equal(cutoff) || oldCancel != cancelID || oldHash != manifestHash || (state != "prepared" && state != "active") {
		return "", streamlog.ErrContentConflict
	}
	for start := 0; start < len(rows); start += 500 {
		end := start + 500
		if end > len(rows) {
			end = len(rows)
		}
		payload, err := json.Marshal(rows[start:end])
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest(epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records,unprocessed_bytes,first_unprocessed_at,last_unprocessed_at)
 SELECT $1,'passive-discovery',$2,v.legacy_kind,v.legacy_reference,v.legacy_status,v.content_sha256,v.unprocessed_records,v.unprocessed_bytes,v.first_unprocessed_at,v.last_unprocessed_at
 FROM jsonb_to_recordset($3::jsonb) AS v(legacy_kind text,legacy_reference text,legacy_status text,content_sha256 text,unprocessed_records bigint,unprocessed_bytes bigint,first_unprocessed_at timestamptz,last_unprocessed_at timestamptz)
 ON CONFLICT DO NOTHING`, epoch, path, payload)
		if err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	cursor := streamlog.SourceCursor{Epoch: epoch, Source: "passive-discovery", Path: path, FileID: scope.CollectorInstanceID, Offset: 0, ParserVersion: discovery.PassiveStreamParserVersion}
	existing, loadErr := journal.LoadSource(cursor.Source, cursor.Path)
	if errors.Is(loadErr, os.ErrNotExist) {
		if err := journal.StartFreshSource(cursor); err != nil {
			return "", err
		}
	} else if loadErr != nil {
		return "", loadErr
	} else if existing.Epoch != epoch || existing.ParserVersion != cursor.ParserVersion || existing.DiscardedBeforeOffset != 0 ||
		(existing.LastSegmentID == "" && existing.FileID != cursor.FileID) {
		return "", streamlog.ErrContentConflict
	}
	activated, err := db.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='active' WHERE epoch=$1 AND source_kind='passive-discovery' AND source_path=$2 AND state IN ('prepared','active') AND cancel_manifest_sha256=$3`, epoch, path, manifestHash)
	if err != nil {
		return "", err
	}
	count, err := activated.RowsAffected()
	if err != nil {
		return "", err
	}
	if count != 1 {
		return "", streamlog.ErrUnconfirmed
	}
	return manifestHash, nil
}

func runPassiveStreamPrepare(opts passiveStreamOptions, epoch, cancelID, previousRelease, cutoffText string) error {
	if opts.Interface == "" || opts.Node == "" || opts.Site == "" || opts.Domain == "" || opts.JournalDir == "" || opts.ScopeFile == "" {
		return errors.New("stream preparation requires interface, node, site, domain, journal and scope")
	}
	cutoff, err := time.Parse(time.RFC3339Nano, cutoffText)
	if err != nil {
		return fmt.Errorf("stream cutoff must be RFC3339: %w", err)
	}
	scope, err := normalized.LoadCaptureScope(opts.ScopeFile)
	if err != nil {
		return err
	}
	journal, err := streamlog.Open(opts.JournalDir)
	if err != nil {
		return err
	}
	release, err := journal.AcquireSourceLease("passive-discovery", discovery.PassiveStreamSourcePath(discovery.Source{ID: "passive-" + opts.Node, Address: opts.Interface}))
	if err != nil {
		return err
	}
	defer release()
	db, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(store.PostgresPoolLimit(2))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	source := discovery.Source{ID: "passive-" + opts.Node, Node: opts.Node, Site: opts.Site, Domain: opts.Domain, Address: opts.Interface, ConfigVersion: 1}
	hash, err := preparePassiveStreamCutover(ctx, db, journal, source, scope, opts.Spool, epoch, cancelID, previousRelease, cutoff)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"epoch": epoch, "source_path": discovery.PassiveStreamSourcePath(source), "cancel_manifest_sha256": hash, "state": "active"})
}
