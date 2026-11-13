package main

import (
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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

// This is an exceptional transfer of still-unfinished flow segments after a
// legacy inode was reused. It never mutates or acknowledges the old journal.
// The new epoch reads the exact protected source bytes again with a birth ID.
type flowReplayPending struct {
	ID            string `json:"id"`
	Start         int64  `json:"start"`
	End           int64  `json:"end"`
	Events        int    `json:"events"`
	SourceSHA256  string `json:"source_sha256"`
	SegmentSHA256 string `json:"segment_sha256"`
}

type flowReplayPlan struct {
	OldEpoch          string              `json:"old_epoch"`
	NewEpoch          string              `json:"new_epoch"`
	SensorID          string              `json:"sensor_id"`
	SourcePath        string              `json:"source_path"`
	OldJournal        string              `json:"old_journal"`
	NewJournal        string              `json:"new_journal"`
	RecoveryFile      string              `json:"recovery_file"`
	ScopeSHA256       string              `json:"scope_sha256"`
	PreviousRelease   string              `json:"previous_release"`
	ReplayID          string              `json:"replay_id"`
	OldFileID         string              `json:"old_file_id"`
	BirthFileID       string              `json:"birth_file_id"`
	OldCursorOffset   int64               `json:"old_cursor_offset"`
	ReplayStart       int64               `json:"replay_start"`
	ReplayFileEnd     int64               `json:"replay_file_end"`
	ReplayFileSHA256  string              `json:"replay_file_sha256"`
	ReplayRangeSHA256 string              `json:"replay_range_sha256"`
	ReplayRecords     int64               `json:"replay_records"`
	PendingEvents     int                 `json:"pending_events"`
	Pending           []flowReplayPending `json:"pending"`
	PendingSHA256     string              `json:"pending_manifest_sha256"`
	PlanSHA256        string              `json:"plan_sha256"`
}

func inspectFlowReplay(j *streamlog.Journal, sourcePath, recoveryFile, oldEpoch, newEpoch,
	newJournal, sensorID, scopeSHA256, previousRelease, replayID string) (flowReplayPlan, error) {
	var plan flowReplayPlan
	if j == nil || filepath.Base(sourcePath) != "flow-syn.jsonl" ||
		filepath.Base(recoveryFile) != "flow-syn.jsonl.1" || oldEpoch == "" || newEpoch == "" || oldEpoch == newEpoch {
		return plan, errors.New("flow replay requires exact source, protected rotation and two distinct epochs")
	}
	cursor, err := j.LoadSource("device-signals", sourcePath)
	if err != nil {
		return plan, err
	}
	if cursor.Epoch != oldEpoch || cursor.Source != "device-signals" || cursor.Path != sourcePath ||
		cursor.ParserVersion != deviceSignalStreamParser || cursor.KeyScheme != "" ||
		cursor.FileID == "" || strings.Contains(cursor.FileID, ":birth:") || cursor.Offset <= 0 ||
		cursor.TailBytes <= 0 || cursor.TailBytes > streamlog.SourceTailProofBytes ||
		len(cursor.TailSHA256) != 64 {
		return plan, errors.New("old flow cursor is not a sealed legacy file position")
	}
	file, err := os.Open(recoveryFile)
	if err != nil {
		return plan, err
	}
	defer file.Close()
	linkInfo, err := os.Lstat(recoveryFile)
	if err != nil || !linkInfo.Mode().IsRegular() {
		return plan, errors.New("protected flow recovery path must be a regular hard link")
	}
	before, err := file.Stat()
	if err != nil || !os.SameFile(linkInfo, before) || before.Size() <= cursor.Offset {
		return plan, errors.New("protected flow rotation is missing unread bytes")
	}
	rotation, err := os.Stat(sourcePath + ".1")
	if err != nil || !os.SameFile(before, rotation) {
		return plan, errors.New("protected flow rotation is no longer the immediate predecessor")
	}
	live, err := os.Stat(sourcePath)
	if err != nil || !live.Mode().IsRegular() || os.SameFile(before, live) {
		return plan, errors.New("new live flow source is absent or aliases the replay file")
	}
	birthID := realtime.FileIdentityBirthAt(sourcePath, recoveryFile, before)
	oldID, _, hasBirth := strings.Cut(birthID, ":birth:")
	if birthID == "" || !hasBirth || birthID == oldID {
		return plan, errors.New("protected flow rotation has no distinct birth identity")
	}
	if oldID != cursor.FileID {
		return plan, errors.New("protected rotation does not match old cursor file identity")
	}
	tail := make([]byte, cursor.TailBytes)
	if _, err = file.ReadAt(tail, cursor.Offset-int64(cursor.TailBytes)); err != nil {
		return plan, err
	}
	tailHash := sha256.Sum256(tail)
	if hex.EncodeToString(tailHash[:]) != cursor.TailSHA256 {
		return plan, errors.New("protected flow rotation does not match committed cursor tail")
	}
	ids, err := j.PendingSegments()
	if err != nil {
		return plan, err
	}
	if len(ids) == 0 || len(ids) > 64 {
		return plan, errors.New("flow replay needs one bounded nonempty pending journal")
	}
	plan = flowReplayPlan{OldEpoch: oldEpoch, NewEpoch: newEpoch, SensorID: sensorID, SourcePath: sourcePath,
		OldJournal: j.Directory(), NewJournal: newJournal, RecoveryFile: recoveryFile,
		ScopeSHA256: scopeSHA256, PreviousRelease: previousRelease, ReplayID: replayID, OldFileID: oldID,
		BirthFileID: birthID, OldCursorOffset: cursor.Offset, ReplayFileEnd: before.Size()}
	for _, id := range ids {
		state, loadErr := j.Load(id)
		if loadErr != nil {
			return flowReplayPlan{}, loadErr
		}
		s := state.Segment
		if !state.Committed || state.Released || s.Quarantined || s.Epoch != oldEpoch ||
			s.Source != "device-signals" || s.SourcePath != sourcePath || s.FileID != oldID ||
			s.ParserVersion != deviceSignalStreamParser || s.KeyScheme != "" ||
			!s.RawIsStandardEvents || s.SourceBackedRaw || s.NeedsProjection || s.RiskFeaturesRequired ||
			len(s.Events) == 0 || len(s.Raw) == 0 || s.EndOffset-s.StartOffset != int64(len(s.Raw)) ||
			state.Acks[streamlog.Archive] == streamlog.Acked || state.Acks[streamlog.Search] == streamlog.Acked {
			return flowReplayPlan{}, fmt.Errorf("pending flow segment %s cannot be safely replayed", id)
		}
		rawHash := sha256.Sum256(s.Raw)
		if hex.EncodeToString(rawHash[:]) != s.RawSHA256 || s.StartOffset < 0 || s.EndOffset > before.Size() {
			return flowReplayPlan{}, fmt.Errorf("pending flow segment %s has invalid source bytes", id)
		}
		actual := make([]byte, len(s.Raw))
		if _, err = file.ReadAt(actual, s.StartOffset); err != nil || !bytes.Equal(actual, s.Raw) {
			return flowReplayPlan{}, fmt.Errorf("pending flow segment %s differs from protected source", id)
		}
		for _, event := range s.Events {
			if event.Source != "flow-syn-sidecar" || event.EventID == "" {
				return flowReplayPlan{}, fmt.Errorf("pending flow segment %s has unexpected event", id)
			}
		}
		plan.Pending = append(plan.Pending, flowReplayPending{ID: id, Start: s.StartOffset, End: s.EndOffset,
			Events: len(s.Events), SourceSHA256: s.RawSHA256, SegmentSHA256: state.ContentSHA256})
		plan.PendingEvents += len(s.Events)
	}
	sort.Slice(plan.Pending, func(i, k int) bool { return plan.Pending[i].Start < plan.Pending[k].Start })
	plan.ReplayStart = plan.Pending[0].Start
	for i, item := range plan.Pending {
		if item.Start >= item.End || (i > 0 && plan.Pending[i-1].End != item.Start) {
			return flowReplayPlan{}, errors.New("unfinished flow segments are not one contiguous source range")
		}
	}
	if plan.Pending[len(plan.Pending)-1].End != cursor.Offset ||
		cursor.LastSegmentID != plan.Pending[len(plan.Pending)-1].ID {
		return flowReplayPlan{}, errors.New("unfinished flow segments do not reach the fixed old cursor")
	}
	scan, err := scanFileCutoverBytes(file, plan.ReplayStart, before.Size(), false)
	if err != nil || scan.Offset != before.Size() || scan.Records < int64(plan.PendingEvents) {
		return flowReplayPlan{}, errors.New("protected flow replay range is not complete newline-delimited input")
	}
	plan.ReplayRangeSHA256, plan.ReplayRecords = scan.SHA256, scan.Records
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return flowReplayPlan{}, err
	}
	full := sha256.New()
	if _, err = io.Copy(full, file); err != nil {
		return flowReplayPlan{}, err
	}
	plan.ReplayFileSHA256 = hex.EncodeToString(full.Sum(nil))
	pendingJSON, err := json.Marshal(plan.Pending)
	if err != nil {
		return flowReplayPlan{}, err
	}
	pendingSHA := sha256.Sum256(pendingJSON)
	plan.PendingSHA256 = hex.EncodeToString(pendingSHA[:])
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return flowReplayPlan{}, errors.New("protected flow replay file changed during audit")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return flowReplayPlan{}, err
	}
	sum := sha256.Sum256(encoded)
	plan.PlanSHA256 = hex.EncodeToString(sum[:])
	return plan, nil
}

func runIngestStreamReplayPrepare(args []string) error {
	fs := flag.NewFlagSet("ingest stream-replay-prepare", flag.ContinueOnError)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered capture sensor")
	source := fs.String("flow-syn-signals", "", "controlled flow source path")
	oldDir := fs.String("old-journal-dir", "", "retained original journal directory")
	newDir := fs.String("new-journal-dir", "", "empty replay journal directory")
	recovery := fs.String("recovery-file", "", "protected old flow rotation hard link")
	oldEpoch := fs.String("old-epoch", "", "existing fixed epoch")
	newEpoch := fs.String("epoch", "", "new birth-aware replay epoch")
	scopeFile := fs.String("capture-scope-config", "", "controlled capture scope")
	interfaceName := fs.String("controlled-interface", "", "verified interface")
	previousRelease := fs.String("previous-release", "", "source release for audit")
	replayID := fs.String("replay-id", "", "immutable operator replay identifier")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	expected := fs.String("expected-plan-sha256", "", "exact plan digest from read-only run")
	apply := fs.Bool("apply", false, "commit audited replay cutover")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *oldDir == "" || *newDir == "" || *recovery == "" ||
		*sensor == "" || *scopeFile == "" || *oldEpoch == "" || *newEpoch == "" ||
		*previousRelease == "" || *replayID == "" || *postgresDSN == "" ||
		!filepath.IsAbs(*source) || !filepath.IsAbs(*oldDir) || !filepath.IsAbs(*newDir) ||
		!filepath.IsAbs(*recovery) || filepath.Clean(*oldDir) == filepath.Clean(*newDir) {
		return errors.New("stream replay needs fixed source, journals, scope, release, identity and database")
	}
	if os.Getenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID") != "true" ||
		filepath.Clean(filepath.Dir(*recovery)) != filepath.Clean(os.Getenv("PROXY_SENTINEL_DEVICE_SIGNAL_RECOVERY_DIR")) {
		return errors.New("stream replay requires birth identities and the protected recovery directory")
	}
	scope, scopeHash, err := loadCaptureScopeWithHash(*scopeFile)
	if err != nil {
		return err
	}
	if scope == nil || scope.SensorID != *sensor || scope.CollectorInstanceID == "" ||
		time.Now().Before(scope.ValidFrom) || !time.Now().Before(scope.ValidUntil) {
		return errors.New("stream replay has no currently valid capture scope")
	}
	if *interfaceName == "" {
		*interfaceName = scope.InterfaceName
	}
	if *interfaceName == "" || scope.InterfaceName != "" && scope.InterfaceName != *interfaceName {
		return errors.New("stream replay has a different controlled interface")
	}
	scopeHash = controlledScopeBindingHash(scopeHash, *interfaceName)
	old, err := streamlog.Open(*oldDir)
	if err != nil {
		return err
	}
	release, err := old.AcquireSourceLease("device-signals", *source)
	if err != nil {
		return err
	}
	defer release()
	plan, err := inspectFlowReplay(old, *source, *recovery, *oldEpoch, *newEpoch,
		*newDir, *sensor, scopeHash, *previousRelease, *replayID)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(plan); err != nil {
		return err
	}
	if !*apply {
		return nil
	}
	if *expected == "" || *expected != plan.PlanSHA256 {
		return errors.New("flow replay plan changed or expected digest is missing")
	}
	return applyFlowReplay(context.Background(), plan, *newDir, *sensor, scopeHash, *previousRelease, *replayID, *postgresDSN)
}

func applyFlowReplay(ctx context.Context, plan flowReplayPlan, newDir, sensor, scopeHash, previousRelease, replayID, dsn string) error {
	if filepath.Clean(newDir) != filepath.Clean(plan.NewJournal) || sensor != plan.SensorID ||
		scopeHash != plan.ScopeSHA256 || previousRelease != plan.PreviousRelease || replayID != plan.ReplayID {
		return errors.New("flow replay apply differs from the sealed plan")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(store.PostgresPoolLimit(2))
	leaseStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn, SensorID: sensor})
	if err != nil {
		return err
	}
	defer leaseStore.Close()
	release, err := leaseStore.AcquireIngestSourceLease(ctx, "device-signals", plan.SourcePath)
	if err != nil {
		return err
	}
	defer release()
	newJournal, err := streamlog.Open(newDir)
	if err != nil {
		return err
	}
	oldDirInfo, oldErr := os.Stat(plan.OldJournal)
	newDirInfo, newErr := os.Stat(newDir)
	if oldErr != nil || newErr != nil || os.SameFile(oldDirInfo, newDirInfo) {
		return errors.New("replay journal must be distinct from the retained old journal")
	}
	newPending, err := newJournal.PendingSegments()
	if err != nil || len(newPending) != 0 {
		return errors.New("new replay journal already has unfinished segments")
	}
	releaseNew, err := newJournal.AcquireSourceLease("device-signals", plan.SourcePath)
	if err != nil {
		return err
	}
	defer releaseNew()
	file, err := os.Open(plan.RecoveryFile)
	if err != nil {
		return err
	}
	defer file.Close()
	cursor, err := preparedStreamCursor(file, plan.NewEpoch, "device-signals", plan.SourcePath,
		plan.BirthFileID, deviceSignalStreamParser, plan.ReplayStart)
	if err != nil {
		return err
	}
	if err := newJournal.StartFreshSource(cursor); err != nil {
		return err
	}
	// The durable new cursor is dormant until this single transaction closes
	// the old cutover, seals the audit, and activates the new one. A crash before
	// commit leaves the old cutover active and this exact cursor retryable.
	return recordFlowReplay(ctx, db, plan, sensor, scopeHash, previousRelease, replayID, newDir)
}

func recordFlowReplay(ctx context.Context, db *sql.DB, plan flowReplayPlan, sensor, scopeHash, previousRelease, replayID, newDir string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldState, oldSensor string
	if err := tx.QueryRowContext(ctx, `SELECT state,sensor_id FROM stream_source_cutovers
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 FOR UPDATE`, plan.OldEpoch, plan.SourcePath).
		Scan(&oldState, &oldSensor); err != nil {
		return err
	}
	if oldSensor != sensor || oldState != "active" && oldState != "closed" {
		return errors.New("old flow source cutover is not owned by this replay")
	}
	var existingPlan, existingState string
	err = tx.QueryRowContext(ctx, `SELECT r.plan_sha256,c.state FROM stream_source_replays r
 JOIN stream_source_cutovers c ON c.epoch=r.new_epoch AND c.source_kind=r.source_kind AND c.source_path=r.source_path
 WHERE r.new_epoch=$1 AND r.source_kind='device-signals' AND r.source_path=$2`, plan.NewEpoch, plan.SourcePath).
		Scan(&existingPlan, &existingState)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if existingPlan != plan.PlanSHA256 || oldState != "closed" || existingState != "active" {
			return errors.New("existing flow replay cutover differs from the fixed plan")
		}
		return tx.Commit()
	}
	if oldState != "active" {
		return errors.New("old flow source already closed without this replay")
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM stream_source_cutovers
 WHERE source_kind='device-signals' AND source_path=$1 AND state='active'`, plan.SourcePath).Scan(&active); err != nil || active != 1 {
		return errors.New("another flow epoch owns the source")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='closed'
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 AND state='active'`, plan.OldEpoch, plan.SourcePath); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO stream_source_cutovers
 (epoch,source_kind,source_path,sensor_id,file_id,start_offset,parser_version,previous_release,
 legacy_cutoff_at,legacy_cancel_id,cancel_manifest_sha256,capture_scope_sha256,state,cutover_mode)
 VALUES($1,'device-signals',$2,$3,$4,$5,$6,$7,statement_timestamp(),$8,$9,$10,'active','verified_replay')`,
		plan.NewEpoch, plan.SourcePath, sensor, plan.BirthFileID, plan.ReplayStart,
		deviceSignalStreamParser, previousRelease, replayID, plan.PlanSHA256, scopeHash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO stream_source_replays
	 (new_epoch,source_kind,source_path,old_epoch,old_journal_dir,new_journal_dir,recovery_file,old_file_id,old_cursor_offset,
 replay_file_id,replay_start_offset,replay_file_end_offset,replay_file_sha256,replay_range_sha256,
 old_pending_manifest_sha256,plan_sha256,replay_records,pending_segments,pending_events)
 VALUES($1,'device-signals',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		plan.NewEpoch, plan.SourcePath, plan.OldEpoch, plan.OldJournal, newDir, plan.RecoveryFile, plan.OldFileID,
		plan.OldCursorOffset, plan.BirthFileID, plan.ReplayStart, plan.ReplayFileEnd,
		plan.ReplayFileSHA256, plan.ReplayRangeSHA256, plan.PendingSHA256, plan.PlanSHA256,
		plan.ReplayRecords, len(plan.Pending), plan.PendingEvents); err != nil {
		return err
	}
	for _, item := range plan.Pending {
		if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest
 (epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records,unprocessed_bytes)
 VALUES($1,'device-signals',$2,'stream_replay_pending_segment',$3,'superseded_pending_replay',$4,$5,$6)`,
			plan.NewEpoch, plan.SourcePath, item.ID, item.SegmentSHA256, item.Events, item.End-item.Start); err != nil {
			return err
		}
	}
	return tx.Commit()
}
