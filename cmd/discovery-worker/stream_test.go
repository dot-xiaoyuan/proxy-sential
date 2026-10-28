package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

type passiveBudgetWriter struct {
	store.StreamLaneWriter
	remaining time.Duration
	deadline  bool
}

type replayFinalizerWriter struct {
	passiveBudgetWriter
	fail bool
}

func notifyAllLanes(queue chan passiveFinalizerSignal, id string) {
	for _, lane := range []streamlog.Lane{streamlog.Archive, streamlog.Search, streamlog.Projection} {
		queue <- passiveFinalizerSignal{id: id, lane: lane}
	}
}

func (w *replayFinalizerWriter) FinalizeSegment(context.Context, string, streamlog.Segment) error {
	if w.fail {
		return streamlog.ErrUnconfirmed
	}
	return nil
}

func TestPassiveFinalizerRecoversAcknowledgedSegmentAfterInterruptedRetry(t *testing.T) {
	dir := t.TempDir()
	j, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", SourcePath: "packet://bond0/passive-node", FileID: "boot", PreviousFileID: "boot", StartOffset: 0, EndOffset: 1, ParserVersion: discovery.PassiveStreamParserVersion,
		NeedsProjection: true, Events: []normalized.Event{{EventID: "event", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Type: "discovery"}}}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: s.Epoch, Source: s.Source, Path: s.SourcePath, FileID: s.FileID, ParserVersion: s.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(s.Source, s.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	for _, lane := range []streamlog.Lane{streamlog.Archive, streamlog.Search, streamlog.Projection} {
		if err := j.BeginAttempt(id, lane); err != nil {
			t.Fatal(err)
		}
		if err := j.Ack(id, lane); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	queue := make(chan passiveFinalizerSignal, 3)
	notifyAllLanes(queue, id)
	called := make(chan error, 1)
	done := make(chan error, 1)
	p := streamlog.Processor{Journal: j, Writer: &replayFinalizerWriter{fail: true}}
	go func() {
		done <- runPassiveFinalizer(ctx, queue, func(ctx context.Context, id string) error {
			err := p.FinalizeAfterLanes(ctx, id)
			called <- err
			return err
		}, time.Hour, 2)
	}()
	if err := <-called; !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("missing receipt not retained: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	j, err = streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || state.Released || state.Acks[streamlog.Projection] != streamlog.Acked {
		t.Fatalf("restart lost unfinalized segment: %+v %v", state, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	queue = make(chan passiveFinalizerSignal, 3)
	notifyAllLanes(queue, id)
	p = streamlog.Processor{Journal: j, Writer: &replayFinalizerWriter{}}
	go func() {
		done <- runPassiveFinalizer(ctx, queue, func(ctx context.Context, id string) error {
			err := p.FinalizeAfterLanes(ctx, id)
			called <- err
			return err
		}, time.Second, 2)
	}()
	if err := <-called; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := j.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed segment was not released: %v", err)
	}
}

func TestPassiveFinalizerRetriesMissingReceiptWithoutBlockingOtherSegments(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan passiveFinalizerSignal, 6)
	notifyAllLanes(queue, "missing")
	notifyAllLanes(queue, "healthy")
	calls := make(chan string, 4)
	missingAttempts := 0
	done := make(chan error, 1)
	go func() {
		done <- runPassiveFinalizer(ctx, queue, func(_ context.Context, id string) error {
			calls <- id
			if id == "missing" {
				missingAttempts++
				if missingAttempts == 1 {
					return streamlog.ErrUnconfirmed
				}
			}
			return nil
		}, 100*time.Millisecond, 4)
	}()
	for i, want := range []string{"missing", "healthy", "missing"} {
		select {
		case got := <-calls:
			if got != want {
				t.Fatalf("call %d: got %q, want %q", i, got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("finalization stalled")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPassiveFinalizerWaitsForAllLaneNotifications(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan passiveFinalizerSignal, 4)
	calls := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- runPassiveFinalizer(ctx, queue, func(_ context.Context, id string) error { calls <- id; return nil }, time.Second, 2)
	}()
	queue <- passiveFinalizerSignal{id: "segment", lane: streamlog.Archive}
	queue <- passiveFinalizerSignal{id: "segment", lane: streamlog.Archive}
	queue <- passiveFinalizerSignal{id: "segment", lane: streamlog.Search}
	select {
	case <-calls:
		t.Fatal("finalized before the third lane notification")
	case <-time.After(40 * time.Millisecond):
	}
	queue <- passiveFinalizerSignal{id: "segment", lane: streamlog.Projection}
	select {
	case got := <-calls:
		if got != "segment" {
			t.Fatalf("unexpected segment %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("fully acknowledged segment was not finalized")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPassiveFinalizerBackpressuresAtRetryLimitWithoutDropping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan passiveFinalizerSignal, 6)
	notifyAllLanes(queue, "first")
	notifyAllLanes(queue, "second")
	calls := make(chan string, 3)
	attempts := 0
	done := make(chan error, 1)
	go func() {
		done <- runPassiveFinalizer(ctx, queue, func(_ context.Context, id string) error {
			calls <- id
			if id == "first" {
				attempts++
				if attempts == 1 {
					return streamlog.ErrUnconfirmed
				}
			}
			return nil
		}, 50*time.Millisecond, 1)
	}()
	for _, want := range []string{"first", "first", "second"} {
		select {
		case got := <-calls:
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("retry or queued segment lost")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPassiveFinalizerPropagatesContentConflict(t *testing.T) {
	queue := make(chan passiveFinalizerSignal, 3)
	notifyAllLanes(queue, "conflict")
	err := runPassiveFinalizer(context.Background(), queue, func(context.Context, string) error {
		return streamlog.ErrContentConflict
	}, time.Second, 2)
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("content conflict was hidden: %v", err)
	}
}

func (*passiveBudgetWriter) Preflight(streamlog.Lane, streamlog.Segment) error {
	// Local validation and durable journal preparation precede the RPC.
	time.Sleep(80 * time.Millisecond)
	return nil
}

func (w *passiveBudgetWriter) WriteBody(ctx context.Context, _ string, _ streamlog.Segment) error {
	deadline, ok := ctx.Deadline()
	w.remaining, w.deadline = time.Until(deadline), ok
	return ctx.Err()
}

func TestPassiveStreamSinkRetainsBudgetAfterLocalPreparation(t *testing.T) {
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", SourcePath: "packet://bond0/passive-node", FileID: "boot", PreviousFileID: "boot", StartOffset: 0, EndOffset: 1, ParserVersion: discovery.PassiveStreamParserVersion,
		Events: []normalized.Event{{EventID: "event", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Type: "discovery"}}}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: s.Epoch, Source: s.Source, Path: s.SourcePath, FileID: s.FileID, ParserVersion: s.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(s.Source, s.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	w := &passiveBudgetWriter{}
	p := passiveStreamProcessor(j, w)
	if p.SinkTimeout != 3*time.Second || p.ProjectionRetryTimeout != 8*time.Second {
		t.Fatalf("unexpected passive budgets: first=%s projection_retry=%s", p.SinkTimeout, p.ProjectionRetryTimeout)
	}
	if err := p.DrainLane(context.Background(), id, streamlog.Archive); err != nil {
		t.Fatal(err)
	}
	if !w.deadline || w.remaining < 2950*time.Millisecond || w.remaining > 3*time.Second {
		t.Fatalf("RPC must receive its own bounded 3-second budget after local preparation: deadline=%t remaining=%s", w.deadline, w.remaining)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[streamlog.Archive] != streamlog.Acked {
		t.Fatalf("confirmed archive did not retain its acknowledgement: %+v %v", state.Acks, err)
	}
}

func TestVerifyPassiveStreamCutoverRequiresAuditedFreshStart(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cursor := streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: "packet://bond0/passive-node", FileID: "boot-a", Offset: 100, DiscardedBeforeOffset: 0, ParserVersion: "passive-frame-v1", LastSegmentID: "segment-one"}
	mock.ExpectQuery("FROM stream_source_cutovers").WithArgs("fresh-1", "passive-discovery", cursor.Path).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "cancel_manifest_sha256"}).AddRow("node", "boot-a", int64(0), "passive-frame-v1", strings.Repeat("a", 64)))
	if err := verifyPassiveStreamCutover(context.Background(), db, cursor, "node"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePassiveStreamCutoverActivatesOnlyAfterLedgerAndCursor(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spool := t.TempDir()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	source := discovery.Source{ID: "passive-node", Node: "node", Site: "site", Domain: "domain", Address: "bond0"}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "node", CollectorInstanceID: "boot", CampusID: "site", AccessDomain: "domain", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := discovery.PassiveStreamSourcePath(source)
	encoded, _ := json.Marshal(struct {
		Epoch, Source, Path, CancelID string
		Cutoff                        time.Time
		Rows                          []streamDiscardRow
	}{"fresh-1", "passive-discovery", path, "cancel-1", at, []streamDiscardRow{}})
	sum := sha256.Sum256(encoded)
	hash := hex.EncodeToString(sum[:])
	mock.ExpectQuery("SELECT count\\(\\*\\) FROM discovery_batch_work").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(0)))
	mock.ExpectQuery("FROM discovery_cancel_manifest m JOIN ingest_batches b").WithArgs(at).WillReturnRows(sqlmock.NewRows([]string{"cancel_id", "batch_id", "original_lane", "remaining_events", "original_created_at", "checksum", "cutoff_at"}))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_source_cutovers").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM stream_source_cutovers WHERE epoch=\\$1").WithArgs("fresh-1", path).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "previous_release", "legacy_cutoff_at", "legacy_cancel_id", "cancel_manifest_sha256", "state"}).AddRow("node", "boot", int64(0), "passive-frame-v1", "compatible-a", at, "cancel-1", hash, "prepared"))
	mock.ExpectCommit()
	mock.ExpectExec("UPDATE stream_source_cutovers SET state='active'").WithArgs("fresh-1", path, hash).WillReturnResult(sqlmock.NewResult(0, 1))
	got, err := preparePassiveStreamCutover(context.Background(), db, j, source, scope, spool, "fresh-1", "cancel-1", "compatible-a", at)
	if err != nil || got != hash {
		t.Fatalf("cutover not activated: %s %v", got, err)
	}
	cursor, err := j.LoadSource("passive-discovery", path)
	if err != nil || cursor.Epoch != "fresh-1" || cursor.Offset != 0 {
		t.Fatalf("fresh source cursor missing: %+v %v", cursor, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCollectPassiveSpoolRowsAuditsUnprocessedOriginals(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("a", 32) + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(`[{"event_id":"old","timestamp":"2026-10-24T10:00:00Z"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := collectPassiveSpoolRows(dir)
	if err != nil || len(rows) != 1 || rows[0].UnprocessedRecords != 1 || rows[0].ContentSHA256 == "" || rows[0].LegacyStatus != "unprocessed" {
		t.Fatalf("spool audit: %+v %v", rows, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".tmp"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := collectPassiveSpoolRows(dir); err == nil {
		t.Fatal("in-flight spool file silently ignored")
	}
	stale := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(filepath.Join(dir, name+".tmp"), stale, stale); err != nil {
		t.Fatal(err)
	}
	rows, err = collectPassiveSpoolRows(dir)
	if err != nil || len(rows) != 2 || rows[1].LegacyStatus != "partial_unknown_count" || rows[1].UnprocessedRecords != 0 || rows[1].UnprocessedBytes == 0 || rows[1].ContentSHA256 == "" {
		t.Fatalf("stale partial spool bytes were not audited: %+v %v", rows, err)
	}
}

func TestLoadCancelledDiscoveryRowsIncludesEarlierCancellation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Truncate(time.Second)
	earlier := cutoff.Add(-time.Hour)
	mock.ExpectQuery("FROM discovery_cancel_manifest m JOIN ingest_batches b").WithArgs(cutoff).WillReturnRows(
		sqlmock.NewRows([]string{"cancel_id", "batch_id", "original_lane", "remaining_events", "original_created_at", "checksum", "cutoff_at"}).
			AddRow("older-cancel", "batch-1", "realtime", 17, earlier, strings.Repeat("a", 64), earlier).
			AddRow("new-cancel", "batch-2", "backfill", 4, cutoff, strings.Repeat("b", 64), cutoff))
	rows, err := loadCancelledDiscoveryRows(context.Background(), db, cutoff)
	if err != nil || len(rows) != 2 || rows[0].LegacyStatus != "cancelled:older-cancel:realtime" || rows[0].UnprocessedRecords != 17 || rows[1].LegacyStatus != "cancelled:new-cancel:backfill" {
		t.Fatalf("cancelled history missing from fresh cutover: %+v %v", rows, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPassiveStreamCutoverRejectsMissingManifest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cursor := streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: "packet://bond0/passive-node", FileID: "boot-a", Offset: 0, DiscardedBeforeOffset: 0, ParserVersion: "passive-frame-v1"}
	mock.ExpectQuery("FROM stream_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "cancel_manifest_sha256"}).AddRow("node", "boot-a", int64(0), "passive-frame-v1", ""))
	if err := verifyPassiveStreamCutover(context.Background(), db, cursor, "node"); err == nil {
		t.Fatal("unaudited cutover accepted")
	}
}

func TestPreparePassiveStreamCutoverRejectsExpiredScopeBeforeAuditing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := discovery.Source{ID: "passive-node", Node: "node", Site: "site", Domain: "domain", Address: "bond0"}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "node", CollectorInstanceID: "boot", CampusID: "site", AccessDomain: "domain", InterfaceName: "bond0", ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now.Add(-time.Hour)}
	if _, err := preparePassiveStreamCutover(context.Background(), db, j, source, scope, t.TempDir(), "fresh-1", "cancel-1", "compatible-a", now.Add(-time.Hour)); err == nil {
		t.Fatal("expired capture scope activated fresh source")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
