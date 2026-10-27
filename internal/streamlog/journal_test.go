package streamlog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestSourceBackedSegmentRecoversAttemptAndSourceCursor(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("verified Zeek source bytes\n")
	segment := testSegment()
	segment.Source = "zeek-dhcp-binding"
	segment.Raw = raw
	segment.EndOffset = segment.StartOffset + int64(len(raw))
	segment.SourceBackedRaw = true
	sum := sha256.Sum256(raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	j.SetRawResolver(func(Segment) ([]byte, error) { return append([]byte(nil), raw...), nil })
	if err := j.StartFreshSource(SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.FileID, Offset: segment.StartOffset, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	// Crash after the one durable descriptor and before the cursor write.
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	j.SetRawResolver(func(Segment) ([]byte, error) { return append([]byte(nil), raw...), nil })
	ids, err := j.RecoverSource(segment.Source, segment.SourcePath)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("descriptor not recovered: %v %v", ids, err)
	}
	cursor, err := j.LoadSource(segment.Source, segment.SourcePath)
	if err != nil || cursor.Offset != segment.EndOffset || cursor.TailBytes != len(raw) {
		t.Fatalf("recovered cursor lacks source proof: %+v %v", cursor, err)
	}
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := j.AbortUnsentAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	j.SetRawResolver(func(Segment) ([]byte, error) { return append([]byte(nil), raw...), nil })
	state, err := j.Load(id)
	if err != nil || state.Acks[Archive] != Pending {
		t.Fatalf("unsent source-backed attempt survived restart: %+v %v", state.Acks, err)
	}
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	j.SetRawResolver(func(Segment) ([]byte, error) { return append([]byte(nil), raw...), nil })
	state, err = j.Load(id)
	if err != nil || state.Acks[Archive] != Attempted || string(state.Segment.Raw) != string(raw) {
		t.Fatalf("attempt or source bytes lost across crash: %+v %v", state, err)
	}
	bad := append([]byte(nil), raw...)
	bad[0] ^= 1
	j.SetRawResolver(func(Segment) ([]byte, error) { return bad, nil })
	if _, err := j.Load(id); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("tampered source bytes accepted: %v", err)
	}
}

func testSegment() Segment {
	return Segment{
		Epoch: "fresh-20261024", Source: "zeek-dhcp", SourcePath: "/logs/dhcp.log", FileID: "device-1",
		PreviousFileID: "device-1", PreviousOffset: 12,
		StartOffset: 12, EndOffset: 42, ParserVersion: "zeek-v1",
		Events:          []normalized.Event{{EventID: "event-1", Timestamp: "2026-10-24T01:00:00Z", Source: "zeek", Type: "discovery", Subject: map[string]any{"ip": "192.0.2.4"}}},
		NeedsProjection: true,
	}
}

func appendCommitted(t *testing.T, j *Journal, segment Segment) string {
	t.Helper()
	if err := j.StartFreshSource(SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestJournalPersistsIndependentAcksAndReleasesOnlyAfterAll(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	id := appendCommitted(t, j, segment)
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Acks[Archive] != Attempted || state.Acks[Search] != Pending || state.Acks[Projection] != Pending {
		t.Fatalf("lost independent state: %+v", state.Acks)
	}
	if err := j.Ack(id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(id, Search); err != nil {
		t.Fatal(err)
	}
	if err := j.Release(id); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("released unprojected segment: %v", err)
	}
	if err := j.Ack(id, Projection); err != nil {
		t.Fatal(err)
	}
	if err := j.Release(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".segment")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("body still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed state still exists: %v", err)
	}
	ids, err := j.PendingSegments()
	if err != nil || len(ids) != 0 {
		t.Fatalf("completed segment appeared pending: %v %v", ids, err)
	}
}

func TestJournalSealsEmptyAckLogWithSourceCursor(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	if err := j.StartFreshSource(SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(j.path(id, ".acklog")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("capture wrote an empty acknowledgement log: %v", err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(j.path(id, ".acklog"))
	if err != nil || info.Size() != 0 {
		t.Fatalf("committed cursor did not seal an empty acknowledgement log: %+v %v", info, err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Committed || !state.AckLog || !state.AckLogSealed || state.Acks[Archive] != Pending {
		t.Fatalf("committed segment cannot recover before its first sink attempt: %+v %v", state, err)
	}
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err = j.Load(id)
	if err != nil || state.Acks[Archive] != Attempted || state.Acks[Search] != Pending {
		t.Fatalf("first durable sink attempt not recovered: %+v %v", state, err)
	}
}

func TestJournalAckLogSurvivesRestartAndIgnoresTornTail(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".acklog")); err != nil {
		t.Fatalf("first attempt lacks its durable ack log: %v", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, id+".acklog"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("incomplete-record"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[Archive] != Attempted {
		t.Fatalf("durable attempt lost behind torn tail: %+v %v", state.Acks, err)
	}
	if err := j.Ack(id, Archive); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err = j.Load(id)
	if err != nil || state.Acks[Archive] != Acked {
		t.Fatalf("ack after torn tail was not recovered: %+v %v", state.Acks, err)
	}
}

func TestJournalContinuesLegacyStateFileWithoutAckLog(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, j, testSegment())
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	state.AckLog = false
	if err := os.Remove(j.path(id, ".acklog")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := atomicJSON(j.path(id, ".state"), stateWithoutEvents(state)); err != nil {
		t.Fatal(err)
	}
	if err := j.BeginAttempt(id, Search); err != nil {
		t.Fatal(err)
	}
	j, err = Open(j.dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err = j.Load(id)
	if err != nil || state.Acks[Search] != Attempted || state.AckLog {
		t.Fatalf("old acknowledgement format was not recovered: %+v %v", state, err)
	}
}

func TestJournalRejectsSameSourcePositionWithDifferentContent(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	id := appendCommitted(t, j, segment)
	if same, err := j.Append(segment); err != nil || same != id {
		t.Fatalf("idempotent append: %s %v", same, err)
	}
	segment.Events[0].Subject["ip"] = "192.0.2.5"
	if _, err := j.Append(segment); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("expected content conflict, got %v", err)
	}
}

func TestJournalRejectsRawBytesWithWrongHash(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.Raw = []byte("source record\n")
	segment.RawSHA256 = "wrong"
	if _, err := j.Append(segment); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("accepted mismatched raw content: %v", err)
	}
}

func TestJournalKeepsFirstArchiveMonthAcrossMonthBoundary(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.ArchiveMonth = "202610"
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	segment.ArchiveMonth = "202611"
	again, err := j.Append(segment)
	if err != nil || again != id {
		t.Fatalf("retry changed segment identity: %s %v", again, err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Segment.ArchiveMonth != "202610" {
		t.Fatalf("archive month drifted: %s", state.Segment.ArchiveMonth)
	}
}

func TestJournalDiscardIncompleteTemporaryFileOnReopen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".partial.tmp"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(testSegment()); err != nil {
		t.Fatal(err)
	}
}

func TestJournalTracksHeaderOnlyInputWithoutSinkWrites(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.Events = nil
	segment.NeedsProjection = false
	segment.RawSHA256 = "header-only"
	id := appendCommitted(t, j, segment)
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range []Lane{Archive, Search, Projection} {
		if state.Acks[lane] != NotApplicable {
			t.Fatalf("header-only lane %s is %s", lane, state.Acks[lane])
		}
	}
	if err := j.Release(id); err != nil {
		t.Fatal(err)
	}
}

func TestPendingLanesExcludeNotApplicableAndAcknowledgedWork(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.NeedsProjection = false
	id := appendCommitted(t, j, segment)
	lanes, err := j.PendingLanes(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(lanes) != 2 || lanes[0] != Archive || lanes[1] != Search {
		t.Fatalf("non-projected segment queued for unexpected lanes: %v", lanes)
	}
	if err := j.Ack(id, Archive); err != nil {
		t.Fatal(err)
	}
	lanes, err = j.PendingLanes(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(lanes) != 1 || lanes[0] != Search {
		t.Fatalf("acknowledged archive or non-applicable projection requeued: %v", lanes)
	}
	projected := testSegment()
	projected.SourcePath = "/logs/projected.log"
	projectedID := appendCommitted(t, j, projected)
	lanes, err = j.PendingLanes(projectedID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lanes) != 3 || lanes[0] != Archive || lanes[1] != Projection || lanes[2] != Search {
		t.Fatalf("required projection was omitted: %v", lanes)
	}
}

func TestPendingSegmentsIncludeUnfinishedBodyWithoutState(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := testSegment()
	first.FileID = "file-1"
	first.StartOffset, first.EndOffset = 0, 10
	firstID, err := j.Append(first)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.StartOffset, second.EndOffset = 10, 20
	secondID, err := j.Append(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, secondID+".state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted body unexpectedly required a state file: %v", err)
	}
	ids, err := j.PendingSegments()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != firstID || ids[1] != secondID {
		t.Fatalf("pending segments: %v", ids)
	}
}

func TestJournalKeepsConcurrentLaneAcksAcrossHandles(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := appendCommitted(t, first, testSegment())
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errors := make(chan error, 3)
	for _, lane := range []Lane{Archive, Search, Projection} {
		group.Add(1)
		go func(lane Lane) {
			defer group.Done()
			if err := second.BeginAttempt(id, lane); err != nil {
				errors <- err
				return
			}
			errors <- first.Ack(id, lane)
		}(lane)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	state, err := second.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range []Lane{Archive, Search, Projection} {
		if state.Acks[lane] != Acked {
			t.Fatalf("lost %s acknowledgement: %+v", lane, state.Acks)
		}
	}
}

func TestJournalOtherSegmentAdvancesWhileOneStripeIsLocked(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := testSegment()
	firstID := appendCommitted(t, j, first)
	second := first
	second.SourcePath = "/logs/other.log"
	second.FileID = "other-device"
	second.PreviousFileID = second.FileID
	for segmentID(second)[:2] == firstID[:2] {
		second.SourcePath += "x"
	}
	secondID := appendCommitted(t, j, second)
	lock, err := j.lockSegment(firstID)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock(lock)
	done := make(chan error, 1)
	go func() { done <- j.BeginAttempt(secondID, Archive) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("other segment waited for unrelated durable write")
	}
}
