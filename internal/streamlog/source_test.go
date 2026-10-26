package streamlog

import (
	"errors"
	"os"
	"testing"
)

func TestFreshSourceCursorCannotAdvanceWithoutDurableSegment(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	start := SourceCursor{Epoch: "new-epoch", Source: "zeek-dhcp", Path: "/logs/dhcp.log", FileID: "inode-a", Offset: 100, ParserVersion: "v1"}
	if err := j.StartFreshSource(start); err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(start.Source, start.Path, "not-a-segment"); err == nil {
		t.Fatal("advanced source without segment")
	}
	segment := testSegment()
	segment.Epoch, segment.Source, segment.FileID, segment.StartOffset, segment.EndOffset = start.Epoch, start.Source, start.FileID, 100, 140
	segment.PreviousFileID, segment.PreviousOffset = start.FileID, start.Offset
	segment.ParserVersion = start.ParserVersion
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(start.Source, start.Path, id); err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource(start.Source, start.Path)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Offset != 140 || cursor.LastSegmentID != id {
		t.Fatalf("bad committed cursor: %+v", cursor)
	}
	if err := j.StartFreshSource(SourceCursor{Epoch: "different-epoch", Source: start.Source, Path: start.Path, FileID: start.FileID, Offset: 140, ParserVersion: "v2"}); !errors.Is(err, ErrSourceAlreadyStarted) {
		t.Fatalf("silently reset source epoch: %v", err)
	}
}

func TestSourceCursorRejectsGapsAndAcceptsNewFileFromZero(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	start := SourceCursor{Epoch: "new-epoch", Source: "zeek-dhcp", Path: "/logs/dhcp.log", FileID: "inode-a", Offset: 100, ParserVersion: "v1"}
	if err := j.StartFreshSource(start); err != nil {
		t.Fatal(err)
	}
	gap := testSegment()
	gap.Epoch, gap.Source, gap.FileID, gap.ParserVersion, gap.StartOffset, gap.EndOffset = start.Epoch, start.Source, start.FileID, start.ParserVersion, 101, 140
	gap.PreviousFileID, gap.PreviousOffset = start.FileID, start.Offset
	gapID, err := j.Append(gap)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(start.Source, start.Path, gapID); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("gap accepted: %v", err)
	}
	rotated := gap
	rotated.FileID, rotated.StartOffset, rotated.EndOffset = "inode-b", 0, 40
	rotatedID, err := j.Append(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(start.Source, start.Path, rotatedID); err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource(start.Source, start.Path)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.FileID != "inode-b" || cursor.Offset != 40 {
		t.Fatalf("rotation not committed: %+v", cursor)
	}
}

func TestSourceGenerationDistinguishesReusedZeekInode(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	start := SourceCursor{Epoch: "fresh-v2", Source: "zeek-dhcp-binding", Path: "/logs/binding.log", FileID: "reused-inode", Offset: 100, ParserVersion: "zeek-dhcp-binding-v2", KeyScheme: "generation-v2", Generation: 1}
	if err := j.StartFreshSource(start); err != nil {
		t.Fatal(err)
	}
	first := testSegment()
	first.Epoch, first.Source, first.SourcePath, first.FileID, first.ParserVersion = start.Epoch, start.Source, start.Path, start.FileID, start.ParserVersion
	first.KeyScheme, first.PreviousGeneration, first.SourceGeneration = start.KeyScheme, 1, 1
	first.PreviousFileID, first.PreviousOffset, first.StartOffset, first.EndOffset = start.FileID, 100, 100, 140
	firstID, err := j.Append(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(start.Source, start.Path, firstID); err != nil {
		t.Fatal(err)
	}
	rotated := first
	rotated.PreviousOffset, rotated.StartOffset, rotated.EndOffset = 140, 0, 40
	rotated.PreviousGeneration, rotated.SourceGeneration = 1, 2
	rotatedID, err := j.Append(rotated)
	if err != nil || rotatedID == firstID {
		t.Fatalf("generation reused segment identity: %s %s %v", firstID, rotatedID, err)
	}
	if err := j.CommitSource(start.Source, start.Path, rotatedID); err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource(start.Source, start.Path)
	if err != nil || cursor.Generation != 2 || cursor.Offset != 40 || cursor.FileID != start.FileID {
		t.Fatalf("reused inode rotation was not fenced: %+v %v", cursor, err)
	}
}

func TestSourceCursorRejectsStaleRotatedSegment(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	start := SourceCursor{Epoch: "new-epoch", Source: "zeek-dhcp", Path: "/logs/dhcp.log", FileID: "inode-a", Offset: 100, ParserVersion: "v1"}
	if err := j.StartFreshSource(start); err != nil {
		t.Fatal(err)
	}
	first := testSegment()
	first.Epoch, first.Source, first.FileID, first.ParserVersion, first.StartOffset, first.EndOffset = start.Epoch, start.Source, "inode-b", start.ParserVersion, 0, 40
	first.PreviousFileID, first.PreviousOffset = "inode-a", 100
	firstID, err := j.Append(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(start.Source, start.Path, firstID); err != nil {
		t.Fatal(err)
	}
	stale := first
	stale.FileID = "inode-c"
	stale.PreviousFileID, stale.PreviousOffset = "inode-a", 100
	staleID, err := j.Append(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(start.Source, start.Path, staleID); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("stale rotated file regressed cursor: %v", err)
	}
}

func TestRecoverSourceCommitsFsyncedSegmentBeforeConsumption(t *testing.T) {
	j, err := Open(t.TempDir())
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
	if _, err := os.Stat(j.path(id, ".state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted body should recover without an extra state fsync: %v", err)
	}
	ids, err := j.RecoverSource(segment.Source, segment.SourcePath)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("pending segment recovery: %v %v", ids, err)
	}
	cursor, err := j.LoadSource(segment.Source, segment.SourcePath)
	if err != nil || cursor.LastSegmentID != id || cursor.Offset != segment.EndOffset {
		t.Fatalf("source did not advance after durable recovery: %+v %v", cursor, err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Committed {
		t.Fatalf("recovered segment cannot be consumed: %+v %v", state, err)
	}
}

func TestRecoverSourceFinishesInterruptedCursorWrite(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	start := SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}
	if err := j.StartFreshSource(start); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.prepareEmptyAckLog(id); err != nil {
		t.Fatal(err)
	}
	state.Committed = true
	state.AckLog = true
	state.AckLogSealed = true
	if err := atomicJSONBeforeDirectoryBarrier(j.path(id, ".state"), stateWithoutEvents(state)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecoverSource(segment.Source, segment.SourcePath); err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource(segment.Source, segment.SourcePath)
	if err != nil || cursor.LastSegmentID != id {
		t.Fatalf("interrupted commit was not finished: %+v %v", cursor, err)
	}
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatalf("recovered cursor did not seal the first sink attempt: %v", err)
	}
}

func TestPreparedSourcePreservesSinkAckAcrossCursorRecovery(t *testing.T) {
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
	if err := j.PrepareSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || !state.ProcessingReady || state.Committed {
		t.Fatalf("prepared segment cannot be consumed independently: %+v %v", state, err)
	}
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := j.Release(id); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("source body released before cursor: %v", err)
	}
	cursor, err := j.LoadSource(segment.Source, segment.SourcePath)
	if err != nil || cursor.LastSegmentID != "" {
		t.Fatalf("preparation advanced the source: %+v %v", cursor, err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := j.RecoverSource(segment.Source, segment.SourcePath)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("prepared source was not recovered: %v %v", ids, err)
	}
	state, err = j.Load(id)
	if err != nil || !state.Committed || state.Acks[Archive] != Acked {
		t.Fatalf("sink acknowledgement was lost during cursor recovery: %+v %v", state, err)
	}
}

func TestRecoverSourceSealsCursorAfterPreparedStateWriteWasInterrupted(t *testing.T) {
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
	if err := j.PrepareSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource(segment.Source, segment.SourcePath)
	if err != nil {
		t.Fatal(err)
	}
	cursor.FileID, cursor.Offset, cursor.LastSegmentID = segment.FileID, segment.EndOffset, id
	if err := atomicJSON(j.sourcePath(segment.Source, segment.SourcePath), cursor); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecoverSource(segment.Source, segment.SourcePath); err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Committed {
		t.Fatalf("durable cursor did not finish the prepared state: %+v %v", state, err)
	}
}

func TestSourceLeasePreventsConcurrentReader(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release, err := j.AcquireSourceLease("zeek-dhcp", "/logs/dhcp.log")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.AcquireSourceLease("zeek-dhcp", "/logs/dhcp.log"); err == nil {
		release()
		t.Fatal("second reader acquired active source")
	}
	release()
	second, err := j.AcquireSourceLease("zeek-dhcp", "/logs/dhcp.log")
	if err != nil {
		t.Fatal(err)
	}
	second()
}
