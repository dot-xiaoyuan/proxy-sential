package streamlog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/streamwal"
)

func passiveWALFixture(t *testing.T) (*Journal, Segment) {
	t.Helper()
	legacy, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := encodingSegment(1)
	s.Source = "passive-discovery"
	s.SourcePath = "packet://bond0/sensor"
	s.ParserVersion = "passive-frame-v1"
	s.PreviousOffset = 0
	s.StartOffset = 0
	s.EndOffset = 100
	if err := legacy.StartFreshSource(SourceCursor{Epoch: s.Epoch, Source: s.Source, Path: s.SourcePath, FileID: s.FileID, ParserVersion: s.ParserVersion, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return legacy, s
}

func TestPassiveLegacyPhaseObservationPreservesInterruptedCommit(t *testing.T) {
	legacy, segment := passiveWALFixture(t)
	var observed []PassiveJournalPhases
	var failures []error
	journal, err := OpenPassiveWALJournal(legacy, segment.SourcePath, PassiveWALOptions{
		PhaseObserver: func(phases PassiveJournalPhases, eventCount int, sourceBytes int64, failure error) {
			if eventCount != len(segment.Events) || sourceBytes != segment.EndOffset-segment.StartOffset {
				t.Errorf("unexpected bounded batch size: %d events %d bytes", eventCount, sourceBytes)
			}
			observed = append(observed, phases)
			failures = append(failures, failure)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	// The body can be durable even if the cursor predecessor is rejected.
	segment.PreviousOffset = 1
	id, err := journal.AppendAndCommitPassive(segment)
	if !errors.Is(err, ErrContentConflict) || id == "" {
		t.Fatalf("expected durable body with rejected cursor: %s %v", id, err)
	}
	if len(observed) != 1 || !observed[0].AppendAttempted || !observed[0].CommitAttempted || !errors.Is(failures[0], ErrContentConflict) {
		t.Fatalf("commit failure was not attributed: %+v %v", observed, failures)
	}
	if cursor, err := journal.LoadSource(segment.Source, segment.SourcePath); err != nil || cursor.Offset != 0 {
		t.Fatalf("failed commit advanced source: %+v %v", cursor, err)
	}
	if state, err := journal.Load(id); err != nil || state.Segment.PreviousOffset != 1 {
		t.Fatalf("failed commit lost body: %+v %v", state, err)
	}
}

func TestPassiveLegacyPhaseObservationSkipsCommitAfterAppendFailure(t *testing.T) {
	legacy, segment := passiveWALFixture(t)
	segment.EndOffset = segment.StartOffset
	_, phases, err := legacy.AppendAndCommitPassiveMeasured(segment)
	if err == nil || !phases.AppendAttempted || phases.CommitAttempted {
		t.Fatalf("invalid append reached commit: %+v %v", phases, err)
	}
}

func TestPassiveLegacyCommitSubphasesCoverDurablePath(t *testing.T) {
	legacy, segment := passiveWALFixture(t)
	_, phases, err := legacy.AppendAndCommitPassiveMeasured(segment)
	if err != nil {
		t.Fatal(err)
	}
	parts := []time.Duration{phases.CommitLockDuration, phases.CommitLoadDuration, phases.CommitAckDuration, phases.CommitStateDuration, phases.CommitCursorDuration}
	var covered time.Duration
	for _, part := range parts {
		if part <= 0 {
			t.Fatalf("missing commit phase: %+v", phases)
		}
		covered += part
	}
	if covered > phases.CommitDuration {
		t.Fatalf("commit phases overlap: %+v", phases)
	}
}

func TestPassiveWALAcceptAtomicallyAdvancesCursorAndRetainsFirstTime(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource(s.Source, s.SourcePath)
	if err != nil || cursor.Offset != 100 || cursor.LastSegmentID != id {
		t.Fatalf("cursor: %+v %v", cursor, err)
	}
	old, _ := legacy.LoadSource(s.Source, s.SourcePath)
	if old.Offset != 0 {
		t.Fatal("legacy cutoff moved")
	}
	s.AcceptedAt = s.AcceptedAt.Add(time.Hour)
	s.ArchiveMonth = "202612"
	if again, err := j.AppendAndCommitPassive(s); err != nil || again != id {
		t.Fatalf("duplicate: %s %v", again, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err := j.Load(id)
	if err != nil || state.Segment.ArchiveMonth != "202611" || state.Segment.AcceptedAt.Equal(s.AcceptedAt) {
		t.Fatalf("first immutable time changed: %+v %v", state, err)
	}
	if _, err := j.AppendAndCommitPassive(s); !errors.Is(err, ErrPassiveWALWritesDisabled) {
		t.Fatalf("disabled writer fell back to v1: %v", err)
	}
}

func TestPassiveWALUnknownLaneReplaysReconcileAndPreservesBody(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeLaneWriter{failArchiveOnce: true}
	p := Processor{Journal: j, Writer: writer}
	if err := p.DrainLane(context.Background(), id, Archive); err == nil {
		t.Fatal("expected unknown archive result")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err := j.Load(id)
	if err != nil || state.Acks[Archive] != Attempted {
		t.Fatalf("unknown outcome reset: %+v %v", state.Acks, err)
	}
	p.Journal = j
	if err := p.DrainLane(context.Background(), id, Archive); err != nil {
		t.Fatal(err)
	}
	if writer.archiveWrites != 1 || writer.archiveChecks != 1 {
		t.Fatalf("unknown result was blindly resent: %+v", writer)
	}
	if err := j.Release(id); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("unconfirmed body released: %v", err)
	}
	for _, lane := range []Lane{Projection, Search} {
		if err := p.DrainLane(context.Background(), id, lane); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.FinalizeAfterLanes(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if state, err := j.Load(id); err != nil || !state.Released {
		t.Fatalf("finalized state: %+v %v", state, err)
	}
	ref, ok := j.V2SegmentReference(id)
	if !ok {
		t.Fatal("missing WAL evidence reference")
	}
	if _, err := os.Stat(ref.WALDirectory); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveWALRoutesLegacyPendingAndRejectsQuarantineActivation(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	id, err := legacy.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(`{"status":"quarantined_unprocessed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true, QuarantineDir: dir}); !errors.Is(err, ErrQuarantined) {
		if j != nil {
			j.Close()
		}
		t.Fatalf("quarantine bypassed: %v", err)
	}
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	ids, err := j.RecoverSource(s.Source, s.SourcePath)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("legacy pending lost: %v %v", ids, err)
	}
	if _, ok := j.V2SegmentReference(id); ok {
		t.Fatal("legacy body claimed by WAL")
	}
	if err := (Processor{Journal: j, Writer: &fakeLaneWriter{}}).Drain(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy retirement changed: %v", err)
	}
}

func TestPassiveWALRecoversAcceptAfterDurableResultBeforeMemoryCursor(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	id := segmentID(s)
	result, err := j.wal.Append(context.Background(), streamwal.Record{Kind: "accept", ID: id, Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	if r := <-result; r.Err != nil {
		t.Fatal(r.Err)
	}
	// The adapter has not applied this receipt to its in-memory source head.
	if cursor, _ := j.LoadSource(s.Source, s.SourcePath); cursor.Offset != 0 {
		t.Fatal("test did not leave the crash window")
	}
	j.Close()
	j, err = OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if cursor, _ := j.LoadSource(s.Source, s.SourcePath); cursor.Offset != s.EndOffset || cursor.LastSegmentID != id {
		t.Fatalf("sealed accept did not recover atomically: %+v", cursor)
	}
	state, err := j.Load(id)
	if err != nil || !state.Committed || state.Acks[Archive] != Pending {
		t.Fatalf("recovered body=%+v %v", state, err)
	}
}

func TestPassiveWALCheckpointCutWaitsForDurableLaneFold(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	transition := passiveTransition{ContentSHA256: j.entries[id].state.ContentSHA256, Lane: Archive, Status: Attempted}
	raw, _ := json.Marshal(transition)
	j.mutationMu.RLock() // Pause exactly after the receipt and before the state fold.
	if _, err := j.persist("lane", id, raw); err != nil {
		j.mutationMu.RUnlock()
		t.Fatal(err)
	}
	type result struct {
		cut PassiveWALCheckpointCandidate
		err error
	}
	done := make(chan result, 1)
	go func() { cut, err := j.CheckpointCandidate(); done <- result{cut, err} }()
	deadline := time.Now().Add(time.Second)
	for j.mutationMu.TryRLock() {
		j.mutationMu.RUnlock()
		if time.Now().After(deadline) {
			j.mutationMu.RUnlock()
			t.Fatal("checkpoint did not wait for in-flight mutation")
		}
		runtime.Gosched()
	}
	select {
	case <-done:
		j.mutationMu.RUnlock()
		t.Fatal("checkpoint passed an unfolded durable receipt")
	default:
	}
	j.mu.Lock()
	err = applyPassiveTransition(&j.entries[id].state, "lane", transition)
	j.mu.Unlock()
	j.mutationMu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || got.cut.Position.LastLSN != 3 || len(got.cut.Entries) != 1 || got.cut.Entries[0].State.Acks[Archive] != Attempted {
		t.Fatalf("checkpoint cut omitted the folded lane: %+v %v", got.cut, got.err)
	}
	if err := j.wal.VerifyPosition(got.cut.Position); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveWALRejectsSourceOrScopeErrorsWithoutMovingCursor(t *testing.T) {
	for _, kind := range []string{"predecessor", "scope", "scope_issue", "source_backed", "first_time"} {
		t.Run(kind, func(t *testing.T) {
			legacy, s := passiveWALFixture(t)
			j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			switch kind {
			case "predecessor":
				s.PreviousOffset = 20
			case "scope":
				delete(s.Events[0].Observer, "capture_scope_id")
			case "scope_issue":
				s.Events[0].Observer["capture_scope_issue"] = "mismatch"
			case "source_backed":
				s.SourceBackedRaw = true
			case "first_time":
				s.AcceptedAt = time.Time{}
			}
			if _, err := j.AppendAndCommitPassive(s); err == nil {
				t.Fatal("invalid accept persisted")
			}
			if cursor, _ := j.LoadSource(s.Source, s.SourcePath); cursor.Offset != 0 {
				t.Fatal("invalid accept moved cursor")
			}
			info, err := streamwal.Inspect(j.dir, streamwal.Options{})
			if err != nil || info.Records != 1 {
				t.Fatalf("invalid accept left a record: %+v %v", info, err)
			}
		})
	}
}

func TestPassiveWALQuarantineRetainsBodyAndBlocksActivation(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Quarantine(id, "fact scope mismatch"); err != nil {
		t.Fatal(err)
	}
	if err := j.Release(id); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("quarantine release=%v", err)
	}
	next := s
	next.PreviousOffset = s.EndOffset
	next.StartOffset = s.EndOffset
	next.EndOffset += 100
	if _, err := j.AppendAndCommitPassive(next); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("quarantine allowed next accept: %v", err)
	}
	j.Close()
	if reopened, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true}); !errors.Is(err, ErrQuarantined) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("quarantine activation: %v", err)
	}
	j, err = OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err := j.Load(id)
	if err != nil || !state.Segment.Quarantined || len(state.Segment.Events) != 1 {
		t.Fatalf("quarantine evidence lost: %+v %v", state, err)
	}
}

func TestPassiveWALRefusesChangedLegacyCutoverAnchor(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.AppendAndCommitPassive(s); err != nil {
		t.Fatal(err)
	}
	j.Close()
	// Simulates an unsupported old producer running after the WAL-aware lease
	// was released. A new adapter must expose the divergence, never reset it.
	if _, err := legacy.AppendAndCommitPassive(s); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{}); !errors.Is(err, ErrContentConflict) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("changed legacy cutoff accepted: %v", err)
	}
}

func TestPassiveWALRejectsAckWithoutAttemptDuringReplay(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := j.Load(id)
	raw, _ := json.Marshal(passiveTransition{ContentSHA256: state.ContentSHA256, Lane: Archive, Status: Acked})
	if _, err := j.persist("lane", id, raw); err != nil {
		t.Fatal(err)
	}
	j.Close()
	if reopened, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{}); !errors.Is(err, ErrContentConflict) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("ack without attempt replayed: %v", err)
	}
}

func TestPassiveWALDefaultRemainsV1AndAbortCannotUndoAck(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := j.V2SegmentReference(id); ok {
		t.Fatal("default mode wrote WAL")
	}
	if _, err := os.Stat(j.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("default mode created WAL: %v", err)
	}
	j.Close()
	j, err = OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	next := s
	next.PreviousOffset = s.EndOffset
	next.StartOffset = s.EndOffset
	next.EndOffset += 100
	id, err = j.AppendAndCommitPassive(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := j.AbortUnsentAttempt(id, Archive); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("abort undid ack: %v", err)
	}
}

func TestPassiveWALRecoveryDoesNotSkipMissingLegacyPendingBody(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	id, err := legacy.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := os.Remove(legacy.path(id, ".segment")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecoverSource(s.Source, s.SourcePath); err == nil {
		t.Fatal("missing pending legacy evidence was skipped")
	}
}

func TestPassiveWALReplayRejectsAcceptAfterDurableQuarantine(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Quarantine(id, "scope mismatch"); err != nil {
		t.Fatal(err)
	}
	next := s
	next.PreviousOffset = s.EndOffset
	next.StartOffset = s.EndOffset
	next.EndOffset += 100
	raw, _ := json.Marshal(next)
	if _, err := j.persist("accept", segmentID(next), raw); err != nil {
		t.Fatal(err)
	}
	j.Close()
	if reopened, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{}); !errors.Is(err, ErrContentConflict) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("post-quarantine accept replayed: %v", err)
	}
}

func TestPassiveWALPureV1KeepsExistingManifestGate(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "historical.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{QuarantineDir: dir})
	if err != nil {
		t.Fatalf("pure v1 changed manifest behavior: %v", err)
	}
	defer j.Close()
	if _, err := os.Stat(j.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pure v1 created WAL: %v", err)
	}
}

func TestPassiveWALMaximumBodyDoesNotNeedASecondEnvelopeCopy(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s.Events[0].Payload["padding"] = ""
	raw, _ := json.Marshal(s)
	s.Events[0].Payload["padding"] = strings.Repeat("x", MaxSegmentBytes-len(raw))
	if raw, _ := json.Marshal(s); len(raw) != MaxSegmentBytes {
		t.Fatal("bad max-body fixture")
	}
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatalf("valid 4 MiB body rejected by wrapper overhead: %v", err)
	}
	if _, err := j.Load(id); err != nil {
		t.Fatal(err)
	}
	s.Events[0].Payload["padding"] = s.Events[0].Payload["padding"].(string) + "x"
	if _, err := j.AppendAndCommitPassive(s); !errors.Is(err, ErrSegmentTooLarge) {
		t.Fatalf("oversized body accepted: %v", err)
	}
}

func TestPassiveWALBodyReferenceIntegrityFailureStopsFurtherCapture(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := j.V2SegmentReference(id)
	f, err := os.OpenFile(filepath.Join(ref.WALDirectory, "records.v1.wal"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteAt([]byte{0}, ref.Offset+64+4+int64(len("accept")+len(id)))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Load(id); !errors.Is(err, ErrPassiveWALStopped) || !errors.Is(err, ErrContentConflict) {
		t.Fatalf("corrupt body reference accepted: %v", err)
	}
	if _, err := j.AppendAndCommitPassive(s); !errors.Is(err, ErrPassiveWALStopped) {
		t.Fatalf("capture continued after corruption: %v", err)
	}
}

func TestPassiveWALBeforeRecoveryFailurePreservesCursorAndReleasesLease(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "wal"}[enabled], func(t *testing.T) {
			legacy, s := passiveWALFixture(t)
			id, err := legacy.Append(s) // RecoverSource would commit this body.
			if err != nil {
				t.Fatal(err)
			}
			before, _ := legacy.LoadSource(s.Source, s.SourcePath)
			blocked := errors.New("audited source verification failed")
			calls := 0
			j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{
				WriteEnabled: enabled,
				BeforeRecovery: func(cursor SourceCursor) error {
					calls++
					if cursor != before {
						t.Fatal("verification saw a recovered cursor")
					}
					if release, err := legacy.AcquireSourceLease(s.Source, s.SourcePath); err == nil {
						release()
						t.Fatal("verification did not hold the source lease")
					}
					return blocked
				},
			})
			if j != nil {
				j.Close()
			}
			if !errors.Is(err, blocked) || calls != 1 {
				t.Fatalf("recovery gate bypassed: calls=%d err=%v", calls, err)
			}
			after, err := legacy.LoadSource(s.Source, s.SourcePath)
			if err != nil || after != before {
				t.Fatalf("failed verification changed cursor: %+v %v", after, err)
			}
			state, err := legacy.Load(id)
			if err != nil || state.Committed || state.ProcessingReady {
				t.Fatalf("failed verification changed pending body: %+v %v", state, err)
			}
			if _, err := os.Stat(filepath.Join(legacy.Directory(), "passive-wal-v1")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed verification created WAL: %v", err)
			}
			release, err := legacy.AcquireSourceLease(s.Source, s.SourcePath)
			if err != nil {
				t.Fatalf("failed verification retained lease: %v", err)
			}
			release()
		})
	}
}

func TestPassiveWALPureV1DefersRecoveryUntilCallerRequestsIt(t *testing.T) {
	legacy, s := passiveWALFixture(t)
	id, err := legacy.Append(s)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := legacy.LoadSource(s.Source, s.SourcePath)
	calls := 0
	j, err := OpenPassiveWALJournal(legacy, s.SourcePath, PassiveWALOptions{BeforeRecovery: func(cursor SourceCursor) error {
		calls++
		if cursor != before {
			t.Fatal("verification saw a recovered cursor")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	after, err := j.LoadSource(s.Source, s.SourcePath)
	if err != nil || after != before || calls != 1 {
		t.Fatalf("pure v1 constructor advanced cursor: %+v calls=%d err=%v", after, calls, err)
	}
	ids, err := j.RecoverSource(s.Source, s.SourcePath)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("explicit recovery failed: %v %v", ids, err)
	}
	after, err = j.LoadSource(s.Source, s.SourcePath)
	if err != nil || after.Offset != s.EndOffset {
		t.Fatalf("explicit recovery did not commit: %+v %v", after, err)
	}
}

func TestPassiveWALDataLimitStillAllowsAcceptedLanesAndFinalize(t *testing.T) {
	legacy, segment := passiveWALFixture(t)
	segment.Events[0].Payload["capacity_padding"] = ""
	raw, err := json.Marshal(segment)
	if err != nil || len(raw) >= 2500 {
		t.Fatalf("invalid capacity fixture: bytes=%d err=%v", len(raw), err)
	}
	segment.Events[0].Payload["capacity_padding"] = strings.Repeat("x", 2500-len(raw))
	opts := PassiveWALOptions{WriteEnabled: true, WAL: streamwal.Options{MaxLogBytes: 64 << 10, MaxDataBytes: 4096, ControlReserveBytes: 32 << 10}}
	j, err := OpenPassiveWALJournal(legacy, segment.SourcePath, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	id, err := j.AppendAndCommitPassive(segment)
	if err != nil {
		t.Fatal(err)
	}
	next := segment
	next.PreviousOffset, next.StartOffset, next.EndOffset = segment.EndOffset, segment.EndOffset, segment.EndOffset+100
	if _, err := j.AppendAndCommitPassive(next); !errors.Is(err, streamwal.ErrNotWritten) || !errors.Is(err, streamwal.ErrDataCapacity) || errors.Is(err, ErrPassiveWALStopped) {
		t.Fatalf("data limit stopped the journal or admitted new input: %v", err)
	}
	if err := (Processor{Journal: j, Writer: &fakeLaneWriter{}}).Drain(context.Background(), id); err != nil {
		t.Fatalf("accepted work could not use control reserve: %v", err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Released || !state.Segment.AcceptedAt.Equal(segment.AcceptedAt) || len(state.Segment.Events) != 1 {
		t.Fatalf("finalization changed first time or deleted body: %+v %v", state, err)
	}
	cursor, err := j.LoadSource(segment.Source, segment.SourcePath)
	if err != nil || cursor.Offset != segment.EndOffset || cursor.LastSegmentID != id {
		t.Fatalf("rejected accept advanced cursor: %+v %v", cursor, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	opts.WAL.MaxDataBytes = 1
	j, err = OpenPassiveWALJournal(legacy, segment.SourcePath, opts)
	if err != nil {
		t.Fatalf("lower data budget prevented recovery: %v", err)
	}
	defer j.Close()
	if state, err := j.Load(id); err != nil || !state.Released || len(state.Segment.Events) != 1 {
		t.Fatalf("completed evidence lost on recovery: %+v %v", state, err)
	}
}
