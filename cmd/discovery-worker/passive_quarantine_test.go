package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestPassiveScopeConflictQuarantineRetainsOneImmutableBody(t *testing.T) {
	dir, spool := t.TempDir(), t.TempDir()
	j, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("observed mirror frame")
	sum := sha256.Sum256(raw)
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", SourcePath: "packet://bond0/node", FileID: "boot", PreviousFileID: "boot",
		StartOffset: 0, EndOffset: int64(len(raw)), ParserVersion: discovery.PassiveStreamParserVersion,
		Raw: raw, RawSHA256: hex.EncodeToString(sum[:]), NeedsProjection: true,
		Events: []normalized.Event{{EventID: "packet-1", Timestamp: time.Now().UTC().Format(time.RFC3339), Type: "discovery"}}}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.FileID, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	manifest, err := quarantinePassiveSegment(j, dir, spool, id, discovery.ErrStreamFactScopeMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := quarantinePassiveSegment(j, dir, spool, id, discovery.ErrStreamFactScopeMismatch); err != nil || again != manifest {
		t.Fatalf("quarantine retry lost idempotency: %s %v", again, err)
	}
	source, err := os.Stat(filepath.Join(dir, id+".segment"))
	if err != nil {
		t.Fatal(err)
	}
	linked, err := os.Stat(filepath.Join(spool, "discovery-quarantine", id+".segment"))
	if err != nil || !os.SameFile(source, linked) {
		t.Fatalf("quarantine duplicated or lost immutable body: %v", err)
	}
	rawManifest, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var record passiveQuarantineRecord
	if err := json.Unmarshal(rawManifest, &record); err != nil || record.SegmentID != id || record.RawSHA256 != segment.RawSHA256 || record.Status != "quarantined_unprocessed" {
		t.Fatalf("quarantine audit lost raw reference or unfinished status: %+v %v", record, err)
	}
	if _, err := j.Load(id); err != nil {
		t.Fatalf("original pending segment was altered: %v", err)
	}
	if _, err := quarantinePassiveSegment(j, dir, spool, "../escape", errors.New("bad")); err == nil {
		t.Fatal("unsafe quarantine id was accepted")
	}
}

func TestPassiveWALQuarantineRetainsReferenceWithoutCopyingBody(t *testing.T) {
	dir, spool := t.TempDir(), t.TempDir()
	legacy, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	s := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", SourcePath: "packet://bond0/node", FileID: "boot", PreviousFileID: "boot",
		StartOffset: 0, EndOffset: 100, ParserVersion: discovery.PassiveStreamParserVersion, ArchiveMonth: at.Format("200601"), AcceptedAt: at, NeedsProjection: true,
		Events: []normalized.Event{{EventID: "event-1", Timestamp: at.Format(time.RFC3339Nano), Type: "discovery", Observer: map[string]any{"capture_scope_id": "scope-1"}}}}
	if err := legacy.StartFreshSource(streamlog.SourceCursor{Epoch: s.Epoch, Source: s.Source, Path: s.SourcePath, FileID: s.FileID, ParserVersion: s.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.OpenPassiveWALJournal(legacy, s.SourcePath, streamlog.PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	id, err := j.AppendAndCommitPassive(s)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := quarantinePassiveSegment(j, dir, spool, id, discovery.ErrStreamFactScopeMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := quarantinePassiveSegment(j, dir, spool, id, discovery.ErrStreamFactScopeMismatch); err != nil || again != manifest {
		t.Fatalf("retry: %s %v", again, err)
	}
	for _, root := range []string{dir, filepath.Join(spool, "discovery-quarantine")} {
		if _, err := os.Stat(filepath.Join(root, id+".segment")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected copied body: %v", err)
		}
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var record passiveQuarantineRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	ref, ok := j.V2SegmentReference(id)
	if !ok || record.WALReference == nil || *record.WALReference != ref || record.Status != "quarantined_unprocessed" {
		t.Fatalf("lost authoritative reference: %+v", record)
	}
	state, err := j.Load(id)
	if err != nil || !state.Segment.Quarantined || len(state.Segment.Events) != 1 {
		t.Fatalf("body or quarantine missing: %+v %v", state, err)
	}
	if err := j.Release(id); !errors.Is(err, streamlog.ErrQuarantined) {
		t.Fatalf("quarantined body released: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := streamlog.OpenPassiveWALJournal(legacy, s.SourcePath, streamlog.PassiveWALOptions{QuarantineDir: filepath.Dir(manifest)}); !errors.Is(err, streamlog.ErrQuarantined) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("quarantine did not block startup: %v", err)
	}
}
