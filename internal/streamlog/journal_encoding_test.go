package streamlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func encodingSegment(count int) Segment {
	segment := testSegment()
	segment.ArchiveMonth = "202611"
	segment.AcceptedAt = time.Date(2026, 11, 1, 7, 0, 0, 123456789, time.UTC)
	segment.Events = make([]normalized.Event, count)
	for i := range segment.Events {
		segment.Events[i] = normalized.Event{
			EventID: fmt.Sprintf("event-%d", i), Timestamp: "2026-11-01T06:59:59.123456789Z",
			Source: "passive-discovery", Type: "discovery",
			Subject:  map[string]any{"ip": "192.0.2.4", "mac": "02:00:00:00:00:01"},
			Observer: map[string]any{"sensor_id": "sensor-1", "capture_scope_id": "scope-1"},
			Payload: map[string]any{"name": "printer <A>&\"B\"\n打印机", "ports": []any{float64(80), float64(443)},
				"evidence": map[string]any{"protocol": "dns-sd", "count": float64(i + 1)}},
		}
	}
	return segment
}

func TestJournalEncodedBodySurvivesInterruptedSourceCommit(t *testing.T) {
	for _, count := range []int{1, MaxSegmentEvents} {
		t.Run(fmt.Sprintf("events_%d", count), func(t *testing.T) {
			dir := t.TempDir()
			j, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			segment := encodingSegment(count)
			if err := j.StartFreshSource(SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath,
				FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(segment)
			if err != nil {
				t.Fatal(err)
			}
			id, err := j.Append(segment)
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(j.path(id, ".segment"))
			if err != nil || !bytes.Equal(body, want) {
				t.Fatalf("persisted segment differs from bounded encoding: %v", err)
			}
			cursor, err := j.LoadSource(segment.Source, segment.SourcePath)
			if err != nil || cursor.Offset != segment.PreviousOffset {
				t.Fatalf("append advanced source before commit: %+v %v", cursor, err)
			}
			// Simulate process loss after the body was fsynced, before state or
			// cursor commit. A new handle must recover the same exact events.
			j, err = Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			ids, err := j.RecoverSource(segment.Source, segment.SourcePath)
			if err != nil || len(ids) != 1 || ids[0] != id {
				t.Fatalf("recover durable body: %v %v", ids, err)
			}
			state, err := j.Load(id)
			if err != nil || !state.Committed || len(state.Segment.Events) != count {
				t.Fatalf("recovered body is not consumable: count=%d committed=%t err=%v", len(state.Segment.Events), state.Committed, err)
			}
			recovered, err := json.Marshal(state.Segment)
			if err != nil || !bytes.Equal(recovered, want) {
				t.Fatalf("recovery changed event bytes or first acceptance time: %v", err)
			}
			cursor, err = j.LoadSource(segment.Source, segment.SourcePath)
			if err != nil || cursor.Offset != segment.EndOffset || cursor.LastSegmentID != id {
				t.Fatalf("recovery failed to commit exact source position: %+v %v", cursor, err)
			}
			if err := j.Release(id); err != ErrUnconfirmed {
				t.Fatalf("recovered unconfirmed body can be released: %v", err)
			}
		})
	}
}

func TestJournalEncodedBodyRejectsBoundsBeforePersistence(t *testing.T) {
	for _, kind := range []string{"events", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			j, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			segment := encodingSegment(1)
			if kind == "events" {
				segment = encodingSegment(MaxSegmentEvents + 1)
			} else {
				segment.Events[0].Payload["oversized"] = strings.Repeat("x", MaxSegmentBytes)
			}
			if _, err := j.Append(segment); err != ErrSegmentTooLarge {
				t.Fatalf("oversized %s accepted: %v", kind, err)
			}
			entries, err := os.ReadDir(j.dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("oversized body left persistent files: %v %v", entries, err)
			}
		})
	}
}

// This measures local encoding/allocation plus the unchanged filesystem
// durability operations. It does not represent production storage throughput.
func BenchmarkJournalAppendThousandEvents(b *testing.B) {
	j, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	segment := encodingSegment(MaxSegmentEvents)
	encoded, err := json.Marshal(segment)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(encoded)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id, err := j.Append(segment)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := os.Remove(j.path(id, ".segment")); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}
