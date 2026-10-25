package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func testStreamSegment() streamlog.Segment {
	return streamlog.Segment{
		Epoch: "fresh", Source: "zeek-dhcp", SourcePath: "/logs/dhcp.log", FileID: "file-1",
		PreviousFileID: "file-1", PreviousOffset: 0,
		StartOffset: 0, EndOffset: 100, ParserVersion: "zeek-v1", ArchiveMonth: "202610",
		AcceptedAt: time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC), NeedsProjection: true,
		Events: []normalized.Event{{EventID: "e1", Timestamp: "2026-10-24T10:00:00Z", Source: "zeek", Type: "discovery", Observer: map[string]any{"capture_scope_id": "scope"}}},
	}
}

func TestStreamLanePreflightRejectsInvalidLocalArchiveWithoutSink(t *testing.T) {
	segment := testStreamSegment()
	segment.Events[0].Timestamp = "bad-time"
	writer := StreamLaneWriter{}
	if err := writer.Preflight(streamlog.Archive, segment); err == nil {
		t.Fatal("invalid timestamp passed archive preflight")
	}
	segment.Events[0].Timestamp = "2026-10-24T10:00:00Z"
	segment.Raw = []byte("unverified source")
	segment.RawSHA256 = "wrong"
	if err := writer.Preflight(streamlog.Archive, segment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("unverified source reached archive sink: %v", err)
	}
	segment.Raw = nil
	if err := writer.Preflight(streamlog.Archive, segment); err != nil {
		t.Fatalf("valid local archive rejected: %v", err)
	}
}

func TestStreamLaneWriterNeverAcknowledgesMissingProjection(t *testing.T) {
	writer := StreamLaneWriter{}
	segment := streamlog.Segment{NeedsProjection: true}
	if err := writer.Project(context.Background(), "segment", segment); !errors.Is(err, ErrStreamProjectorUnavailable) {
		t.Fatalf("missing projector acknowledged: %v", err)
	}
	if err := writer.ReconcileProjection(context.Background(), "segment", segment); !errors.Is(err, ErrStreamProjectorUnavailable) {
		t.Fatalf("missing projector reconciled: %v", err)
	}
}

type recordingRiskQueue struct{ calls int }

func (r *recordingRiskQueue) MarkStreamRiskSubjectsDirty(context.Context, string, streamlog.Segment) error {
	r.calls++
	return nil
}

type recordingSharedQueue struct{ calls int }

func (r *recordingSharedQueue) MarkStreamSharedJobs(context.Context, string, streamlog.Segment) error {
	r.calls++
	return nil
}

func TestStreamSidecarCannotFinalizeWithoutSharedJobQueue(t *testing.T) {
	segment := streamlog.Segment{Epoch: "fresh", Source: "device-signals", SourcePath: "/signals/handshake.jsonl", Events: []normalized.Event{{Source: "handshake-sidecar", SourceEventType: "handshake", Type: "device"}}}
	if err := (StreamLaneWriter{}).FinalizeSegment(context.Background(), "segment-a", segment); !errors.Is(err, ErrStreamProjectorUnavailable) {
		t.Fatalf("shared signal lost without durable job: %v", err)
	}
	queue := &recordingSharedQueue{}
	if err := (StreamLaneWriter{SharedQueue: queue}).FinalizeSegment(context.Background(), "segment-a", segment); err != nil || queue.calls != 1 {
		t.Fatalf("shared signal queue failed: calls=%d err=%v", queue.calls, err)
	}
}

func TestStreamRiskQueueIsRequiredEvenWithoutDeviceProjection(t *testing.T) {
	segment := riskFeatureTestSegment()
	segment.Events[0].Type = "http"
	segment.NeedsProjection = false
	if err := (StreamLaneWriter{}).FinalizeSegment(context.Background(), "segment-a", segment); !errors.Is(err, ErrStreamProjectorUnavailable) {
		t.Fatalf("unprojected protocol event lost its risk wake: %v", err)
	}
	queue := &recordingRiskQueue{}
	if err := (StreamLaneWriter{RiskQueue: queue}).FinalizeSegment(context.Background(), "segment-a", segment); err != nil || queue.calls != 1 {
		t.Fatalf("independent protocol risk wake failed: calls=%d err=%v", queue.calls, err)
	}
}

func TestStreamLaneWriterDrainsBodyAndSearchWithoutNormalLookup(t *testing.T) {
	segment := testStreamSegment()
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		queries = append(queries, string(data))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment.NeedsProjection = false
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	if err := (streamlog.Processor{Journal: j, Writer: StreamLaneWriter{ClickHouse: ch}}).Drain(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.HasPrefix(queries[0], "INSERT INTO stream_event_body_evidence") || !strings.HasPrefix(queries[1], "INSERT INTO stream_event_search") {
		t.Fatalf("unexpected sink path: %v", queries)
	}
}

func TestStreamLaneWriterDoesNotReplayAnUnknownClickHouseWrite(t *testing.T) {
	segment := testStreamSegment()
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	present := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(string(query), "SELECT") {
			t.Errorf("ambiguous write was resent: %s", query)
			return
		}
		if !present {
			return
		}
		row := map[string]any{"scope_id": prepared[0].scope, "event_key": prepared[0].key,
			"content_sha256": prepared[0].hash, "archive_month": uint32(202610), "retention_class": "evidence"}
		encoded, _ := json.Marshal(row)
		_, _ = w.Write(append(encoded, '\n'))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	writer := StreamLaneWriter{ClickHouse: ch}
	for _, check := range []func(context.Context, string, streamlog.Segment) error{writer.ReconcileBody, writer.ReconcileSearch} {
		if err := check(context.Background(), "segment", segment); !errors.Is(err, streamlog.ErrUnconfirmed) {
			t.Fatalf("missing result was replayed or acknowledged: %v", err)
		}
	}
	present = true
	for _, check := range []func(context.Context, string, streamlog.Segment) error{writer.ReconcileBody, writer.ReconcileSearch} {
		if err := check(context.Background(), "segment", segment); err != nil {
			t.Fatalf("late flush was not reconciled: %v", err)
		}
	}
}
