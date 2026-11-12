package eventbus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type replaySink struct {
	calls int
	last  Receipt
	err   error
}

func (s *replaySink) WriteReceipts(_ context.Context, receipts []Receipt) error {
	s.calls++
	if len(receipts) == 1 {
		s.last = receipts[0]
	}
	return s.err
}

func validQuarantineRecord(t *testing.T) *kgo.Record {
	t.Helper()
	event := json.RawMessage(`{"event_id":"replay-1","type":"discovery","timestamp":"2026-11-12T03:00:00Z"}`)
	hash := sha256.Sum256(event)
	envelope := Envelope{SchemaVersion: SchemaVersion, EventID: "replay-1", EventType: "discovery", PartitionKey: "device-1",
		ObservedAt: time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC), AcceptedAt: time.Date(2026, 11, 12, 3, 0, 1, 0, time.UTC),
		ContentHash: "sha256:" + hex.EncodeToString(hash[:]), SegmentID: "segment-1", Source: "passive-discovery", SourcePath: "packet://bond0", Event: event}
	raw, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &kgo.Record{Topic: DefaultDiscoveryTopic, Partition: 2, Offset: 42, Value: raw}
}

func TestReplayQuarantineVerifiesPositionHashAndAuditsOnlySuccess(t *testing.T) {
	dir := t.TempDir()
	record := validQuarantineRecord(t)
	path, err := quarantineInvalidRecord(dir, record, "old parser rejected")
	if err != nil {
		t.Fatal(err)
	}
	sink := &replaySink{}
	items, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", []string{filepath.Base(path)}, sink)
	if err != nil || len(items) != 1 || items[0].Status != "applied" || sink.calls != 1 || sink.last.Offset != 42 {
		t.Fatalf("replay failed: items=%+v calls=%d err=%v", items, sink.calls, err)
	}
	if _, err := os.Stat(path + ".replay.normalized-only.json"); err != nil {
		t.Fatalf("audit missing: %v", err)
	}
	items, err = ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", []string{filepath.Base(path)}, sink)
	if err != nil || len(items) != 1 || items[0].Status != "already_applied" || sink.calls != 1 {
		t.Fatalf("audited replay repeated sink: %+v calls=%d err=%v", items, sink.calls, err)
	}
	if err := os.WriteFile(path, []byte(`{"topic":"tampered"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", []string{filepath.Base(path)}, sink); err == nil {
		t.Fatal("tampered quarantine replayed")
	}
}

func TestReplayQuarantineRejectsTraversalAndUnboundedBatch(t *testing.T) {
	dir := t.TempDir()
	sink := &replaySink{}
	if _, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", []string{"../elsewhere.json"}, sink); err == nil {
		t.Fatal("traversal accepted")
	}
	names := make([]string, 33)
	for i := range names {
		names[i] = "x.json"
	}
	if _, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", names, sink); err == nil {
		t.Fatal("unbounded batch accepted")
	}
}

func TestReplayQuarantineKeepsFailedSinkAndChecksSourceOffset(t *testing.T) {
	dir := t.TempDir()
	path, err := quarantineInvalidRecord(dir, validQuarantineRecord(t), "old parser rejected")
	if err != nil {
		t.Fatal(err)
	}
	sink := &replaySink{err: errors.New("sink unavailable")}
	name := filepath.Base(path)
	if _, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", []string{name}, sink); err == nil {
		t.Fatal("failed sink reported replay success")
	}
	if _, err := os.Stat(path + ".replay.normalized-only.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed sink wrote audit: %v", err)
	}
	sink.err = nil
	if _, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", []string{name}, sink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "full", []string{name}, sink); err != nil {
		t.Fatal(err)
	}
	if sink.calls != 3 {
		t.Fatalf("different sink mode incorrectly reused prior audit: %d", sink.calls)
	}
	var entry quarantinedRecord
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	entry.Offset++
	raw, _ = json.Marshal(entry)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayQuarantinedRecords(context.Background(), dir, DefaultDiscoveryTopic, "normalized-only", []string{name}, sink); err == nil {
		t.Fatal("source offset tampering passed audit")
	}
}
