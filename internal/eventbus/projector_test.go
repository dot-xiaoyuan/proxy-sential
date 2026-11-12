package eventbus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

func projectorTestRecord(t *testing.T, observed time.Time, offset int64) *kgo.Record {
	t.Helper()
	event := json.RawMessage(`{"event_id":"evt-proof","type":"discovery","timestamp":"` + observed.UTC().Format(time.RFC3339Nano) + `"}`)
	hash := sha256.Sum256(event)
	envelope := Envelope{
		SchemaVersion: SchemaVersion, EventID: "evt-proof", EventType: "discovery",
		SensorID: "sensor-1", ScopeID: "scope-1", PartitionKey: "device-1",
		ObservedAt: observed, AcceptedAt: observed.Add(time.Second),
		ContentHash: "sha256:" + hex.EncodeToString(hash[:]), SegmentID: "seg-proof",
		Source: "passive-discovery", SourcePath: "packet://bond0", Event: event,
	}
	raw, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &kgo.Record{Topic: "ps.discovery.events.v1", Partition: 2, Offset: offset, Value: raw}
}

func TestProjectorQuarantinesExpiredNormalizedProofWithoutSinkReceipt(t *testing.T) {
	now := time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	p := &Projector{opts: ProjectorOptions{QuarantineDir: dir}}
	old := projectorTestRecord(t, now.Add(-7*24*time.Hour), 42)
	receipt, include, err := p.receiptOrQuarantine(old, now)
	if err != nil || include || receipt.EventID != "" {
		t.Fatalf("expired normalized proof reached sink: receipt=%+v include=%t err=%v", receipt, include, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one durable gap file: entries=%v err=%v", entries, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var gap quarantinedRecord
	if err := json.Unmarshal(raw, &gap); err != nil || gap.Reason != normalizedProofWindowGapReason || gap.Offset != old.Offset || gap.ContentSHA256 == "" {
		t.Fatalf("gap audit lacks source position or reason: %+v err=%v", gap, err)
	}
	// Reconsumption after a failed sink batch must find the same immutable gap.
	if _, include, err := p.receiptOrQuarantine(old, now.Add(time.Second)); err != nil || include {
		t.Fatalf("gap replay was not idempotent: include=%t err=%v", include, err)
	}
	fresh := projectorTestRecord(t, now.Add(-time.Minute), 43)
	receipt, include, err = p.receiptOrQuarantine(fresh, now)
	if err != nil || !include || receipt.EventID != "evt-proof" {
		t.Fatalf("fresh valid event was not sent to sink: receipt=%+v include=%t err=%v", receipt, include, err)
	}
}

func TestProjectorCannotAdvancePastUnpersistedProofGap(t *testing.T) {
	now := time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)
	blocked := filepath.Join(t.TempDir(), "file-not-directory")
	if err := os.WriteFile(blocked, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &Projector{opts: ProjectorOptions{QuarantineDir: blocked}}
	old := projectorTestRecord(t, now.Add(-7*24*time.Hour), 44)
	if receipt, include, err := p.receiptOrQuarantine(old, now); err == nil || include || receipt.EventID != "" {
		t.Fatalf("unpersisted gap was allowed into a committed batch: receipt=%+v include=%t err=%v", receipt, include, err)
	}
}

func TestReceiptFromRecord(t *testing.T) {
	event := json.RawMessage(`{"event_id":"evt-1","type":"discovery","timestamp":"2026-10-30T05:00:00Z"}`)
	hash := sha256.Sum256(event)
	envelope := Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       "evt-1",
		EventType:     "discovery",
		SensorID:      "sensor-1",
		ScopeID:       "scope-1",
		PartitionKey:  "device-1",
		ObservedAt:    time.Date(2026, 10, 30, 5, 0, 0, 0, time.UTC),
		AcceptedAt:    time.Date(2026, 10, 30, 5, 0, 1, 0, time.UTC),
		ContentHash:   "sha256:" + hex.EncodeToString(hash[:]),
		SegmentID:     "seg-1",
		Source:        "passive-discovery",
		SourcePath:    "packet://bond0",
		Event:         event,
	}
	raw, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := receiptFromRecord(&kgo.Record{Value: raw, Partition: 2, Offset: 42})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.EventID != "evt-1" || receipt.DeviceKey != "device-1" || receipt.Partition != 2 || receipt.Offset != 42 {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	if string(receipt.Envelope) != string(raw) {
		t.Fatal("envelope was not preserved")
	}
}

func TestReceiptFromRecordRejectsBodyMismatch(t *testing.T) {
	event := json.RawMessage(`{"event_id":"other","type":"discovery","timestamp":"2026-10-30T05:00:00Z"}`)
	hash := sha256.Sum256(event)
	envelope := Envelope{SchemaVersion: SchemaVersion, EventID: "evt-1", EventType: "discovery", PartitionKey: "device-1", ObservedAt: time.Date(2026, 10, 30, 5, 0, 0, 0, time.UTC), ContentHash: "sha256:" + hex.EncodeToString(hash[:]), Event: event}
	raw, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiptFromRecord(&kgo.Record{Value: raw}); err == nil {
		t.Fatal("mismatched event id was accepted")
	}
}

func TestQuarantineInvalidRecordIsDurableAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	record := &kgo.Record{Topic: "ps.discovery.events.v1", Partition: 2, Offset: 42, Value: []byte("invalid")}
	path, err := quarantineInvalidRecord(dir, record, "invalid JSON")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quarantineInvalidRecord(dir, record, "invalid JSON"); err != nil {
		t.Fatalf("replayed quarantine record: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Fatal("quarantine escaped its directory")
	}
	record.Value = []byte("different")
	if _, err := quarantineInvalidRecord(dir, record, "invalid JSON"); err == nil {
		t.Fatal("same position with conflicting content was accepted")
	}
}

func TestReceiptFromRecordRejectsBadEnvelope(t *testing.T) {
	cases := [][]byte{
		[]byte(`not-json`),
		[]byte(`{"schema_version":1,"event_id":"evt"}`),
		[]byte(`{"schema_version":2,"event_id":"evt","partition_key":"dev","observed_at":"2026-10-30T05:00:00Z"}`),
	}
	for _, raw := range cases {
		if _, err := receiptFromRecord(&kgo.Record{Value: raw}); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}

func TestProjectorOptionsValidation(t *testing.T) {
	valid := ProjectorOptions{
		Brokers: []string{"127.0.0.1:9092"}, Topic: "topic", Group: "group",
		BatchSize: 100, FetchMaxBytes: 1 << 20, FlushInterval: time.Second,
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Group = ""
	if err := invalid.validate(); err == nil {
		t.Fatal("expected missing group error")
	}
}
