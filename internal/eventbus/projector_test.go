package eventbus

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestReceiptFromRecord(t *testing.T) {
	envelope := Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       "evt-1",
		EventType:     "discovery",
		SensorID:      "sensor-1",
		ScopeID:       "scope-1",
		PartitionKey:  "device-1",
		ObservedAt:    time.Date(2026, 10, 30, 5, 0, 0, 0, time.UTC),
		AcceptedAt:    time.Date(2026, 10, 30, 5, 0, 1, 0, time.UTC),
		ContentHash:   "sha256:abc",
		SegmentID:     "seg-1",
		Source:        "passive-discovery",
		SourcePath:    "packet://bond0",
		Event:         json.RawMessage(`{"type":"discovery"}`),
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
