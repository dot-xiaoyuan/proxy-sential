package realtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/streamlog"
)

func TestVerifiedDHCPMessageSourcePreservesRequestAsMACClue(t *testing.T) {
	line := []byte("{\"ts\":1789537676.8,\"mac\":\"02:00:00:00:00:10\",\"requested_addr\":\"192.168.1.12\",\"msg_types\":\"REQUEST\",\"vendor_class\":\"MSFT 5.0\"}\n")
	events, stats, err := normalize(Source{Kind: "zeek-dhcp-binding", Path: "/logs/current/device_dhcp_message.log"}, line, 0, "sensor-a", nil)
	if err != nil || stats.Emitted != 1 || len(events) != 1 || events[0].Payload["request_only"] != true || events[0].Subject["ip"] != nil {
		t.Fatalf("message source lost non-binding request: %+v, %+v, %v", events, stats, err)
	}
}

func TestVerifiedDHCPMessageCaptureCommitsSourcePositionAndRawProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_dhcp_message.log")
	raw := []byte("{\"ts\":1789537676.8,\"mac\":\"02:00:00:00:00:10\",\"requested_addr\":\"192.168.1.12\",\"msg_types\":\"REQUEST\",\"vendor_class\":\"MSFT 5.0\"}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	j.SetRawResolver(func(streamlog.Segment) ([]byte, error) { return append([]byte(nil), raw...), nil })
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-message", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), ParserVersion: "zeek-dhcp-message-v1", KeyScheme: "generation-v2", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if err != nil || !captured {
		t.Fatalf("per-message capture failed: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Committed || !state.Segment.SourceBackedRaw || state.Segment.ParserVersion != "zeek-dhcp-message-v1" || len(state.Segment.Events) != 1 || state.Segment.Events[0].Payload["request_only"] != true {
		t.Fatalf("per-message segment lost raw proof or request: %+v %v", state, err)
	}
	cursor, err := j.LoadSource(source.Kind, path)
	if err != nil || cursor.Offset != int64(len(raw)) || cursor.LastSegmentID != id {
		t.Fatalf("per-message cursor did not follow durable segment: %+v %v", cursor, err)
	}
}
