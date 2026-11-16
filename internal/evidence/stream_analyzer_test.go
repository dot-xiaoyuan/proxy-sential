package evidence

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestFixedWindowStreamAnalyzerMatchesReplayAcrossPagesAndLateEvents(t *testing.T) {
	asOf := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	events := []normalized.Event{
		{EventID: "old", Timestamp: asOf.Add(-11 * time.Minute).Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"origin": "ttl", "ttl": 63}, Flow: map[string]any{"direction": "outbound"}},
		{EventID: "new-a", Timestamp: asOf.Add(-8 * time.Minute).Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": "192.0.2.8", "account_id": "account-a", "mac": "02:00:00:00:00:08", "entity_role": "endpoint"}, Payload: map[string]any{"origin": "ttl", "ttl": 63}, Flow: map[string]any{"direction": "outbound"}},
		{EventID: "new-b", Timestamp: asOf.Add(-time.Minute).Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": "192.0.2.8", "account_id": "account-a", "mac": "02:00:00:00:00:09", "entity_role": "endpoint"}, Payload: map[string]any{"origin": "ttl", "ttl": 126}, Flow: map[string]any{"direction": "outbound"}},
		{EventID: "new-a", Timestamp: asOf.Add(-8 * time.Minute).Format(time.RFC3339Nano), Type: "device", Subject: map[string]any{"ip": "192.0.2.8"}},
	}
	var input bytes.Buffer
	stream, err := NewFixedWindowStreamAnalyzer(Options{Window: 10 * time.Minute, AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if err := json.NewEncoder(&input).Encode(event); err != nil {
			t.Fatal(err)
		}
		if err := stream.Add(event); err != nil {
			t.Fatal(err)
		}
	}
	want, err := Analyze(&input, Options{Window: 10 * time.Minute, AsOf: asOf})
	if err != nil {
		t.Fatal(err)
	}
	got := stream.Result()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("streaming risk evidence changed replay semantics\n got=%+v\nwant=%+v", got, want)
	}
}
