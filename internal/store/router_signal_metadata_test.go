package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRouterSignalBatchPreservesCursorOnInvalidMetadata(t *testing.T) {
	for _, mode := range []string{"null", "empty", "valid", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("nullable observer crashed router recognition: %v", value)
				}
			}()
			stamp := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			first := routerSignalRow{Timestamp: stamp.Format(time.RFC3339Nano), EventID: "good", SensorID: "office", SubjectIP: "192.0.2.22", Source: "zeek", SourceEventType: "dhcp", ObserverJSON: `{"sensor_id":"wrong","collector_instance_id":"boot-1"}`, PayloadJSON: `{"vendor_class":"ZTE SR7410-20"}`, FlowJSON: `{}`}
			second := first
			second.Timestamp = stamp.Add(time.Second).Format(time.RFC3339Nano)
			second.EventID = "second"
			switch mode {
			case "null":
				second.ObserverJSON = "null"
			case "empty":
				second.ObserverJSON = ""
			case "valid":
				second.ObserverJSON = `{"sensor_id":"wrong","collector_instance_id":"boot-2"}`
			case "invalid":
				second.ObserverJSON = `{"collector_instance_id":`
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(first)
				json.NewEncoder(w).Encode(second)
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			cursor := routerRecognitionCursor{Timestamp: stamp.Add(-time.Second), EventID: "before", Owner: "worker"}
			events, next, err := (&DBStore{ch: ch}).routerSignalBatch(context.Background(), "office", cursor, 100)
			if mode == "invalid" {
				if err == nil || len(events) != 0 || next != cursor {
					t.Fatalf("invalid metadata advanced cursor or silently passed: events=%d next=%+v err=%v", len(events), next, err)
				}
				return
			}
			if err != nil || len(events) != 2 || next.EventID != "second" {
				t.Fatalf("valid optional metadata stopped processing: %d %+v %v", len(events), next, err)
			}
			for _, event := range events {
				if event.Observer["sensor_id"] != "office" {
					t.Fatalf("metadata replaced canonical scope: %+v", event.Observer)
				}
			}
			if mode == "valid" && events[1].Observer["collector_instance_id"] != "boot-2" {
				t.Fatalf("lost instance attribution: %+v", events[1].Observer)
			}
		})
	}
}
