package store

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/normalized"
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

func TestDHCPHeaderConflictSurvivesDeviceAndRouterProjection(t *testing.T) {
	const rejected = "02:00:00:00:00:11"
	const verified = "02:00:00:00:00:22"
	var input, events bytes.Buffer
	for _, option := range []string{"", verified} {
		row := map[string]any{"ts": 1789537676.8, "msg_types": "ACK", "assigned_addr": "192.0.2.10",
			"htype": 6, "hlen": 6, "mac": rejected, "client_chaddr": rejected}
		if option != "" {
			row["client_id_hwtype"], row["client_id_hwaddr"] = 1, option
		}
		if err := json.NewEncoder(&input).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := zeek.Convert(&input, &events, zeek.Options{LogKind: "dhcp-message", SensorID: "office"})
	if err != nil || stats.Emitted != 2 {
		t.Fatalf("converted %v, %v", stats, err)
	}
	var rows []routerSignalRow
	decoder := json.NewDecoder(&events)
	for _, want := range []string{"", verified} {
		var event normalized.Event
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		var signal string
		for _, draft := range signalDrafts(event) {
			if draft.kind == "mac" {
				signal = draft.value
			}
		}
		if signal != want {
			t.Fatalf("inventory MAC = %q, want %q", signal, want)
		}
		raw, err := json.Marshal(event.Payload)
		if err != nil {
			t.Fatal(err)
		}
		mac, _ := event.Subject["mac"].(string)
		rows = append(rows, routerSignalRow{Timestamp: event.Timestamp, EventID: event.EventID, SensorID: "office", Source: event.Source,
			SourceEventType: event.SourceEventType, Type: event.Type, SubjectMAC: mac, PayloadJSON: string(raw)})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, row := range rows {
			json.NewEncoder(w).Encode(row)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	published, _, err := (&DBStore{ch: ch}).routerSignalBatch(context.Background(), "office", routerRecognitionCursor{}, 10)
	if err != nil || len(published) != 2 {
		t.Fatalf("router input count=%d err=%v", len(published), err)
	}
	if published[0].Subject["mac"] != nil || published[1].Subject["mac"] != verified || published[0].Payload["client_chaddr"] != rejected {
		t.Fatalf("router replaced the selected identity or lost original evidence: %+v", published)
	}
}
