package realtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPassiveHardwareResponsesThroughIngestCheckpoint(t *testing.T) {
	for _, kind := range []string{"snmp", "bacnet", "modbus"} {
		t.Run(kind, func(t *testing.T) {
			port := 161
			if kind == "bacnet" {
				port = 47808
			}
			if kind == "modbus" {
				port = 502
			}
			row := map[string]any{"ts": 1785232800.25, "uid": "passive-response", "id.orig_h": "192.0.2.2", "id.orig_p": 50000, "id.resp_h": "192.0.2.9", "id.resp_p": port, "source_h": "192.0.2.9", "source_p": port, "destination_h": "192.0.2.2", "destination_p": 50000, "is_orig": false}
			switch kind {
			case "snmp":
				row["parser_version"], row["is_response"] = "snmp-device/v1", true
				row["system_object_id"], row["system_description"] = "1.3.6.1.4.1.52674.500.1", "NetBotz Environment Sensor"
				row["snmp_varbinds"] = map[string]string{"1.3.6.1.2.1.1.1.0": "NetBotz Environment Sensor", "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.52674.500.1"}
			case "bacnet":
				row["pdu_service"], row["object_type"], row["instance_number"] = "read-property-ack", "device", 101
				row["property"], row["value"] = "model-name", "Watchdog Test Controller"
			case "modbus":
				row["request_response"], row["mei_type"] = "RESPONSE", "READ-DEVICE-IDENTIFICATION"
				row["object_id_code"], row["object_value"], row["unit"] = "0x05", "Watchdog Test Controller", 1
			}
			raw, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), kind+".log")
			if err = os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			backend := &fakeBackend{}
			opts := Options{SensorID: "hardware-replay", MaxBatchBytes: 8192, StoreTimeout: time.Second}
			source := Source{Kind: "zeek-" + kind, Path: path}
			if err = ProcessOnce(context.Background(), backend, opts, source); err != nil {
				t.Fatal(err)
			}
			if len(backend.events) != 1 {
				t.Fatalf("emitted %d events", len(backend.events))
			}
			event := backend.events[0]
			if event.Subject["ip"] != "192.0.2.9" || event.Subject["mac"] != nil || event.SourceEventType != kind || event.Payload["is_response"] != true {
				t.Fatalf("response identity changed through ingestion: %+v", event)
			}
			if event.RawRef["content_sha256"] == "" || event.Timestamp != "2026-07-28T10:00:00.25Z" {
				t.Fatalf("lost event time/reference: %+v", event)
			}
			if err = ProcessOnce(context.Background(), backend, opts, source); err != nil {
				t.Fatal(err)
			}
			if len(backend.events) != 1 {
				t.Fatal("checkpoint replay duplicated an event")
			}
		})
	}
}
