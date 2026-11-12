package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
)

// Replay through the same source binding and realtime adapter used by ingest
// run. Zeek's per-response SNMP log has no capture-interface column.
func TestIngestZeekCaptureScopeWiring(t *testing.T) {
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, kind, instance, iface, issue string
		noScope, expired                   bool
	}{
		{name: "SNMP log without interface", kind: "zeek-snmp", instance: "zeek-boot", iface: "enp3s0f0"},
		{name: "other configured instance", kind: "zeek-snmp", instance: "other-boot", iface: "enp3s0f0", issue: "capture_scope_collector_mismatch"},
		{name: "expired mapping", kind: "zeek-snmp", instance: "zeek-boot", iface: "enp3s0f0", expired: true, issue: "capture_scope_outside_validity"},
		{name: "reported other interface", kind: "zeek-iot", instance: "zeek-boot", iface: "other0", issue: "capture_scope_interface_mismatch"},
		{name: "unconfigured scope preserves defaults", kind: "zeek-snmp", instance: "zeek-boot", noScope: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "campus-204", CollectorInstanceID: "zeek-boot", CampusID: "site-204", AccessDomain: "mirror-204", InterfaceName: "enp3s0f0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
			if tc.noScope {
				scope = nil
			} else if tc.expired {
				scope.ValidUntil = at
			}
			row := map[string]any{
				"ts": at.Unix(), "uid": "scope-response", "id.orig_h": "10.131.254.2", "id.orig_p": 50000,
				"id.resp_h": "10.131.254.3", "id.resp_p": 161, "source_h": "10.131.254.3", "source_p": 161,
				"destination_h": "10.131.254.2", "destination_p": 50000, "is_orig": false,
				"parser_version": "snmp-device/v1", "is_response": true,
				"system_description": "H3C Comware Software\r\nH3C S5570S-28S-HPWR-EI-A Switch",
				"system_object_id":   "1.3.6.1.4.1.25506.1.1",
			}
			row["snmp_varbinds"] = map[string]any{"1.3.6.1.2.1.1.1.0": row["system_description"], "1.3.6.1.2.1.1.2.0": row["system_object_id"]}
			if tc.kind == "zeek-iot" {
				row = map[string]any{"ts": at.Unix(), "ip": "10.131.254.3", "protocol": "http", "domain": "mirror-204", "interface_name": tc.iface, "parser_version": "iot-metadata-v2", "metadata": "Device HTTP server"}
			}
			raw, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "device.log")
			if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			source := bindIngestSource(realtime.Source{Kind: tc.kind, Path: path}, scope, tc.instance)
			if source.CollectorInstanceID != tc.instance {
				t.Fatalf("configured Zeek instance overwritten: %+v", source)
			}
			backend := &ingestScopeBackend{}
			if err := realtime.ProcessOnce(context.Background(), backend, realtime.Options{SensorID: "campus-204", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}, source); err != nil {
				t.Fatal(err)
			}
			if len(backend.events) != 1 {
				t.Fatalf("expected one retained event, got %d", len(backend.events))
			}
			event := backend.events[0]
			issue, _ := event.Observer["capture_scope_issue"].(string)
			iface, _ := event.Observer["interface"].(string)
			if issue != tc.issue || iface != tc.iface || event.Observer["collector_instance_id"] != tc.instance {
				t.Fatalf("scope/interface/instance was lost or overwritten: %+v", event.Observer)
			}
			if tc.issue != "" || tc.noScope {
				if event.Observer["capture_scope_id"] != nil || event.Subject["campus_id"] != nil || event.Payload["access_domain"] != nil {
					t.Fatalf("failed or absent mapping assigned scope: %+v", event)
				}
			} else if event.Observer["capture_scope_id"] != scope.ID() || event.Subject["campus_id"] != scope.CampusID || event.Payload["access_domain"] != scope.AccessDomain {
				t.Fatalf("configured scope not applied: %+v", event)
			}
			if tc.kind == "zeek-snmp" && (event.Subject["ip"] != row["source_h"] || event.Payload["system_description"] != row["system_description"] || event.RawRef["content_sha256"] == nil) {
				t.Fatalf("response identity or raw evidence changed: %+v", event)
			}
		})
	}
}

func TestIngestCaptureScopeDoesNotAssignZeekInterfaceToOtherSources(t *testing.T) {
	scope := &normalized.CaptureScope{InterfaceName: "enp3s0f0"}
	for _, kind := range []string{"suricata", "device-signals", "shared-device-signals"} {
		source := bindIngestSource(realtime.Source{Kind: kind, CollectorInstanceID: "original-instance"}, scope, "zeek-instance")
		if source.ControlledInterface != "" || source.CollectorInstanceID != "original-instance" || source.CaptureScope != scope {
			t.Fatalf("non-Zeek behavior changed: %+v", source)
		}
	}
}

type ingestScopeBackend struct{ events []normalized.Event }

func (*ingestScopeBackend) WriteCollectorRun(context.Context, store.Run) error { return nil }
func (b *ingestScopeBackend) WriteNormalizedEvents(_ context.Context, events []normalized.Event) error {
	b.events = append(b.events, events...)
	return nil
}
func (*ingestScopeBackend) WriteIngestDiagnostics(context.Context, []ingest.Diagnostic) error {
	return nil
}
func (*ingestScopeBackend) LoadIngestCheckpoint(context.Context, string, string) (ingest.Checkpoint, bool, error) {
	return ingest.Checkpoint{}, false, nil
}
func (*ingestScopeBackend) BeginIngestBatch(context.Context, ingest.Batch) error { return nil }
func (*ingestScopeBackend) CommitIngestBatch(context.Context, ingest.Batch, string) error {
	return nil
}
func (*ingestScopeBackend) FailIngestBatch(context.Context, string, error) error { return nil }
