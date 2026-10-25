package zeek

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestControlledZeekFileBindingSuppliesCaptureInterface(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "zeek-owner", CampusID: "site-a", AccessDomain: "bond0-router-minimal", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	raw := fmt.Sprintf(`{"ts":%d,"client_addr":"192.0.2.82","server_addr":"192.0.2.1","mac":"02:00:00:00:00:82","assigned_addr":"192.0.2.82"}`+"\n", now.Unix())
	var output bytes.Buffer
	stats, err := Convert(bytes.NewBufferString(raw), &output, Options{SensorID: "sensor-a", LogKind: "dhcp", CollectorInstanceID: "zeek-owner", CaptureScope: scope, ControlledInterface: "bond0"})
	if err != nil || stats.Emitted != 1 {
		t.Fatalf("Zeek capture binding failed: %+v %v", stats, err)
	}
	var event normalized.Event
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Observer["capture_scope_issue"] != nil || event.Observer["interface"] != "bond0" || event.Observer["capture_scope_id"] == nil {
		t.Fatalf("controlled Zeek source lost scope: %+v", event.Observer)
	}
}

func TestControlledZeekFileBindingRejectsConflictingScopedInterface(t *testing.T) {
	now := time.Now().UTC()
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "zeek-owner", CampusID: "site-a", AccessDomain: "bond0-router-minimal", InterfaceName: "bond1", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	var output bytes.Buffer
	if _, err := Convert(bytes.NewBufferString(""), &output, Options{SensorID: "sensor-a", LogKind: "dhcp", CollectorInstanceID: "zeek-owner", CaptureScope: scope, ControlledInterface: "bond0"}); err == nil {
		t.Fatal("conflicting Zeek interface binding was accepted")
	}
}

func TestDHCPDiscoverWithoutAddressRetainsMACOnlyObservation(t *testing.T) {
	raw := `{"ts":1792890000,"mac":"02:00:00:00:00:83","msg_types":["DISCOVER","DISCOVER"]}` + "\n"
	var output bytes.Buffer
	stats, err := Convert(bytes.NewBufferString(raw), &output, Options{SensorID: "sensor-a", LogKind: "dhcp"})
	if err != nil || stats.Emitted != 1 || stats.Skipped != 0 {
		t.Fatalf("MAC-only DHCP request was dropped: %+v %v", stats, err)
	}
	var event normalized.Event
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Subject["ip"] != nil || event.Subject["mac"] != "02:00:00:00:00:83" || event.SourceEventType != "dhcp" {
		t.Fatalf("DHCP request gained an address or lost its MAC: %+v", event.Subject)
	}
}

func TestDHCPWithoutAddressOrMACRemainsRejected(t *testing.T) {
	raw := `{"ts":1792890000,"msg_types":["DISCOVER"]}` + "\n"
	var output bytes.Buffer
	stats, err := Convert(bytes.NewBufferString(raw), &output, Options{SensorID: "sensor-a", LogKind: "dhcp"})
	if err != nil || stats.Emitted != 0 || stats.Skipped != 1 {
		t.Fatalf("unidentified DHCP request was accepted: %+v %v", stats, err)
	}
}
