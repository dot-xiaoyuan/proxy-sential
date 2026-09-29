package devicesignal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestTTLCollectorScopeAndRestartIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	values := map[bucketKey]int{{IP: "192.168.1.2", MAC: "02:00:00:00:00:01", Direction: "outbound", Version: 4, TTL: 63}: 10}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "lab", CollectorInstanceID: "first", CampusID: "campus", AccessDomain: "nas", ValidFrom: now, ValidUntil: now.Add(time.Hour)}
	ids := map[string]bool{}
	for _, instance := range []string{"first", "second"} {
		file := filepath.Join(t.TempDir(), "signals.jsonl")
		if err := writeBucketWithScope(file, "lab", "eth0", instance, scope, now, values); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var event normalized.Event
		if err = json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		if ids[event.EventID] {
			t.Fatal("collector restart reused event ID")
		}
		ids[event.EventID] = true
		if event.Observer["collector_instance_id"] != instance {
			t.Fatal(event)
		}
		if instance == "first" {
			if event.Subject["campus_id"] != "campus" {
				t.Fatal(event)
			}
		} else if event.Subject["campus_id"] != nil || event.Observer["capture_scope_issue"] == nil {
			t.Fatal("restart inherited invalid mapping", event)
		}
	}
}
