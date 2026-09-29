package normalized

import (
	"testing"
	"time"
)

func TestCaptureScopeDoesNotRelabelHistoryOrCollector(t *testing.T) {
	now := time.Now().UTC()
	scope := &CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "s", CollectorInstanceID: "boot", CampusID: "campus", AccessDomain: "nas", ValidFrom: now, ValidUntil: now.Add(time.Hour)}
	event := Event{EventID: "one", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "s", "collector_instance_id": "boot"}, Subject: map[string]any{"ip": "192.0.2.1"}, Payload: map[string]any{}}
	good := scope.Apply(event)
	if good.Subject["campus_id"] != "campus" || good.Observer["capture_scope_id"] == nil {
		t.Fatal(good)
	}
	if event.Subject["campus_id"] != nil {
		t.Fatal("mutated original event")
	}
	old := event
	old.Timestamp = now.Add(-time.Second).Format(time.RFC3339Nano)
	if got := scope.Apply(old); got.Subject["campus_id"] != nil || got.Observer["capture_scope_issue"] != "capture_scope_outside_validity" {
		t.Fatal(got)
	}
	end := event
	end.Timestamp = scope.ValidUntil.Format(time.RFC3339Nano)
	if got := scope.Apply(end); got.Observer["capture_scope_issue"] == nil {
		t.Fatal("end boundary accepted")
	}
	reboot := event
	reboot.Observer = map[string]any{"sensor_id": "s", "collector_instance_id": "new-boot"}
	if got := scope.Apply(reboot); got.Subject["campus_id"] != nil || got.Observer["capture_scope_issue"] == nil {
		t.Fatal(got)
	}
	conflict := event
	conflict.Subject = map[string]any{"campus_id": "other"}
	if got := scope.Apply(conflict); got.Subject["campus_id"] != "other" || got.Observer["capture_scope_issue"] == nil {
		t.Fatal(got)
	}
}
