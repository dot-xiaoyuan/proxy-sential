package suricata

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func TestAdapterControlledScope(t *testing.T) {
	at := time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SensorID: "lab", CollectorInstanceID: "boot", CampusID: "campus", AccessDomain: "nas", ValidFrom: at, ValidUntil: at.Add(time.Hour)}
	raw := `{"timestamp":"2026-09-15T07:01:00Z","event_type":"http","src_ip":"192.0.2.1","dest_ip":"198.51.100.1","http":{"hostname":"campus.test","http_method":"GET"}}`
	for _, instance := range []string{"boot", "restarted"} {
		var out bytes.Buffer
		stats, err := Convert(strings.NewReader(raw), &out, Options{SensorID: "lab", CollectorInstanceID: instance, CaptureScope: scope})
		if err != nil || stats.Emitted != 1 {
			t.Fatal(stats, err)
		}
		var event normalized.Event
		if err = json.Unmarshal(out.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if instance == "boot" {
			if event.Subject["campus_id"] != "campus" || event.Payload["access_domain"] != "nas" {
				t.Fatal(event)
			}
		} else if event.Subject["campus_id"] != nil || event.Observer["capture_scope_issue"] == nil {
			t.Fatal("restarted capture inherited identity", event)
		}
	}
}
