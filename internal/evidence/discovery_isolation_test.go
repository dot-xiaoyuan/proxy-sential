package evidence

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoveryDoesNotShiftRiskWindow(t *testing.T) {
	base := normalizedLine("tls-a", "tls", map[string]any{"ja3": "a"}, map[string]any{}) + "\n" + normalizedLine("tls-b", "tls", map[string]any{"ja3": "b"}, map[string]any{}) + "\n"
	a, e := Analyze(strings.NewReader(base), Options{})
	if e != nil {
		t.Fatal(e)
	}
	event := normalized.Event{SchemaVersion: "v1", EventID: "discovery-future", Type: "discovery", Timestamp: "2099-01-01T00:00:00Z", Subject: map[string]any{"ip": "192.0.2.1", "mac": "00:11:22:33:44:55"}, Payload: map[string]any{"origin": "neighbor", "ttl": 900}}
	var b bytes.Buffer
	b.WriteString(base)
	_ = json.NewEncoder(&b).Encode(event)
	after, e := Analyze(&b, Options{})
	if e != nil {
		t.Fatal(e)
	}
	if a.MaxTime != after.MaxTime || !reflect.DeepEqual(a.Evidence, after.Evidence) {
		t.Fatal("discovery changed risk window or evidence")
	}
}
