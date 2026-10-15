package zeek

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
)

func TestIoTMetadataScopeAndCredentials(t *testing.T) {
	row := map[string]any{"ts": 1789707600, "ip": "10.1.2.3", "domain": "mirror0", "interface_name": "bond0", "protocol": "mqtt", "parser_version": "iot-metadata-v2", "metadata": `{"device":{"manufacturer":"Test","model":"S1","password":"secret","identifiers":["00:11:22:33:44:55"]},"value":123,"password":"secret"}`}
	raw, _ := json.Marshal(row)
	var out bytes.Buffer
	stats, e := Convert(bytes.NewReader(raw), &out, Options{SensorID: "n1", LogKind: "iot"})
	if e != nil || stats.Emitted != 1 {
		t.Fatalf("%+v %v", stats, e)
	}
	if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "123") {
		t.Fatal("unrestricted MQTT contents persisted")
	}
	var event normalized.Event
	if e = json.Unmarshal(out.Bytes(), &event); e != nil {
		t.Fatal(e)
	}
	if event.Subject["ip"] != "10.1.2.3" || event.Payload["product_verified"] == true {
		t.Fatal("forwarded declaration assumed hardware identity")
	}
	for _, field := range []string{"domain", "interface_name", "parser_version"} {
		copy := map[string]any{}
		for k, v := range row {
			copy[k] = v
		}
		delete(copy, field)
		raw, _ = json.Marshal(copy)
		out.Reset()
		stats, e = Convert(bytes.NewReader(raw), &out, Options{SensorID: "n1", LogKind: "iot"})
		if e != nil || stats.Emitted != 0 {
			t.Fatal("unscoped metadata admitted")
		}
	}
}
