package suricata

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"testing"
)

func TestLargeFlowIDAndInstance(t *testing.T) {
	var out bytes.Buffer
	_, err := Convert(bytes.NewBufferString(`{"timestamp":"2026-09-08T10:00:00Z","flow_id":18446744073709551615,"event_type":"tls","src_ip":"10.0.0.1","dest_ip":"1.1.1.1","tls":{"sni":"example.com"}}`), &out, Options{SensorID: "s", CollectorInstanceID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	var e normalized.Event
	if err = json.Unmarshal(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Flow["connection_id"] != normalized.ConnectionID("s", "suricata", "boot", "18446744073709551615") {
		t.Fatalf("flow precision lost: %+v", e)
	}
}
