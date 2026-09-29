package suricata

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"testing"
)

func TestConnectKeepsHTTPAndDoesNotInventRequestTime(t *testing.T) {
	cfg, err := proxyprotocol.Load("../../../examples/proxy-protocol/producers.example.json")
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"timestamp":"2026-09-11T01:00:00Z","flow_id":123,"tx_id":0,"event_type":"http","src_ip":"192.0.2.1","dest_ip":"198.51.100.1","http":{"http_method":"CONNECT","status":200}}`
	var out bytes.Buffer
	stats, err := Convert(bytes.NewBufferString(raw), &out, Options{SensorID: "replay", CollectorInstanceID: "replay-boot", ProxyProducer: cfg.Producer("replay", "suricata", "replay-boot")})
	if err != nil || stats.Emitted != 2 {
		t.Fatal(stats, err)
	}
	dec := json.NewDecoder(&out)
	var original, e normalized.Event
	dec.Decode(&original)
	dec.Decode(&e)
	r := proxyprotocol.Evaluate(e, cfg)
	if original.Type != "http" || r.Outcome != "success" || !r.Trusted || !r.RequestAt.IsZero() {
		t.Fatal(original, r)
	}
	if proxyprotocol.Attribute(r, nil).Attribution.State != "unknown" {
		t.Fatal("invented attribution")
	}
}
