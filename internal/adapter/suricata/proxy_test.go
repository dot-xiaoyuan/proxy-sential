package suricata

import (
	"bytes"
	"encoding/json"
	"math"
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

func TestConnectDoesNotEmitAnUnsignedTransactionAfterSigningFailure(t *testing.T) {
	p := proxyprotocol.Producer{ParserID: "sentinel-suricata-http", ParserVersion: "1", Key: "01234567890123456789012345678901"}
	e := normalized.Event{Type: "http", Flow: map[string]any{"src_ip": "192.0.2.1"}, Payload: map[string]any{"method": "CONNECT", "status": 200}, RawRef: map[string]any{"tx_id": "1", "extra": math.NaN()}}
	if transaction, ok, err := proxyTransaction(e, Options{ProxyProducer: &p}); err == nil || ok || transaction.Type != "" {
		t.Fatal("adapter published an unsigned transaction after an encoding error")
	}
	// Other HTTP methods still follow their original path; no proxy signing is
	// attempted merely because an unrelated record carries unusual metadata.
	e.Payload["method"] = "GET"
	if _, ok, err := proxyTransaction(e, Options{ProxyProducer: &p}); err != nil || ok {
		t.Fatal("ordinary HTTP was routed through proxy signing")
	}
}
