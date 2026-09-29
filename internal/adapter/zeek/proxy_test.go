package zeek

import (
	"bytes"
	"encoding/json"
	"os"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"testing"
)

func TestProxyPacketReplay(t *testing.T) {
	path := os.Getenv("PROXY_SENTINEL_TEST_ZEEK_PROXY_LOG")
	if path == "" {
		path = "../../../examples/proxy-protocol/zeek-replay.jsonl"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := proxyprotocol.Load("../../../examples/proxy-protocol/producers.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	stats, err := Convert(bytes.NewReader(raw), &out, Options{SensorID: "replay", CollectorInstanceID: "replay-boot", LogKind: "proxy", ProxyProducer: cfg.Producer("replay", "zeek", "replay-boot")})
	if err != nil || stats.Emitted != 14 {
		t.Fatal(stats, err)
	}
	decoder := json.NewDecoder(&out)
	merged := map[string]proxyprotocol.Result{}
	for decoder.More() {
		var e normalized.Event
		if err = decoder.Decode(&e); err != nil {
			t.Fatal(err)
		}
		r := proxyprotocol.Evaluate(e, cfg)
		if !r.Trusted {
			t.Fatal("signature failed after serialization", r)
		}
		merged[r.ID] = proxyprotocol.Merge(merged[r.ID], r)
	}
	counts := map[string]int{}
	for _, r := range merged {
		counts[r.Outcome]++
	}
	if len(merged) != 8 || counts["success"] != 2 || counts["failed"] != 3 || counts["incomplete"] != 2 || counts["unsupported"] != 1 {
		t.Fatal(counts)
	}
}
