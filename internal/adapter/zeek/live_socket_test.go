package zeek

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
)

// An optional fixture is a capture of real private sockets, never business traffic.
func TestProxyLiveSocketReplay(t *testing.T) {
	dir := os.Getenv("PROXY_SENTINEL_TEST_LIVE_PROXY_DIR")
	if dir == "" {
		t.Skip("real socket fixture not supplied")
	}
	var manifest struct {
		Cases []struct {
			Name     string   `json:"name"`
			Expected []string `json:"expected"`
		} `json:"cases"`
		UIDCases map[string]string `json:"uid_cases"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "proxy_transactions.log"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := proxyprotocol.Config{Version: "private-loopback-fixture", Producers: []proxyprotocol.Producer{{
		SensorID: "replay", Source: "zeek", InstanceID: "replay-boot", ParserID: "sentinel-zeek-proxy", ParserVersion: "1",
		CampusID: "fixture-campus", AccessDomain: "fixture-access", Key: "private-fixture-key-32-bytes-only-tests",
	}}}
	var out bytes.Buffer
	_, err = Convert(bytes.NewReader(raw), &out, Options{SensorID: "replay", CollectorInstanceID: "replay-boot", LogKind: "proxy", ProxyProducer: cfg.Producer("replay", "zeek", "replay-boot")})
	if err != nil {
		t.Fatal(err)
	}
	merged := map[string]proxyprotocol.Result{}
	names := map[string]string{}
	dec := json.NewDecoder(&out)
	for dec.More() {
		var e normalized.Event
		if err = dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		uid := proxyprotocol.Text(e.RawRef, "uid")
		name, ok := manifest.UIDCases[uid]
		if !ok {
			t.Fatalf("unmapped transaction UID %s", uid)
		}
		r := proxyprotocol.Evaluate(e, cfg)
		if !r.Trusted {
			t.Fatalf("serialized fixture lost signature: %s", r.Reason)
		}
		names[r.ID] = name
		merged[r.ID] = proxyprotocol.Merge(merged[r.ID], r)
	}
	actual := map[string][]string{}
	for id, r := range merged {
		in := proxyprotocol.Input("fixture-account", []proxyprotocol.Result{r}, nil, time.Now(), 24*time.Hour, "manual")
		if in.Known || in.Violated {
			t.Fatal("unattributed fixture became account policy input", in)
		}
		actual[names[id]] = append(actual[names[id]], r.Outcome)
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, want := actual[c.Name], append([]string(nil), c.Expected...)
			sort.Strings(got)
			sort.Strings(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("real socket transactions: got %v, want %v", got, want)
			}
		})
	}
}
