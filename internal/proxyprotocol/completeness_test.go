package proxyprotocol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

func TestConnectCompletionRequiresBothTimes(t *testing.T) {
	for _, mode := range []string{"missing-request", "missing-both", "invalid-request", "missing-response", "invalid-response", "reversed", "response-after-observed", "success", "failure", "equal-times", "suricata-single-record", "suricata-partial-time", "suricata-wrong-parser", "suricata-invalid-times"} {
		t.Run(mode, func(t *testing.T) {
			e, p := fixture()
			e.Source, p.Source, p.ParserID = "zeek", "zeek", "sentinel-zeek-proxy"
			want := "incomplete"
			switch mode {
			case "missing-request":
				delete(e.Payload, "request_at")
			case "missing-both":
				delete(e.Payload, "request_at")
				delete(e.Payload, "response_at")
			case "invalid-request":
				e.Payload["request_at"] = "bad-time"
			case "missing-response":
				delete(e.Payload, "response_at")
			case "invalid-response":
				e.Payload["response_at"] = "bad-time"
			case "reversed":
				e.Payload["request_at"] = e.Timestamp
				e.Payload["response_at"] = "2026-09-11T01:00:00Z"
			case "response-after-observed":
				e.Payload["response_at"] = "2026-09-11T01:00:02Z"
			case "success":
				want = "success"
			case "failure":
				e.Payload["status"] = 403
				want = "failed"
			case "equal-times":
				e.Payload["request_at"] = e.Timestamp
				want = "success"
			case "suricata-single-record", "suricata-partial-time", "suricata-wrong-parser", "suricata-invalid-times":
				p.Source, e.Source = "suricata", "suricata"
				p.ParserID = "sentinel-suricata-http"
				delete(e.Payload, "request_at")
				if mode != "suricata-partial-time" {
					delete(e.Payload, "response_at")
				}
				if mode == "suricata-wrong-parser" {
					p.ParserID = "wrong-parser"
				}
				if mode == "suricata-single-record" {
					want = "success"
				}
				if mode == "suricata-invalid-times" {
					e.Payload["request_at"] = "bad-time"
					e.Payload["response_at"] = "bad-time"
				}
			}
			Sign(&e, p)
			r := Evaluate(e, Config{Producers: []Producer{p}})
			if !r.Trusted || r.Outcome != want || want != "success" && r.Confidence != 0 {
				t.Fatalf("partial transaction confirmed: %+v want=%s", r, want)
			}
			if mode == "suricata-single-record" {
				ss := []policy.Session{{ID: "current", AccountID: "current", IP: r.IP, CampusID: "c", AccessDomain: "nas", Source: "auth", StartedAt: r.ObservedAt.Add(-time.Minute), ConfirmedAt: r.ObservedAt, HeartbeatSeconds: 60}}
				if in := Input("current", []Result{r}, ss, r.ObservedAt, time.Hour, "manual"); in.Known || in.Violated {
					t.Fatal("observation-only Suricata record assigned to current account", in)
				}
			}
		})
	}
}

func TestProxyInputRejectsIncompleteAndFuturePersistedResults(t *testing.T) {
	for _, mode := range []string{"missing-response", "missing-observed", "missing-connection", "unsupported-protocol", "future-response", "future-observed", "valid"} {
		t.Run(mode, func(t *testing.T) {
			e, p := fixture()
			Sign(&e, p)
			r := Evaluate(e, Config{Producers: []Producer{p}})
			now := r.ObservedAt
			switch mode {
			case "missing-response":
				r.ResponseAt = time.Time{}
			case "missing-observed":
				r.ObservedAt = time.Time{}
			case "missing-connection":
				r.ConnectionID = ""
			case "unsupported-protocol":
				r.Protocol = "socks_udp"
			case "future-response":
				now = r.RequestAt.Add(500 * time.Millisecond)
			case "future-observed":
				r.ObservedAt = now.Add(time.Minute)
			}
			ss := []policy.Session{{ID: "s", AccountID: "owner", IP: r.IP, CampusID: "c", AccessDomain: "nas", Source: "auth", StartedAt: r.RequestAt.Add(-time.Minute), ConfirmedAt: r.RequestAt, HeartbeatSeconds: 60}}
			in := Input("owner", []Result{r}, ss, now, time.Hour, "manual")
			if in.Violated != (mode == "valid") || in.Known != (mode == "valid") {
				t.Fatalf("invalid persisted result reached policy input: %+v mode=%s", in, mode)
			}
		})
	}
}

func TestProxyRepositoryNormalizesLegacyPartialResults(t *testing.T) {
	for _, mode := range []string{"read-existing", "commit-new", "merge-existing", "complete-correction"} {
		t.Run(mode, func(t *testing.T) {
			e, p := fixture()
			Sign(&e, p)
			complete := Evaluate(e, Config{Version: "same", Producers: []Producer{p}})
			legacy := complete
			legacy.RuleVersion = "proxy-transactions/v1"
			legacy.ResponseAt = time.Time{}
			legacy.EventIDs = []string{"legacy-event"}
			dir := t.TempDir()
			repo := OpenRepository(nil, dir)
			path := filepath.Join(dir, "results", legacy.ID+".json")
			raw, err := json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "commit-new" {
				if err := repo.Commit(context.Background(), []Result{legacy}, ScanState{}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := atomicFile(path, raw); err != nil {
					t.Fatal(err)
				}
				if mode == "merge-existing" {
					current := legacy
					current.Outcome = "incomplete"
					current.Confidence = 0
					current.EventIDs = []string{"current-event"}
					if err := repo.Commit(context.Background(), []Result{current}, ScanState{}); err != nil {
						t.Fatal(err)
					}
				} else if mode == "complete-correction" {
					if err := repo.Commit(context.Background(), []Result{complete}, ScanState{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			rows, err := OpenRepository(nil, dir).Query(context.Background(), legacy.IP, time.Time{}, 10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("read result rows=%d err=%v", len(rows), err)
			}
			want := "incomplete"
			if mode == "complete-correction" {
				want = "success"
			}
			if rows[0].Outcome != want || want == "incomplete" && rows[0].Confidence != 0 {
				t.Fatalf("legacy malformed success persisted: %+v", rows[0])
			}
			if mode == "read-existing" {
				after, err := os.ReadFile(path)
				if err != nil || string(after) != string(raw) {
					t.Fatal("read destroyed original audit document")
				}
			}
			if mode == "complete-correction" && len(rows[0].EventIDs) != 2 {
				t.Fatalf("correction discarded original evidence IDs: %+v", rows[0])
			}
		})
	}
}
