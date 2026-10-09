package proxyprotocol

import (
	"context"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func fixture() (normalized.Event, Producer) {
	p := Producer{SensorID: "s", Source: "test", InstanceID: "boot", ParserID: "parser", ParserVersion: "1", CampusID: "c", AccessDomain: "nas", Key: "01234567890123456789012345678901"}
	e := normalized.Event{SchemaVersion: "v1", EventID: "e", Type: "proxy_transaction", Source: "test", Timestamp: "2026-09-11T01:00:01Z", Observer: map[string]any{"sensor_id": "s", "collector_instance_id": "boot"}, Subject: map[string]any{"ip": "192.0.2.1"}, Flow: map[string]any{"connection_id": normalized.ConnectionID("s", "test", "boot", "conn")}, Payload: map[string]any{"protocol": "http_connect", "transaction_id": "1", "request_at": "2026-09-11T01:00:00Z", "response_at": "2026-09-11T01:00:01Z", "method": "CONNECT", "status": 200}}
	return e, p
}

func TestProducerEpochCannotTrustEarlierOrLaterLogs(t *testing.T) {
	for _, tc := range []struct {
		name, from, until, request string
		trusted                    bool
	}{
		{"current epoch", "2026-09-11T01:00:00Z", "2026-09-11T01:01:00Z", "2026-09-11T01:00:00Z", true},
		{"old log signed after restart", "2026-09-11T01:00:02Z", "2026-09-11T01:01:00Z", "2026-09-11T01:00:00Z", false},
		{"request before epoch", "2026-09-11T01:00:00Z", "2026-09-11T01:01:00Z", "2026-09-11T00:59:59Z", false},
		{"response at retired boundary", "2026-09-11T01:00:00Z", "2026-09-11T01:00:01Z", "2026-09-11T01:00:00Z", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, p := fixture()
			p.ValidFrom, _ = time.Parse(time.RFC3339Nano, tc.from)
			p.ValidUntil, _ = time.Parse(time.RFC3339Nano, tc.until)
			e.Payload["request_at"] = tc.request
			Sign(&e, p)
			r := Evaluate(e, Config{Version: "bounded", Producers: []Producer{p}})
			if r.Trusted != tc.trusted {
				t.Fatalf("trusted=%t expected=%t: %+v", r.Trusted, tc.trusted, r)
			}
			if !tc.trusted && (r.Confidence != 0 || r.CampusID != "" || r.AccessDomain != "") {
				t.Fatal("stale source received attribution", r)
			}
		})
	}
}
func TestProtocolOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, protocol   string
		status           int
		version, command int
		want             string
	}{{"connect", "http_connect", 200, 0, 0, "success"}, {"denied", "http_connect", 403, 0, 0, "failed"}, {"auth", "http_connect", 407, 0, 0, "failed"}, {"no response", "http_connect", 0, 0, 0, "incomplete"}, {"socks", "socks5", 0, 5, 1, "success"}, {"socks denied", "socks5", 5, 5, 1, "failed"}, {"socks4", "socks5", 0, 4, 1, "unsupported"}, {"udp", "socks5", 0, 5, 3, "unsupported"}} {
		t.Run(tc.name, func(t *testing.T) {
			e, p := fixture()
			e.Payload["protocol"] = tc.protocol
			e.Payload["status"] = tc.status
			e.Payload["version"] = tc.version
			e.Payload["command"] = tc.command
			if tc.protocol == "socks5" {
				e.Payload["reply"] = tc.status
			} else if tc.status == 0 {
				delete(e.Payload, "response_at")
			}
			Sign(&e, p)
			r := Evaluate(e, Config{Version: "v1", Producers: []Producer{p}})
			if r.Outcome != tc.want {
				t.Fatal(r)
			}
		})
	}
}
func TestForgedTrustMissingConnectionAndNoMerge(t *testing.T) {
	e, p := fixture()
	e.Payload["verified"] = true
	if r := Evaluate(e, Config{Producers: []Producer{p}}); r.Trusted {
		t.Fatal("self-reported trust accepted")
	}
	Sign(&e, p)
	e.Payload["status"] = 201
	if r := Evaluate(e, Config{Producers: []Producer{p}}); r.Trusted {
		t.Fatal("tampered event accepted")
	}
	e, p = fixture()
	delete(e.Flow, "connection_id")
	Sign(&e, p)
	if r := Evaluate(e, Config{Producers: []Producer{p}}); r.Outcome != "incomplete" {
		t.Fatal(r)
	}
	e, p = fixture()
	delete(e.Payload, "response_at")
	delete(e.Payload, "status")
	Sign(&e, p)
	a := Evaluate(e, Config{Producers: []Producer{p}})
	e2, p := fixture()
	delete(e2.Payload, "method")
	Sign(&e2, p)
	b := Evaluate(e2, Config{Producers: []Producer{p}})
	if Merge(a, b).Outcome == "success" {
		t.Fatal("consumer stitched partial transactions")
	}
	complete, _ := fixture()
	Sign(&complete, p)
	c := Evaluate(complete, Config{Producers: []Producer{p}})
	if Merge(a, c).Outcome != "success" || Merge(c, a).Outcome != "success" {
		t.Fatal("late completion failed")
	}
	if c.RequestAt != time.Date(2026, 9, 11, 1, 0, 0, 0, time.UTC) {
		t.Fatal(c)
	}
}

func TestAttributionExpiryAndAutomaticGate(t *testing.T) {
	e, p := fixture()
	Sign(&e, p)
	r := Evaluate(e, Config{Producers: []Producer{p}})
	now := r.ObservedAt
	ss := []policy.Session{{ID: "session", AccountID: "old", EndpointID: "device", IP: r.IP, CampusID: "c", AccessDomain: "nas", Source: "auth", StartedAt: r.RequestAt.Add(-time.Minute), ConfirmedAt: r.RequestAt, HeartbeatSeconds: 60}}
	if in := Input("old", []Result{r}, ss, now, time.Hour, "manual"); !in.Violated {
		t.Fatal(in)
	}
	if in := Input("old", []Result{r}, ss, now, time.Hour, "automatic"); in.Violated || in.Known {
		t.Fatal(in)
	}
	if in := Input("old", []Result{r}, ss, now.Add(2*time.Hour), time.Hour, "manual"); in.Violated {
		t.Fatal(in)
	}
	ss[0].EndedAt = r.RequestAt.Add(time.Second)
	next := ss[0]
	next.AccountID = "new"
	next.StartedAt = now.Add(time.Second)
	next.EndedAt = time.Time{}
	ss = append(ss, next)
	if in := Input("new", []Result{r}, ss, now.Add(2*time.Second), time.Hour, "manual"); in.Violated {
		t.Fatal("IP rebound attributed to new account")
	}
	ss[1].StartedAt = r.RequestAt.Add(-time.Minute)
	if in := Input("old", []Result{r}, ss, now, time.Hour, "manual"); in.Violated {
		t.Fatal("conflicting identity accepted")
	}
}
func TestRepositoryRestartAndLateCorrection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := OpenRepository(nil, dir)
	e, p := fixture()
	delete(e.Payload, "status")
	Sign(&e, p)
	a := Evaluate(e, Config{Version: "v1", Producers: []Producer{p}})
	state := ScanState{After: Cursor{EventID: "a"}}
	if err := repo.Commit(ctx, []Result{a}, state); err != nil {
		t.Fatal(err)
	}
	e, p = fixture()
	Sign(&e, p)
	b := Evaluate(e, Config{Version: "v1", Producers: []Producer{p}})
	if err := repo.Commit(ctx, []Result{b, a, b}, state); err != nil {
		t.Fatal(err)
	}
	repo = OpenRepository(nil, dir)
	rows, err := repo.Query(ctx, a.IP, time.Time{}, 100)
	if err != nil || len(rows) != 1 || rows[0].Outcome != "success" {
		t.Fatal(rows, err)
	}
	saved, err := repo.State(ctx)
	if err != nil || saved.After.EventID != "a" {
		t.Fatal(saved, err)
	}
}

func TestNoCrossConnectionOrInstanceMerge(t *testing.T) {
	a, p := fixture()
	delete(a.Payload, "status")
	delete(a.Payload, "response_at")
	Sign(&a, p)
	left := Evaluate(a, Config{Producers: []Producer{p}})
	b, _ := fixture()
	b.Flow["connection_id"] = "another-connection"
	Sign(&b, p)
	right := Evaluate(b, Config{Producers: []Producer{p}})
	if Merge(left, right).Outcome == "success" {
		t.Fatal("cross connection merge")
	}
	b, _ = fixture()
	b.Observer["collector_instance_id"] = "next-boot"
	p.InstanceID = "next-boot"
	Sign(&b, p)
	right = Evaluate(b, Config{Producers: []Producer{p}})
	if Merge(left, right).Outcome == "success" {
		t.Fatal("cross boot merge")
	}
}
func TestCompleteTransactionConflictAndRequestTime(t *testing.T) {
	e, p := fixture()
	Sign(&e, p)
	a := Evaluate(e, Config{Producers: []Producer{p}})
	e.Payload["status"] = 403
	Sign(&e, p)
	b := Evaluate(e, Config{Producers: []Producer{p}})
	if r := Merge(a, b); r.Outcome != "conflict" || r.Confidence != 0 {
		t.Fatal(r)
	}
	e, p = fixture()
	delete(e.Payload, "response_at")
	Sign(&e, p)
	if r := Evaluate(e, Config{Producers: []Producer{p}}); r.Outcome != "incomplete" {
		t.Fatal(r)
	}
}
