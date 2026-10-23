package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/airelay"
)

func TestAIRelayUsageQueryBoundsAndDomainRules(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	q := AIRelayUsageQuery{From: now.Add(-time.Hour), To: now, IP: "10.20.0.11", Domain: "yunwu.ai", CampusID: "main", SensorID: "zeek-1", Limit: 20}
	sql, err := relayRowsSQL(q)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"ai_relay_domain_matches_v1", "subject_ip='10.20.0.11'", "campus_id='main'", "sensor_id='zeek-1'", "endsWith(domain,'.yunwu.ai')", "domain NOT IN"} {
		if part == "uniqExact" {
			continue
		}
		if !strings.Contains(sql, part) {
			t.Errorf("query missing %q", part)
		}
	}
	matcher := airelay.Default()
	for _, host := range []string{"api.yunwu.ai", "yunwu.ai"} {
		if _, ok := matcher.Match(host); !ok {
			t.Errorf("expected match for %s", host)
		}
	}
	for _, host := range []string{"notyunwu.ai", "yunwu.ai.evil.example", "api.openai.com"} {
		if _, ok := matcher.Match(host); ok {
			t.Errorf("unexpected match for %s", host)
		}
	}
	for _, bad := range []AIRelayUsageQuery{{From: now.Add(-8 * 24 * time.Hour), To: now}, {From: now, To: now}, {From: q.From, To: q.To, IP: "bad-ip"}, {From: q.From, To: q.To, Cursor: "bad-cursor"}} {
		if _, err := relayRowsSQL(bad); err == nil {
			t.Errorf("accepted invalid query: %+v", bad)
		}
	}
}

func TestAIRelayUsageListReadsPageAndDetails(t *testing.T) {
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		query := string(body)
		queries = append(queries, query)
		if strings.Contains(query, "LIMIT 10 BY ip") {
			_, _ = io.WriteString(w, `{"ip":"10.0.0.1","event_id":"e1","timestamp":"2026-10-21T01:00:00Z","domain":"openrouter.ai","source":"handshake_tls","sensor_id":"s1"}`+"\n")
			return
		}
		_, _ = io.WriteString(w, `{"ip":"10.0.0.1","first_seen":"2026-10-21T00:00:00Z","last_seen":"2026-10-21T01:00:00Z","event_count":2,"domains":["openrouter.ai"],"total":3}`+"\n")
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 2, 0, 0, 0, time.UTC)
	page, err := store.ListAIRelayUsage(context.Background(), AIRelayUsageQuery{From: now.Add(-time.Hour), To: now, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "count() OVER() AS total") || !strings.Contains(queries[1], "subject_ip IN ('10.0.0.1')") || page.Page.Total != 3 || len(page.Items) != 1 || len(page.Items[0].Events) != 1 || page.Items[0].DomainNames["openrouter.ai"] != "OpenRouter 聚合站" {
		t.Fatalf("queries=%d page=%+v", len(queries), page)
	}
}

func TestAIRelayUsageRowDecoding(t *testing.T) {
	var items []AIRelayUsage
	err := decodeAIRelayRows([]byte(`{"ip":"10.0.0.1","first_seen":"2026-10-21T00:00:00Z","last_seen":"2026-10-21T01:00:00Z","event_count":2,"domains":["api.yunwu.ai"],"total":3}`+"\n"), &items)
	if err != nil || len(items) != 1 || items[0].EventCount != 2 || items[0].FirstSeen == "" || items[0].total != 3 {
		t.Fatalf("decode: %+v %v", items, err)
	}
	var events []struct {
		IP string
		AIRelayEvent
	}
	err = decodeAIRelayRows([]byte(`{"ip":"10.0.0.1","event_id":"e1","timestamp":"2026-10-21T01:00:00Z","domain":"api.yunwu.ai","source":"tls","sensor_id":"s1"}`+"\n"), &events)
	if err != nil || len(events) != 1 || events[0].EventID != "e1" {
		t.Fatalf("event decode: %+v %v", events, err)
	}
}
