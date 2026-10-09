package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func TestProxyReviewIdentityUsesObservedTime(t *testing.T) {
	identity := func(id, stamp, account, endpoint string) normalized.Event {
		return proxyTestEvent(id, "identity", stamp, map[string]any{"ip": "192.0.2.82", "account_id": account, "endpoint_id": endpoint}, nil, nil)
	}
	traffic := func(id, stamp string) normalized.Event {
		return proxyTestEvent(id, "tls", stamp, map[string]any{"ip": "192.0.2.82"}, nil, map[string]any{"sni": "vpn.example.test"})
	}
	old := identity("old", "2026-10-01T01:00:00Z", "old-account", "old-endpoint")
	next := identity("next", "2026-10-01T02:00:00Z", "next-account", "next-endpoint")
	before := traffic("before", "2026-10-01T01:30:00Z")
	after := traffic("after", "2026-10-01T02:30:00Z")
	for _, mode := range []string{"future", "historical", "mixed", "partial", "timezone", "sensor", "campus", "logout", "conflicting_explicit", "interval_change", "same_time_conflict"} {
		t.Run(mode, func(t *testing.T) {
			events := []normalized.Event{old, before, next}
			account, endpoint := "old-account", "old-endpoint"
			switch mode {
			case "future":
				events = []normalized.Event{before, next}
				account, endpoint = "", ""
			case "mixed":
				events = append(events, after)
				account, endpoint = "", ""
			case "partial":
				events = []normalized.Event{traffic("no-owner", "2026-10-01T00:30:00Z"), old, before}
				account, endpoint = "", ""
			case "timezone":
				events = []normalized.Event{identity("old", "2026-10-01T09:00:00+08:00", account, endpoint), before, identity("next", "2026-10-01T02:00:00Z", "next-account", "next-endpoint")}
			case "sensor", "campus":
				other := identity("other", "2026-10-01T01:20:00Z", "other-account", "other-endpoint")
				if mode == "sensor" {
					other.Observer["sensor_id"] = "other-sensor"
				} else {
					other.Subject["campus_id"] = "other-campus"
				}
				events = []normalized.Event{old, other, before}
			case "logout":
				stop := identity("stop", "2026-10-01T01:20:00Z", account, endpoint)
				stop.Payload = map[string]any{"session_status": "stop"}
				events = []normalized.Event{old, stop, before}
				account, endpoint = "", ""
			case "conflicting_explicit":
				explicit := traffic("explicit", before.Timestamp)
				explicit.Subject["account_id"] = "explicit-account"
				events = []normalized.Event{old, explicit}
				account, endpoint = "explicit-account", ""
			case "interval_change":
				span := traffic("span", after.Timestamp)
				span.Flow = map[string]any{"start": before.Timestamp, "end": after.Timestamp}
				events = []normalized.Event{old, next, span}
				account, endpoint = "", ""
			case "same_time_conflict":
				other := identity("other", old.Timestamp, "other-account", "other-endpoint")
				events = []normalized.Event{old, other, before}
				account, endpoint = "", ""
			}
			result := BuildProxyReviewResponse("office-30", "7d", events, nil)
			if len(result.Items) != 1 || result.Items[0].AccountID != account || result.Items[0].EndpointID != endpoint {
				t.Fatalf("incorrect event-time owner (%s/%s): %+v", account, endpoint, result)
			}
			if result.Items[0].CaseID != proxyReviewCaseID("192.0.2.82") {
				t.Fatal("identity changes broke stable detail URL")
			}
		})
	}
}

func TestProxyReviewAggregateRetainsSubjectAndScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		group := strings.SplitN(string(query), "GROUP BY ", 2)
		if len(group) != 2 {
			t.Error("review query did not aggregate")
		} else {
			for _, column := range []string{"sensor_id", "campus_id", "account_id", "endpoint_id"} {
				if !strings.Contains(strings.SplitN(group[1], "ORDER BY", 2)[0], column) {
					t.Errorf("aggregation merged distinct %s", column)
				}
			}
		}
		fmt.Fprintln(w, `{"first_seen":"2026-10-01T01:00:00Z","last_seen":"2026-10-01T01:01:00Z","event_id":"a","type":"tls","subject_ip":"192.0.2.82","sensor_id":"sensor-a","campus_id":"campus-a","account_id":"account-a","endpoint_id":"endpoint-a","aggregate_count":2}`)
		fmt.Fprintln(w, `{"first_seen":"2026-10-01T02:00:00Z","last_seen":"2026-10-01T02:01:00Z","event_id":"b","type":"tls","subject_ip":"192.0.2.82","sensor_id":"sensor-b","campus_id":"campus-b","account_id":"account-b","endpoint_id":"endpoint-b","aggregate_count":3}`)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	events, err := ch.ListProxyReviewEvents(context.Background(), "", 7*24*time.Hour, 5000)
	if err != nil || len(events) != 2 {
		t.Fatalf("aggregate decode: events=%d err=%v", len(events), err)
	}
	for i, expected := range []string{"a", "b"} {
		if stringFromMap(events[i].Subject, "account_id") != "account-"+expected || stringFromMap(events[i].Subject, "endpoint_id") != "endpoint-"+expected || stringFromMap(events[i].Subject, "campus_id") != "campus-"+expected || stringFromMap(events[i].Observer, "sensor_id") != "sensor-"+expected {
			t.Errorf("aggregate lost subject/scope: %+v", events[i])
		}
	}
	result := BuildProxyReviewResponse("", "7d", events, nil)
	if len(result.Items) != 1 || result.EventCount != 5 || result.Items[0].AccountID != "" || result.Items[0].EndpointID != "" || result.Items[0].ReviewStatus != "needs_more_data" || result.Items[0].ReviewReason == "" {
		t.Fatalf("mixed owners were silently presented as one owner: %+v", result)
	}
}

func TestProxyReviewRiskDoesNotCrossSubjects(t *testing.T) {
	for _, mode := range []string{"account_alias", "endpoint_alias", "wrong_ip", "bound_ip_other_owner", "matching_account", "matching_endpoint", "matching_ip", "legacy_ip"} {
		t.Run(mode, func(t *testing.T) {
			item := ProxyReviewCase{IP: "192.0.2.82"}
			snapshot := risk.Snapshot{IP: item.IP, SubjectType: "account", SubjectID: "other", AccountID: "other", Score: 95, Level: "confirmed", EvidenceIDs: []string{"other-owner-evidence"}}
			want := false
			switch mode {
			case "endpoint_alias":
				snapshot.SubjectType, snapshot.SubjectID, snapshot.AccountID, snapshot.EndpointID = "endpoint", "other-endpoint", "", "other-endpoint"
			case "wrong_ip":
				item.AccountID = "other"
				snapshot.IP = "192.0.2.83"
			case "bound_ip_other_owner":
				snapshot.SubjectType, snapshot.SubjectID = "ip", item.IP
			case "matching_account":
				item.AccountID, want = "other", true
			case "matching_endpoint":
				snapshot.SubjectType, snapshot.SubjectID, snapshot.AccountID, snapshot.EndpointID = "endpoint", "other-endpoint", "", "other-endpoint"
				item.EndpointID, want = "other-endpoint", true
			case "matching_ip":
				snapshot.SubjectType, snapshot.SubjectID, snapshot.AccountID, want = "ip", item.IP, "", true
			case "legacy_ip":
				snapshot.SubjectType, snapshot.SubjectID, snapshot.AccountID, want = "", "", "", true
			}
			_, got := proxyReviewRisk(item, ProxyReviewRiskMap([]risk.Snapshot{snapshot}))
			if got != want {
				t.Fatalf("risk crossed owner/IP boundary: got=%v want=%v snapshot=%+v", got, want, snapshot)
			}
		})
	}
}
