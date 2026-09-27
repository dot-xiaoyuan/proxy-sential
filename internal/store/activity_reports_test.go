package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestActivityReportAggregatesInClickHouseAndKeepsUnknown(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query = string(body)
		if strings.Contains(query, "activity_rollup_refreshes") || strings.Contains(query, "SELECT count() AS count FROM activity_rollup_10m") {
			_, _ = w.Write([]byte("{\"count\":1}\n"))
			return
		}
		_, _ = w.Write([]byte("{\"key\":\"http2\",\"label\":\"http2\",\"count\":8,\"total_count\":10,\"unknown_count\":2,\"last_seen\":\"2026-09-03 10:00:00.000000\"}\n{\"key\":\"未知\",\"label\":\"未知\",\"count\":2,\"total_count\":10,\"unknown_count\":2,\"last_seen\":\"2026-09-03 10:00:00.000000\"}\n"))
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.QueryActivityReport(context.Background(), ActivityReportQuery{ActivityQuery: ActivityQuery{Window: "1h", SensorID: "campus-a", AsOf: "2026-09-03T10:00:00Z"}, Dimension: "application", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 10 || report.ClassifiedCount != 8 || report.UnknownCount != 2 || len(report.Items) != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, expected := range []string{"FROM activity_rollup_10m", "dimension='application'", "UNION ALL", "normalized_events_canonical FINAL", "GROUP BY value", "LIMIT 10"} {
		if !strings.Contains(query, expected) {
			t.Fatalf("missing %q in query: %s", expected, query)
		}
	}
}

func TestClickHouseTimestampPreservesUTCInstant(t *testing.T) {
	if got := clickHouseTimestamp("2026-09-27T10:00:00Z"); got != "2026-09-27 18:00:00.000000" {
		t.Fatalf("wrong Shanghai timestamp: %s", got)
	}
}

func TestActivityReportRejectsUnknownDimension(t *testing.T) {
	store, _ := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:1"})
	if _, err := store.QueryActivityReport(context.Background(), ActivityReportQuery{ActivityQuery: ActivityQuery{Window: "1h"}, Dimension: "unsupported"}); err == nil {
		t.Fatal("expected unsupported dimension error")
	}
}
