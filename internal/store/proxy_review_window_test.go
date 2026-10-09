package store

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDatabaseProxyReviewSupportsAutomaticTenMinuteWindow(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "INTERVAL 10 MINUTE") {
			t.Errorf("wrong rolling interval: %s", body)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", "postgres://unused:unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s := &DBStore{ch: ch, pg: &PostgresStore{db: db, sensorID: "test"}}
	_, err = s.GetProxyReviews(context.Background(), ActivityQuery{Window: "10m"})
	if !called || err == nil || strings.Contains(err.Error(), "window must") {
		t.Fatalf("automatic rolling window rejected before query: called=%v err=%v", called, err)
	}
}
