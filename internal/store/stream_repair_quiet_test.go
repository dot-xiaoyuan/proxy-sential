package store

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxy-sentinel/internal/streamlog"
)

func TestRequireQuietStreamRepairWaitsForTransientSharedQueue(t *testing.T) {
	queueChecks, processChecks := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.Contains(query, "FROM system.asynchronous_inserts"):
			queueChecks++
			if queueChecks == 1 {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(query, "FROM system.processes"):
			processChecks++
			_, _ = io.WriteString(w, "0\n")
		default:
			t.Errorf("unexpected quiet proof query: %q", query)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.requireQuietStreamRepair(context.Background(), []string{"stream_event_body_evidence"}); err != nil {
		t.Fatalf("transient shared queue did not drain: %v", err)
	}
	if queueChecks != 3 || processChecks != 2 {
		t.Fatalf("repair did not require two quiet scans: queue=%d process=%d", queueChecks, processChecks)
	}
}

func TestRequireQuietStreamRepairReportsPersistentSharedTableActivity(t *testing.T) {
	for _, test := range []struct {
		name, busyQuery, want string
	}{
		{"queued", "FROM system.asynchronous_inserts", "asynchronous_insert_batches=1"},
		{"active", "FROM system.processes", "active_inserts=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), test.busyQuery) {
					_, _ = io.WriteString(w, "1\n")
				} else {
					_, _ = io.WriteString(w, "0\n")
				}
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			err = ch.requireQuietStreamRepair(context.Background(), []string{"stream_event_body_evidence"})
			if !errors.Is(err, streamlog.ErrUnconfirmed) || !strings.Contains(err.Error(), "table=stream_event_body_evidence") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("persistent activity was not diagnosed safely: %v", err)
			}
		})
	}
}
