package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

func TestReadStreamSharedCaseRefsRequiresEveryIndexedOriginal(t *testing.T) {
	for _, indexed := range []bool{true, false} {
		t.Run(fmt.Sprint(indexed), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			decision := `{"evidence":{"id":"observation","sensor_id":"sensor","campus_id":"campus","access_domain":"bond0","ip":"10.0.0.2","from":"2026-10-25T11:59:00Z","to":"2026-10-25T12:00:00Z","source_epochs":{"handshake-sidecar":"fresh"},"source_scopes":{"handshake-sidecar":"scope"},"records":[{"event_id":"one","source":"handshake-sidecar","collector_instance_id":"collector"}]}}`
			mock.ExpectQuery("SELECT d.document FROM policy_decision_records").WithArgs("observation", "generation").WillReturnRows(sqlmock.NewRows([]string{"document"}).AddRow([]byte(decision)))
			ref := StreamBodyRef{Epoch: "fresh", Class: "evidence", Month: "202610", Scope: "scope", Key: "fresh:one", SHA256: strings.Repeat("a", 64)}
			refJSON, _ := json.Marshal(ref)
			var lookup string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query, _ := io.ReadAll(r.Body)
				lookup = string(query)
				if !indexed {
					return
				}
				row, _ := json.Marshal(map[string]any{"observed_at": "2026-10-25T11:59:30Z", "indexed_at": "2026-10-25T11:59:31Z", "event_key": ref.Key,
					"source": "handshake-sidecar", "protocol": "handshake", "sensor_id": "sensor", "campus_id": "campus", "access_domain": "bond0", "subject_ip": "10.0.0.2", "subject_mac": "", "collector_instance_id": "collector", "scope_id": "scope", "content_sha256": ref.SHA256, "archive_month": 202610, "retention_class": "evidence", "body_ref": string(refJSON)})
				_, _ = w.Write(append(row, '\n'))
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			got, err := (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).ReadStreamSharedCaseRefs(context.Background(), "observation", "generation")
			if indexed && (err != nil || len(got) != 1 || got[0] != ref) {
				t.Fatalf("indexed ref=%+v err=%v", got, err)
			}
			if !indexed && !errors.Is(err, streamlog.ErrUnconfirmed) {
				t.Fatalf("missing original accepted: %v", err)
			}
			if !strings.Contains(lookup, "event_key IN ('fresh:one')") || !strings.Contains(lookup, "LIMIT 201") {
				t.Fatalf("case source lookup was not exact and bounded: %s", lookup)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadStreamSharedCaseRefsRejectsUnboundedSnapshot(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var records []map[string]string
	for i := 0; i < 101; i++ {
		records = append(records, map[string]string{"event_id": fmt.Sprintf("e%d", i), "source": "handshake-sidecar", "collector_instance_id": "collector"})
	}
	decision, _ := json.Marshal(map[string]any{"evidence": map[string]any{"id": "observation", "sensor_id": "sensor", "campus_id": "campus", "access_domain": "bond0", "ip": "10.0.0.2", "from": time.Date(2026, 10, 25, 11, 59, 0, 0, time.UTC), "to": time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), "source_epochs": map[string]string{"handshake-sidecar": "fresh"}, "source_scopes": map[string]string{"handshake-sidecar": "scope"}, "records": records}})
	mock.ExpectQuery("SELECT d.document FROM policy_decision_records").WillReturnRows(sqlmock.NewRows([]string{"document"}).AddRow(decision))
	if _, err := (&DBStore{pg: &PostgresStore{db: db}, ch: &ClickHouseStore{}}).ReadStreamSharedCaseRefs(context.Background(), "observation", "generation"); err == nil {
		t.Fatal("unbounded case original copy was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
