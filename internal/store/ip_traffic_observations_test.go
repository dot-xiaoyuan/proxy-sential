package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIPTrafficObservationsUseCurrentSourceAndExactIP(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	from := time.Date(2026, 10, 26, 6, 40, 0, 0, time.UTC)
	cutoff := from.Add(time.Minute)
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-a", SHA256: strings.Repeat("a", 64)}
	encoded, _ := json.Marshal(ref)
	row := map[string]any{"observed_at": from.Add(2 * time.Minute).Format(time.RFC3339Nano), "event_key": ref.Key, "content_sha256": ref.SHA256,
		"scope_id": ref.Scope, "protocol": "handshake", "event_type": "device", "source": "handshake-sidecar", "sensor_id": "sensor-a",
		"subject_ip": "10.157.2.191", "archive_month": 202610, "retention_class": ref.Class, "body_ref": string(encoded)}
	var sql string
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		sql = string(body)
		_ = json.NewEncoder(w).Encode(row)
	}))
	defer server.Close()
	ch, _ := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	s := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
	query := IPTrafficObservationQuery{SensorID: "sensor-a", IP: "10.157.2.191", SourceOwner: "handshake-sidecar", From: from, To: from.Add(15 * time.Minute), Limit: 20}
	expectSource := func() {
		mock.ExpectQuery(`SELECT s.epoch,s.scope_id,s.source_cutoff_at,c.state`).WithArgs("sensor-a", "handshake-sidecar").
			WillReturnRows(sqlmock.NewRows([]string{"epoch", "scope", "cutoff", "state"}).AddRow("fresh", "scope-a", cutoff, "active"))
	}
	expectSource()
	page, err := s.ListIPTrafficObservations(context.Background(), query)
	if err != nil || page.Status != "ready" || len(page.Items) != 1 || !page.From.Equal(cutoff) || page.Source == nil || page.Source.Epoch != "fresh" {
		t.Fatalf("current traffic page=%+v err=%v", page, err)
	}
	for _, clause := range []string{"subject_ip='10.157.2.191'", "sensor_id='sensor-a'", "startsWith(event_key,'fresh:')", "protocol IN ('handshake','ttl','hop_limit')", "max_rows_to_read=1000000", "LIMIT 21"} {
		if !strings.Contains(sql, clause) {
			t.Fatalf("missing query boundary %q: %s", clause, sql)
		}
	}
	if strings.Contains(sql, "stream_event_body") {
		t.Fatal("list fetched full bodies")
	}
	row["subject_ip"] = "10.157.2.192"
	expectSource()
	if _, err := s.ListIPTrafficObservations(context.Background(), query); err == nil {
		t.Fatal("accepted evidence from another IP")
	}
	query.To = cutoff
	expectSource()
	page, err = s.ListIPTrafficObservations(context.Background(), query)
	if err != nil || page.Status != "before_cutover" || calls != 2 {
		t.Fatalf("pre-cutover history treated as current: %+v %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIPTrafficObservationsRejectUnboundedQueriesAndSurfaceMissingSource(t *testing.T) {
	from := time.Now().UTC()
	base := IPTrafficObservationQuery{SensorID: "sensor-a", IP: "2001:db8::1", SourceOwner: "packet-sidecar", From: from, To: from.Add(15 * time.Minute), Limit: 20}
	for _, change := range []func(*IPTrafficObservationQuery){
		func(q *IPTrafficObservationQuery) { q.IP = "invalid" }, func(q *IPTrafficObservationQuery) { q.To = q.From.Add(24 * time.Hour) },
		func(q *IPTrafficObservationQuery) { q.Limit = 101 }, func(q *IPTrafficObservationQuery) { q.SourceOwner = "other" },
		func(q *IPTrafficObservationQuery) { q.Protocol = "dns" }, func(q *IPTrafficObservationQuery) { q.SensorID = "" },
	} {
		q := base
		change(&q)
		if err := q.Validate(); !errors.Is(err, ErrInvalidStreamEventIndexQuery) {
			t.Fatalf("accepted query %+v: %v", q, err)
		}
	}
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectQuery(`SELECT s.epoch,s.scope_id,s.source_cutoff_at,c.state`).WithArgs("sensor-a", "packet-sidecar").WillReturnRows(sqlmock.NewRows([]string{"epoch", "scope", "cutoff", "state"}))
	page, err := (&DBStore{pg: &PostgresStore{db: db}}).ListIPTrafficObservations(context.Background(), base)
	if err != nil || page.Status != "source_unavailable" || page.Items == nil {
		t.Fatalf("missing source hidden as empty traffic: %+v %v", page, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
