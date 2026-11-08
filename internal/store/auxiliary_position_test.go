package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/pagination"
)

func TestAuxiliaryStreamPositionReadsOnlyKeysAndRejectsEmptyTargetPage(t *testing.T) {
	from := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	query := StreamEventIndexQuery{ScopeID: "scope-a", Protocol: "ssdp", From: from, To: from.Add(time.Minute), Limit: 20}
	response := `{"observed_at":"2026-11-06T00:00:30Z","event_key":"event-20","content_sha256":"` + strings.Repeat("a", 64) + `"}`
	var statement string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		statement = string(b)
		io.WriteString(w, response)
	}))
	defer server.Close()
	s, _ := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if _, err := s.PositionStreamEventIndex(context.Background(), query, 2); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("full previous page was accepted as an existing next page: %v", err)
	}
	response += "\n" + strings.ReplaceAll(strings.ReplaceAll(response, "event-20", "event-21"), "00:00:30", "00:00:29")
	position, err := s.PositionStreamEventIndex(context.Background(), query, 2)
	if err != nil {
		t.Fatal(err)
	}
	var cursor streamIndexCursor
	raw, _ := base64.RawURLEncoding.DecodeString(position.Cursor)
	json.Unmarshal(raw, &cursor)
	if cursor.Key != "event-20" || cursor.Filter != streamIndexFilter(query) || position.Page != 2 {
		t.Fatalf("wrong boundary: %+v %+v", position, cursor)
	}
	if !strings.Contains(statement, "LIMIT 2 OFFSET 19") || strings.Contains(statement, "body_ref") || strings.Contains(statement, "stream_event_body") {
		t.Fatalf("position read payloads or wrong page: %s", statement)
	}
}

func TestAuxiliaryRelayPositionPreservesScopeAndUsesIPBoundary(t *testing.T) {
	now := time.Now().UTC()
	q := AIRelayUsageQuery{From: now.Add(-time.Hour), To: now, Domain: "yunwu.ai", SensorID: "sensor-a", Limit: 20}
	var statement string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		statement = string(b)
		io.WriteString(w, "{\"ip\":\"192.0.2.20\"}\n{\"ip\":\"192.0.2.21\"}\n")
	}))
	defer server.Close()
	s, _ := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	p, err := s.PositionAIRelayUsage(context.Background(), q, 2)
	if err != nil || p.Cursor != "192.0.2.20" {
		t.Fatalf("position=%+v err=%v", p, err)
	}
	for _, want := range []string{"sensor_id='sensor-a'", "domain='yunwu.ai'", "LIMIT 2 OFFSET 19"} {
		if !strings.Contains(statement, want) {
			t.Fatalf("missing %s: %s", want, statement)
		}
	}
	if strings.Contains(statement, "LIMIT 10 BY") || strings.Contains(statement, "groupUniqArray") {
		t.Fatalf("position loaded detail content: %s", statement)
	}
}

func TestAuxiliaryEndpointPositionUsesSnapshotAndRejectsMissingTarget(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &PostgresStore{db: db}
	at := time.Now().UTC()
	q := EndpointObservationQuery{Kind: "ip", Limit: 20, AsOf: at.Format(time.RFC3339Nano)}
	mock.ExpectQuery("SELECT record_id,observed_at FROM").WithArgs("mac:00:11:22:33:44:55", "ip", "", "", nil, nil, q.AsOf, int64(19)).WillReturnRows(sqlmock.NewRows([]string{"record_id", "observed_at"}).AddRow("lease:20", at.Add(-time.Minute)))
	if _, err := s.PositionEndpointObservations(context.Background(), "mac:00:11:22:33:44:55", q, 2); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("accepted empty target: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuxiliaryEndpointPositionRoundTripsSnapshotAndFilters(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &PostgresStore{db: db}
	at := time.Now().UTC()
	q := EndpointObservationQuery{Kind: "account", Value: "teacher", Source: "radius", Limit: 2, AsOf: at.Format(time.RFC3339Nano)}
	mock.ExpectQuery("SELECT record_id,observed_at FROM").WithArgs("endpoint-a", "account", "teacher", "radius", nil, nil, q.AsOf, int64(1)).WillReturnRows(sqlmock.NewRows([]string{"record_id", "observed_at"}).AddRow("session:2", at.Add(-time.Minute)).AddRow("session:3", at.Add(-2*time.Minute)))
	p, err := s.PositionEndpointObservations(context.Background(), "endpoint-a", q, 2)
	if err != nil {
		t.Fatal(err)
	}
	q.Cursor = p.Cursor
	if err := ValidateEndpointObservationQuery("endpoint-a", &q); err != nil {
		t.Fatal(err)
	}
	q.AsOf = at.Add(time.Second).Format(time.RFC3339Nano)
	if err := ValidateEndpointObservationQuery("endpoint-a", &q); err == nil {
		t.Fatal("accepted a cursor from a different snapshot")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuxiliaryRiskPositionKeepsCutoverAndRejectsFullPreviousPage(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &PostgresStore{db: db}
	cutoff := time.Now().UTC().Add(-time.Hour)
	mock.ExpectQuery("SELECT accepted_after").WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}).AddRow(cutoff))
	mock.ExpectQuery("SELECT c.level,c.score,c.subject_id").WithArgs("sensor-a", "account", cutoff, "high", int64(19)).WillReturnRows(sqlmock.NewRows([]string{"level", "score", "subject_id"}).AddRow("high", 70, "account-20"))
	if _, err := s.PositionStreamRiskCurrent(context.Background(), "sensor-a", "account", "high", 2, 20); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("accepted empty risk page: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuxiliaryStreamMetadataCountsDeduplicatedKeysWithoutBodies(t *testing.T) {
	from := time.Now().UTC()
	q := StreamEventIndexQuery{ScopeID: "scope-a", SensorID: "sensor-a", SubjectIP: "192.0.2.1", Epoch: "epoch-a", ObservationOnly: true, From: from, To: from.Add(time.Minute), Limit: 20}
	var statement string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		statement = string(b)
		io.WriteString(w, `{"total":23}`)
	}))
	defer server.Close()
	s, _ := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	metadata, err := s.StreamEventIndexMetadata(context.Background(), q)
	if err != nil || metadata.Total != 23 || metadata.AsOf.IsZero() {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	for _, want := range []string{"uniqExact(tuple(observed_at,event_key,content_sha256))", "subject_ip='192.0.2.1'", "startsWith(event_key,'epoch-a:')", "sensor_id='sensor-a'", "read_overflow_mode='throw'"} {
		if !strings.Contains(statement, want) {
			t.Fatalf("missing scope %s: %s", want, statement)
		}
	}
	if strings.Contains(statement, "body_ref") || strings.Contains(statement, "stream_event_body") {
		t.Fatalf("count loaded bodies: %s", statement)
	}
}

func TestAuxiliaryStreamMetadataAcceptsQuotedUInt64(t *testing.T) {
	from := time.Now().UTC()
	q := StreamEventIndexQuery{ScopeID: "scope-a", From: from, To: from.Add(time.Minute), Limit: 20}
	response := `{"total":"23"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, response) }))
	defer server.Close()
	s, _ := NewClickHouseStore(ClickHouseOptions{DSN: server.URL + "?output_format_json_quote_64bit_integers=1"})
	metadata, err := s.StreamEventIndexMetadata(context.Background(), q)
	if err != nil || metadata.Total != 23 {
		t.Fatalf("quoted UInt64 count=%+v err=%v", metadata, err)
	}
	for _, invalid := range []string{`{"total":"oops"}`, `{"total":-1}`, `{"total":"18446744073709551615"}`, `{}`, `{"total":1.5}`} {
		response = invalid
		if _, err = s.StreamEventIndexMetadata(context.Background(), q); err == nil {
			t.Fatalf("invalid count became success: %s", invalid)
		}
	}
}
