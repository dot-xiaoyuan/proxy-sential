package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"

	"github.com/DATA-DOG/go-sqlmock"
)

type passiveARPBatchArgument struct{ first, last, middle string }

type passiveARPFactBatchArgument struct{}

type passiveARPArrayConverter struct{}

func (passiveARPArrayConverter) ConvertValue(value any) (driver.Value, error) {
	if _, ok := value.([]string); ok {
		return "text-array", nil
	}
	return driver.DefaultParameterConverter.ConvertValue(value)
}

type passiveARPBatchIDs []string

func (want passiveARPBatchIDs) Match(value driver.Value) bool {
	raw, ok := value.(string)
	if !ok {
		return false
	}
	var rows []passiveARPBatchRow
	if json.Unmarshal([]byte(raw), &rows) != nil || len(rows) != len(want) {
		return false
	}
	for i := range rows {
		if rows[i].ID != want[i] {
			return false
		}
	}
	return true
}

func (passiveARPFactBatchArgument) Match(value driver.Value) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	var rows []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal([]byte(text), &rows) != nil || len(rows) != 1 {
		return false
	}
	return strings.HasPrefix(rows[0].ID, "fact-")
}

type passiveARPCandidatesSortedArgument struct{}

func (passiveARPCandidatesSortedArgument) Match(value driver.Value) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	var rows []passiveARPCandidate
	if json.Unmarshal([]byte(text), &rows) != nil || len(rows) != 2 {
		return false
	}
	return rows[0].MAC == "02:00:00:00:00:01" && rows[1].MAC == "02:00:00:00:00:02"
}

func TestPassiveARPCandidatesAcquireEndpointLocksInIdentityOrder(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Truncate(time.Second)
	event := func(id, mac, ip string) normalized.Event {
		return normalized.Event{
			EventID: id, Source: "zeek", SourceEventType: "arp", Timestamp: at.Format(time.RFC3339Nano),
			Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
			Subject:  map[string]any{"ip": ip, "mac": mac, "campus_id": "campus-204"},
			Payload:  map[string]any{"origin": "arp", "message": "reply"},
		}
	}
	scope, err := parsePassiveDiscoveryScope("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`(?s)INSERT INTO endpoint_entities.*ORDER BY incoming.mac`).WithArgs(passiveARPCandidatesSortedArgument{}).WillReturnResult(sqlmock.NewResult(0, 2))
	if err := ensurePassiveARPCandidateEndpoints(context.Background(), db, []normalized.Event{
		event("second", "02:00:00:00:00:02", "10.1.1.2"),
		event("first", "02:00:00:00:00:01", "10.1.1.1"),
	}, scope); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func (a passiveARPBatchArgument) Match(value driver.Value) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	var rows []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal([]byte(text), &rows) != nil || len(rows) != 2 {
		return false
	}
	return rows[0].ID == a.first && rows[1].ID == a.last && rows[0].ID != a.middle && rows[1].ID != a.middle
}

func TestPassiveDiscoveryBatchesRepeatedARPSenderWrites(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passiveARPArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &DBStore{pg: &PostgresStore{db: db}}
	at := time.Now().UTC().Truncate(time.Second)
	events := make([]normalized.Event, 3)
	for i, id := range []string{"arp-first", "arp-middle", "arp-last"} {
		events[i] = normalized.Event{
			EventID: id, Source: "zeek", SourceEventType: "arp", Timestamp: at.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
			Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
			Subject:  map[string]any{"ip": "10.1.1.2", "mac": "02:00:00:00:00:01", "campus_id": "campus-204"},
			Payload:  map[string]any{"origin": "arp", "message": "reply"},
		}
	}
	scope, err := parsePassiveDiscoveryScope("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO endpoint_entities").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT id,observed_at FROM discovery_observations").WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"id", "observed_at"}))
	mock.ExpectExec("WITH incoming").WithArgs(passiveARPFactBatchArgument{}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	stats, err := store.processPassiveDiscoveryBatch(context.Background(), events, scope)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Processed != 3 || stats.Emitted != 1 || stats.Skipped != 2 || stats.Reasons["arp_repeated_claim_coalesced"] != 1 || stats.Reasons["arp_fact_refreshed"] != 1 {
		t.Fatalf("unexpected ARP batch stats: %+v", stats)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveDiscoveryFlushesDuplicateARPEventIDs(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passiveARPArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &DBStore{pg: &PostgresStore{db: db}}
	at := time.Now().UTC().Truncate(time.Second)
	event := normalized.Event{
		EventID: "arp-replayed", Source: "zeek", SourceEventType: "arp", Timestamp: at.Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
		Subject:  map[string]any{"ip": "10.1.1.2", "mac": "02:00:00:00:00:01", "campus_id": "campus-204"},
		Payload:  map[string]any{"origin": "arp", "message": "reply"},
	}
	replay := event
	replay.Timestamp = at.Add(time.Second).Format(time.RFC3339Nano)
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO endpoint_entities").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT id,observed_at FROM discovery_observations").WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"id", "observed_at"}))
	mock.ExpectExec("WITH incoming").WithArgs(passiveARPFactBatchArgument{}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	stats, err := store.processPassiveDiscoveryBatch(context.Background(), []normalized.Event{event, replay}, scope)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Processed != 2 || stats.Emitted != 1 || stats.Skipped != 1 || stats.Reasons["arp_fact_refreshed"] != 1 {
		t.Fatalf("unexpected replay stats: %+v", stats)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveARPBatchRefreshesOnlyDueFacts(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passiveARPArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	observations := []discovery.Observation{
		{ID: "recent", Origin: "arp", MAC: "00:11:22:33:44:55", IP: "10.0.0.1", ObservedAt: at, ValidUntil: at.Add(10 * time.Minute)},
		{ID: "due", Origin: "arp", MAC: "00:11:22:33:44:56", IP: "10.0.0.2", ObservedAt: at, ValidUntil: at.Add(10 * time.Minute)},
		{ID: "new", Origin: "arp", MAC: "00:11:22:33:44:57", IP: "10.0.0.3", ObservedAt: at, ValidUntil: at.Add(10 * time.Minute)},
	}
	mock.ExpectQuery("SELECT id,observed_at FROM discovery_observations").WithArgs(sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"id", "observed_at"}).AddRow("recent", at.Add(-30*time.Second)).AddRow("due", at.Add(-time.Minute)))
	mock.ExpectExec("WITH incoming AS").WithArgs(passiveARPBatchIDs{"due", "new"}).WillReturnResult(sqlmock.NewResult(0, 2))
	written, err := (&DBStore{}).insertPassiveARPBatch(context.Background(), db, observations)
	if err != nil || len(written) != 2 || written[0].ID != "due" || written[1].ID != "new" {
		t.Fatalf("ARP refresh selection = %+v, %v", written, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
