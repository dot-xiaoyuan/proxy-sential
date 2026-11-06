package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"

	"github.com/DATA-DOG/go-sqlmock"
)

type passiveARPBatchArgument struct{ first, last, middle string }

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
	db, mock, err := sqlmock.New()
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
	mock.ExpectExec("WITH incoming").WithArgs(passiveARPBatchArgument{first: "arp-first", last: "arp-last", middle: "arp-middle"}).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	stats, err := store.processPassiveDiscoveryBatch(context.Background(), events, scope)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Processed != 3 || stats.Emitted != 2 || stats.Skipped != 1 || stats.Reasons["arp_repeated_claim_coalesced"] != 1 {
		t.Fatalf("unexpected ARP batch stats: %+v", stats)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveDiscoveryFlushesDuplicateARPEventIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
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
	mock.ExpectExec("WITH incoming").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("WITH incoming").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	stats, err := store.processPassiveDiscoveryBatch(context.Background(), []normalized.Event{event, replay}, scope)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Processed != 2 || stats.Emitted != 2 || stats.Skipped != 0 {
		t.Fatalf("unexpected replay stats: %+v", stats)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
