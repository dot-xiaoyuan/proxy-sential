package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"

	"github.com/DATA-DOG/go-sqlmock"
)

type passiveLivePTRBatchArgument struct {
	eventID       string
	wantWithdrawn *bool
}

func (a passiveLivePTRBatchArgument) Match(value driver.Value) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	var facts []passiveLivePTRFactRow
	if json.Unmarshal([]byte(text), &facts) != nil || len(facts) != 1 || facts[0].EventID != a.eventID {
		return false
	}
	return a.wantWithdrawn == nil || facts[0].Withdrawn == *a.wantWithdrawn
}

func TestPassiveLivePTRCommitAdvancesReceiveCursorWithFacts(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	first := passiveLivePTRTestEvent("first", at.Add(-time.Minute), 4500)
	last := passiveLivePTRTestEvent("last", at, 4500)
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &DBStore{pg: &PostgresStore{db: db}}
	cursor := passiveLivePTRCursor{ReceivedAt: at.Add(time.Second), EventID: "recv-last", Owner: "worker"}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO endpoint_entities").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO passive_live_ptr_current").WithArgs(passiveLivePTRBatchArgument{eventID: "last"}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE passive_live_ptr_state").WithArgs("campus-204", "worker", cursor.ReceivedAt, "recv-last", 2, 1, 0).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.finishPassiveLivePTR(context.Background(), "campus-204", cursor, []normalized.Event{first, last}, scope); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveLivePTRLostLeaseRollsBackFacts(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	event := passiveLivePTRTestEvent("event", at, 4500)
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &DBStore{pg: &PostgresStore{db: db}}
	cursor := passiveLivePTRCursor{ReceivedAt: at.Add(time.Second), EventID: "recv", Owner: "old-worker"}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO endpoint_entities").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO passive_live_ptr_current").WithArgs(passiveLivePTRBatchArgument{eventID: "event"}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE passive_live_ptr_state").WithArgs("campus-204", "old-worker", cursor.ReceivedAt, "recv", 1, 1, 0).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	if err := store.finishPassiveLivePTR(context.Background(), "campus-204", cursor, []normalized.Event{event}, scope); err == nil {
		t.Fatal("lost lease committed current hints without their cursor")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveLivePTRExpiredPositiveKeepsEventTimeWatermark(t *testing.T) {
	at := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	event := passiveLivePTRTestEvent("expired-positive", at, 120)
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &DBStore{pg: &PostgresStore{db: db}}
	cursor := passiveLivePTRCursor{ReceivedAt: at.Add(time.Second), EventID: "recv", Owner: "worker"}
	withdrawn := true
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO endpoint_entities").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO passive_live_ptr_current").WithArgs(passiveLivePTRBatchArgument{eventID: "expired-positive", wantWithdrawn: &withdrawn}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE passive_live_ptr_state").WithArgs("campus-204", "worker", cursor.ReceivedAt, "recv", 1, 1, 0).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.finishPassiveLivePTR(context.Background(), "campus-204", cursor, []normalized.Event{event}, scope); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveLivePTRStartIsFixedAndValid(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	t.Setenv("PROXY_SENTINEL_PASSIVE_LIVE_PTR_START", now.Add(-time.Hour).Format(time.RFC3339))
	start, err := passiveLivePTRStart(now)
	if err != nil || !start.Equal(now.Add(-time.Hour)) {
		t.Fatalf("configured immutable start lost: %s %v", start, err)
	}
	t.Setenv("PROXY_SENTINEL_PASSIVE_LIVE_PTR_START", now.Add(time.Hour).Format(time.RFC3339))
	if _, err := passiveLivePTRStart(now); err == nil {
		t.Fatal("future start accepted")
	}
}

func TestPassiveLivePTRStreamRowKeepsStringTTLAndReceivePosition(t *testing.T) {
	row := passiveLivePTRStreamRow{
		ReceivedAt: "2026-11-06T06:15:12.123456Z", Timestamp: "2026-11-06T06:14:00.000000Z",
		EventID: "ptr-1", SensorID: "campus-204", CampusID: "campus-204",
		SubjectIP: "10.1.1.24", FlowSrcIP: "10.1.1.24", FlowDstIP: "224.0.0.251",
		InterfaceName: "enp3s0f0", ResponderMAC: "02:00:00:00:00:24",
		RecordName: "_ipp._tcp.local", ServiceTarget: "HP LaserJet Pro._ipp._tcp.local", RecordTTLRaw: `"4500"`,
	}
	event, received, err := row.normalizedEvent()
	if err != nil || event.Payload["record_ttl"] != "4500" || received.Format(time.RFC3339Nano) != row.ReceivedAt {
		t.Fatalf("stream row lost TTL or receive position: event=%+v received=%s err=%v", event, received, err)
	}
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	fact, ok := passiveLivePTRFact(event, scope)
	if !ok || fact.Withdrawn || !fact.ValidUntil.Equal(time.Date(2026, 11, 6, 7, 29, 0, 0, time.UTC)) {
		t.Fatalf("string TTL did not produce the expected live fact: %+v ok=%v", fact, ok)
	}
}

func TestPassiveLivePTRQueryPreservesNativeReceiveColumnInFilter(t *testing.T) {
	query := passiveLivePTRQuery("campus-204", passiveLivePTRCursor{ReceivedAt: time.Date(2026, 11, 6, 5, 17, 0, 0, time.UTC)}, time.Date(2026, 11, 6, 7, 0, 0, 0, time.UTC))
	if !strings.Contains(query, "AS received_at_text") || strings.Contains(query, "AS received_at,") || !strings.Contains(query, "PREWHERE sensor_id='campus-204' AND received_at>=") {
		t.Fatalf("receive time output alias shadows the native filtered column: %s", query)
	}
}
