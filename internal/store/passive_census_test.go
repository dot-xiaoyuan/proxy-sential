package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
)

func censusReplay(id, at, mac string) normalized.Event {
	return normalized.Event{
		EventID: id, Source: "zeek", SourceEventType: "arp", Timestamp: at,
		Observer: map[string]any{"sensor_id": "census-replay", "interface": "mirror0"},
		Subject:  map[string]any{"ip": "10.24.1.5", "mac": mac, "campus_id": "campus"},
		Payload:  map[string]any{"access_domain": "mirror", "vlan": "24"},
		Flow:     map[string]any{},
	}
}

func TestPassiveCensusCoalescesDuplicateLateAndBindingChange(t *testing.T) {
	base := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	first := censusReplay("first", base.Format(time.RFC3339Nano), "00:11:22:33:44:55")
	last := censusReplay("last", base.Add(2*time.Minute).Format(time.RFC3339Nano), "00:11:22:33:44:55")
	late := censusReplay("late", base.Add(-time.Minute).Format(time.RFC3339Nano), "00:11:22:33:44:55")
	rebound := censusReplay("rebound", base.Add(3*time.Minute).Format(time.RFC3339Nano), "00:11:22:33:44:56")
	current, buckets, bindings, err := coalesceCensusIdentifiers([]normalized.Event{first, last, first, late, rebound}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 3 || len(buckets) != 5 || len(bindings) != 2 {
		t.Fatalf("current=%+v buckets=%+v bindings=%+v", current, buckets, bindings)
	}
	for _, item := range current {
		if item.Kind == "ip" && (!item.FirstSeen.Equal(base.Add(-time.Minute)) || !item.LastSeen.Equal(base.Add(3*time.Minute))) {
			t.Fatalf("late or rebound observation lost: %+v", item)
		}
	}
}

func TestPassiveCensusRejectsMissingExplicitScope(t *testing.T) {
	if _, _, _, err := coalesceCensusIdentifiers([]normalized.Event{censusReplay("a", "2026-11-10T09:00:00Z", "00:11:22:33:44:55")}, []string{"invalid"}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	current, _, _, err := coalesceCensusIdentifiers([]normalized.Event{censusReplay("a", "2026-11-10T09:00:00Z", "00:11:22:33:44:55")}, nil)
	if err != nil || len(current) != 0 {
		t.Fatalf("empty scope admitted: %+v %v", current, err)
	}
}

func TestPassiveCensusDHCPRebindRetiresOlderClaim(t *testing.T) {
	base := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	old := censusReplay("old", base.Format(time.RFC3339Nano), "00:11:22:33:44:55")
	newer := censusReplay("ack", base.Add(time.Minute).Format(time.RFC3339Nano), "00:11:22:33:44:66")
	newer.SourceEventType = "dhcp"
	newer.Payload["msg_types"] = "ACK"
	_, _, bindings, err := coalesceCensusIdentifiers([]normalized.Event{old, newer}, []string{"10.0.0.0/8"})
	if err != nil || len(bindings) != 2 {
		t.Fatalf("bindings=%+v error=%v", bindings, err)
	}
	for _, binding := range bindings {
		if binding.MAC == "00:11:22:33:44:55" && (!binding.Withdrawn || !binding.ValidUntil.Equal(base.Add(time.Minute))) {
			t.Fatalf("old binding still active: %+v", binding)
		}
		if binding.MAC == "00:11:22:33:44:66" && (binding.Withdrawn || binding.Source != "dhcp:zeek") {
			t.Fatalf("new binding invalid: %+v", binding)
		}
	}
}

func TestPassiveCensusMalformedQueuedBatchRetainsFailureCursor(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "sensor-204"}}
	at := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM passive_census_pending_batches`).WithArgs("sensor-204").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor_id", "scope_version", "first_source_at", "last_source_at", "first_enqueued_at", "payload", "attempts"}).AddRow(7, "sensor-204", "scope-v1", at, at, at, []byte(`{bad`), 0))
	mock.ExpectExec(`UPDATE passive_census_pending_batches SET lease_owner`).WithArgs(int64(7), "worker").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	task, claimed, claimErr := s.claimPassiveCensus(context.Background(), "worker")
	if !claimed || claimErr == nil || task.ID != 7 {
		t.Fatalf("claim=%+v claimed=%t error=%v", task, claimed, claimErr)
	}
	mock.ExpectExec(`UPDATE passive_census_pending_batches SET lease_owner=''`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE passive_census_runtime SET failed_batches`).WillReturnResult(sqlmock.NewResult(0, 1))
	s.failPassiveCensus(context.Background(), task, claimErr)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
