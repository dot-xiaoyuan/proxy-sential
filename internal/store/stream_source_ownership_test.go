package store

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestLegacySourceGuardRetainsClosedAndPausedOwnership(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM stream_source_cutovers WHERE state IN \('active','paused','closed'\)`).
		WillReturnRows(sqlmock.NewRows([]string{"source_kind", "source_path", "sensor_id"}).
			AddRow("zeek-dhcp", "/logs/dhcp.log", "sensor-a").
			AddRow("zeek-dhcp", "/logs/dhcp.log", "sensor-a").
			AddRow("device-signals", "/signals/ttl.jsonl", "sensor-a"))
	owners, err := (&PostgresStore{db: db}).ActiveStreamSourceCutovers(context.Background())
	if err != nil || len(owners) != 2 || owners["zeek-dhcp\x00/logs/dhcp.log"] != "sensor-a" {
		t.Fatalf("retired source lost ownership: owners=%v err=%v", owners, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySourceGuardRejectsConflictingRetiredOwner(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM stream_source_cutovers WHERE state IN \('active','paused','closed'\)`).
		WillReturnRows(sqlmock.NewRows([]string{"source_kind", "source_path", "sensor_id"}).
			AddRow("zeek-dhcp", "/logs/dhcp.log", "sensor-a").
			AddRow("zeek-dhcp", "/logs/dhcp.log", "sensor-b"))
	if _, err := (&PostgresStore{db: db}).ActiveStreamSourceCutovers(context.Background()); err == nil {
		t.Fatal("conflicting retired owner was accepted")
	}
}
