package store

import (
	"context"
	"database/sql/driver"
	"fmt"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

type signalSliceConverter struct{}

func (signalSliceConverter) ConvertValue(value any) (driver.Value, error) {
	if value != nil && reflect.ValueOf(value).Kind() == reflect.Slice {
		return fmt.Sprint(value), nil
	}
	return driver.DefaultParameterConverter.ConvertValue(value)
}

// A batch with event samples should reach PostgreSQL once per distinct fact.
// The old INSERT followed by UPDATE rewrote every fact twice.
func TestDeviceSignalBatchUsesOneStatement(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(signalSliceConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO device_signal_facts`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signal := DeviceSignal{SignalID: "signal-a", IP: "192.0.2.1", Source: "ncu", Kind: "mac", Value: "02:00:00:00:00:01", EventIDs: []string{"event-a"}}
	if err := upsertDeviceSignalFactsBatch(context.Background(), tx, "sensor-a", []DeviceSignal{signal}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
