package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"proxy-sentinel/internal/discovery"
)

type passiveARPBatchIDs []string

type passiveARPArrayConverter struct{}

func (passiveARPArrayConverter) ConvertValue(value any) (driver.Value, error) {
	if _, ok := value.([]string); ok {
		return "text-array", nil
	}
	return driver.DefaultParameterConverter.ConvertValue(value)
}

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
