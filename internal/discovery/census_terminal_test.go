package discovery

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type censusArrayConverter struct{}

func (censusArrayConverter) ConvertValue(value any) (driver.Value, error) {
	if _, ok := value.([]string); ok {
		return "{test}", nil
	}
	return driver.DefaultParameterConverter.ConvertValue(value)
}

func TestCensusTerminalTypeKeepsConflictSeparateFromIdentified(t *testing.T) {
	view := DeviceView{DeviceType: "printer", ClassificationStatus: "identified"}
	if got := censusTerminalType(view); got != "printer" {
		t.Fatalf("identified type=%q", got)
	}
	view = DeviceView{ClassificationStatus: "conflict", Observations: []Observation{{DeviceType: "printer"}, {DeviceType: "camera"}}}
	if got := censusTerminalType(view); got != "camera" {
		t.Fatalf("conflicting type bucket=%q", got)
	}
	view = DeviceView{ClassificationStatus: "expired", LastDeviceType: "recorder"}
	if got := censusTerminalType(view); got != "recorder" {
		t.Fatalf("expired type=%q", got)
	}
}

func TestCensusDirectTypeEvidenceRejectsWeakClues(t *testing.T) {
	now := time.Now().UTC()
	view := DeviceView{Observations: []Observation{{DeviceType: "printer", Confidence: "clue", ObservedAt: now, ValidUntil: now.Add(time.Hour)}}}
	if censusDirectTypeEvidence(view, "printer", now) {
		t.Fatal("weak type clue became an identified terminal")
	}
	view.Observations[0].Confidence = "strong"
	if !censusDirectTypeEvidence(view, "printer", now) {
		t.Fatal("strong current type evidence was ignored")
	}
	view.Observations[0].ValidUntil = now.Add(-time.Second)
	if censusDirectTypeEvidence(view, "printer", now) {
		t.Fatal("expired type evidence remained current")
	}
}

func TestCensusTerminalSameScopedMACWithCompetingEndpointsCountsOnce(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{Node: "sensor-204", Site: "east", Domain: "access", VLAN: "20", MAC: "00:11:22:33:44:55", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
	printer := base
	printer.DeviceType = "printer"
	camera := base
	camera.DeviceType = "camera"
	views := []DeviceView{
		{ID: "endpoint-a", EndpointID: "asset-a", MAC: base.MAC, DeviceType: "printer", ClassificationStatus: "identified", FirstSeen: now, LastSeen: now, Observations: []Observation{printer}},
		{ID: "endpoint-b", EndpointID: "asset-b", MAC: base.MAC, DeviceType: "camera", ClassificationStatus: "identified", FirstSeen: now, LastSeen: now, Observations: []Observation{camera}},
	}
	merged := mergeCensusTerminalViews(views)
	if len(merged) != 1 || merged[0].ClassificationStatus != "conflict" || len(merged[0].Observations) != 2 {
		t.Fatalf("competing endpoint identities not deduplicated: %+v", merged)
	}
}

func TestRefreshCensusTerminalUsesAffectedLatestEvidence(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(censusArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Truncate(time.Second)
	observation := Observation{ID: "observation-1", EventID: "event-1", SourceID: "passive:sensor-204:mirror", Node: "sensor-204", Site: "east", Domain: "access", VLAN: "20", MAC: "00:11:22:33:44:55", Origin: "dns_sd", DeviceType: "printer", Confidence: "strong", ObservedAt: at, ValidUntil: at.Add(time.Hour), RuleVersion: "rule-1"}
	raw, _ := json.Marshal(observation)
	mock.ExpectQuery(`SELECT DISTINCT lower`).WithArgs(sqlmock.AnyArg(), "sensor-204").WillReturnRows(sqlmock.NewRows([]string{"mac"}).AddRow(observation.MAC))
	mock.ExpectQuery(`SELECT l.device_key`).WithArgs(sqlmock.AnyArg(), "sensor-204").WillReturnRows(sqlmock.NewRows([]string{"device_key", "data", "endpoint_id", "role", "confidence", "conflict"}).AddRow("device-1", raw, "", "", 0.0, false))
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO passive_census_terminal_current`).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "device-1", "printer", "identified", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "rule-1", "sensor-204", "east", "access", "20", "", sqlmock.AnyArg(), "00:11:22:33:44:55").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := RefreshCensusTerminals(context.Background(), db, "sensor-204", []string{"device-1"}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
