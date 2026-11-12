package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/census"
)

func TestCensusQueryKeepsSensorBoundaryAndWindows(t *testing.T) {
	server := &Server{sensorID: "sensor-204"}
	request := httptest.NewRequest("GET", "/discovery/census/summary?window=7d&campus_id=east&vlan=20", nil)
	query, err := server.censusQuery(request)
	if err != nil || query.SensorID != "sensor-204" || query.CampusID != "east" || query.VLAN != "20" || query.Window != 7*24*time.Hour {
		t.Fatalf("query=%+v error=%v", query, err)
	}
	for _, target := range []string{"?sensor_id=other", "?window=1h", "?limit=201", "?kind=ip&terminal_status=identified", "?kind=terminal&terminal_status=unknown"} {
		if _, err := server.censusQuery(httptest.NewRequest("GET", "/discovery/census/identifiers"+target, nil)); err == nil {
			t.Fatalf("accepted invalid census query %s", target)
		}
	}
}

func TestCensusComparisonStreamEndsWithMatchingCounts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	server := &Server{sensorID: "sensor-204", operations: &operationsState{db: db}}
	mock.ExpectBegin()
	runtime := func() {
		mock.ExpectQuery(`FROM passive_census_runtime`).WithArgs("sensor-204").WillReturnRows(sqlmock.NewRows([]string{"available_from", "last_source_at", "last_success_at", "oldest_pending_at", "failed_batches", "scope_version", "last_batch_rows", "last_batch_ms"}).AddRow(now.Add(-25*time.Hour), now, now, nil, 0, "scope-v1", 4, 3))
	}
	pageRuntime := func() {
		mock.ExpectQuery(`SELECT last_source_at FROM passive_census_runtime`).WithArgs("sensor-204").WillReturnRows(sqlmock.NewRows([]string{"last_source_at"}).AddRow(now))
	}
	runtime()
	mock.ExpectQuery(`count\(\*\) FILTER`).WillReturnRows(sqlmock.NewRows([]string{"ips", "v4", "v6", "macs", "random", "incomplete"}).AddRow(1, 1, 0, 1, 0, 0))
	mock.ExpectQuery(`SELECT count\(\*\) FROM passive_census_binding_current`).WillReturnRows(sqlmock.NewRows([]string{"bindings"}).AddRow(1))
	mock.ExpectQuery(`SELECT effective_type`).WillReturnRows(sqlmock.NewRows([]string{"type", "state", "count"}).AddRow("printer", "identified", 1))
	pageRuntime()
	mock.ExpectQuery(`FROM passive_census_identifier_current i`).WillReturnRows(sqlmock.NewRows([]string{"scope_key", "sensor_id", "campus_id", "access_domain", "vlan", "vrf", "kind", "value", "ip_family", "random_mac", "first_seen", "last_seen", "last_event_id", "last_source"}).AddRow("scope-a", "sensor-204", "east", "access", "20", "", "ip", "10.20.0.2", 4, false, now, now, "event-ip", "zeek"))
	pageRuntime()
	mock.ExpectQuery(`FROM passive_census_identifier_current i`).WillReturnRows(sqlmock.NewRows([]string{"scope_key", "sensor_id", "campus_id", "access_domain", "vlan", "vrf", "kind", "value", "ip_family", "random_mac", "first_seen", "last_seen", "last_event_id", "last_source"}).AddRow("scope-a", "sensor-204", "east", "access", "20", "", "mac", "00:11:22:33:44:55", 0, false, now, now, "event-mac", "zeek"))
	pageRuntime()
	mock.ExpectQuery(`FROM passive_census_binding_current b JOIN`).WillReturnRows(sqlmock.NewRows([]string{"scope_key", "sensor_id", "campus_id", "access_domain", "vlan", "vrf", "ip", "mac", "observed_at", "event_id", "source"}).AddRow("scope-a", "sensor-204", "east", "access", "20", "", "10.20.0.2", "00:11:22:33:44:55", now, "event-binding", "arp:zeek"))
	pageRuntime()
	identity := `["identity","sensor-204","east","access","20","","mac","00:11:22:33:44:55"]`
	mock.ExpectQuery(`FROM passive_census_terminal_current t`).WillReturnRows(sqlmock.NewRows([]string{"scope_key", "sensor_id", "campus_id", "access_domain", "vlan", "vrf", "identity_key", "device_key", "mac", "effective_type", "state", "first_seen", "last_seen"}).AddRow("scope-a", "sensor-204", "east", "access", "20", "", identity, "device-1", "00:11:22:33:44:55", "printer", "identified", now, now))
	mock.ExpectCommit()
	response := httptest.NewRecorder()
	server.streamDiscoveryCensus(response, context.Background(), census.Query{SensorID: "sensor-204"})
	if response.Code != 200 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	lines := strings.Split(strings.TrimSpace(response.Body.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("stream records=%d: %s", len(lines), response.Body.String())
	}
	var start, end map[string]any
	if err = json.Unmarshal([]byte(lines[0]), &start); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(lines[5]), &end); err != nil {
		t.Fatal(err)
	}
	if start["record"] != "manifest" || end["record"] != "end" || end["complete"] != true {
		t.Fatalf("manifest=%v end=%v", start, end)
	}
	counts := end["counts"].(map[string]any)
	for _, kind := range []string{"ip", "mac", "binding", "terminal"} {
		if counts[kind] != float64(1) {
			t.Fatalf("%s count=%v", kind, counts[kind])
		}
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
