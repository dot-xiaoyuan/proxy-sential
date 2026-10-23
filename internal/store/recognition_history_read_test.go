package store

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDeviceNameStreamSeekKeepsStrictProgressAndAsOfBound(t *testing.T) {
	for _, fragment := range []string{"WITH RECURSIVE streams", "(p.source,p.value_key,p.sensor_id,p.address_key)", "ORDER BY source,lower(value),sensor_id,coalesce(evidence->>'address',''),observed_at DESC,event_id DESC LIMIT 1"} {
		if !strings.Contains(deviceNamesReadSQL, fragment) {
			t.Fatalf("missing stream seek contract: %s", fragment)
		}
	}
	if strings.Count(deviceNamesReadSQL, "observed_at <= $2") != 2 {
		t.Fatal("seed and successor must both exclude future evidence")
	}
}

func TestDeviceNamesKeepHistoricalEvidenceWithoutExpiredLeaseLookups(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	n := DeviceNameEvidence{Value: "Laptop.local", Source: "mdns_hostname", Kind: "hostname", ObservedAt: now.Add(-8 * 24 * time.Hour), ValidUntil: now.Add(-7 * 24 * time.Hour)}
	raw, _ := json.Marshal(n)
	mock.ExpectQuery(`(?s)n.source='mdns_hostname' AND n.observed_at > \$2::timestamptz-interval '7 days' AND .*valid_until.* > \$2`).WillReturnRows(sqlmock.NewRows([]string{"id", "evidence", "cutoff"}).AddRow("endpoint", raw, nil))
	mock.ExpectQuery(`SELECT endpoint_id,value FROM device_name_notes`).WillReturnRows(sqlmock.NewRows([]string{"id", "value"}))
	names, err := (&PostgresStore{db: db}).DeviceNames(context.Background(), []string{"endpoint"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if names["endpoint"] == nil || names["endpoint"].Status != "historical" {
		t.Fatalf("historical name lost: %+v", names)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecognitionHistoryPreservesInventoryAndConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	first := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	last := first.Add(time.Hour)
	mock.ExpectQuery(`SELECT event_id,account_id,host\(ip\),first_seen,last_seen`).WithArgs("endpoint", 200).WillReturnRows(sqlmock.NewRows([]string{"id", "account", "ip", "first", "last"}).AddRow("ip1", "account-a", "10.0.0.1", first, last).AddRow("ip2", "account-b", "2001:db8::1", first, last))
	mock.ExpectQuery(`SELECT event_id,account_id,access_id,first_seen,last_seen`).WithArgs("endpoint", 200).WillReturnRows(sqlmock.NewRows([]string{"id", "account", "access", "first", "last"}).AddRow("access", "account-b", "ap", first, last))
	pg := &PostgresStore{db: db}
	ips, accesses, err := pg.recognitionHistory(context.Background(), "endpoint", 200)
	if err != nil {
		t.Fatal(err)
	}
	fullIPs := append([]IdentityIPMACHistory(nil), ips...)
	for i := range fullIPs {
		fullIPs[i].MAC = "00:11:22:33:44:55"
		fullIPs[i].EntityRole = "endpoint"
		fullIPs[i].Source = "auth"
		fullIPs[i].IdentityConfidence = .9
		fullIPs[i].EventIDsSample = []string{"evidence"}
	}
	fullAccess := append([]IdentityAccessHistory(nil), accesses...)
	fullAccess[0].Source = "auth"
	fullAccess[0].AP = "ap"
	fullAccess[0].EventIDsSample = []string{"evidence"}
	base := IdentityState{Endpoints: []EndpointEntity{{EndpointID: "endpoint", PrimaryMAC: "00:11:22:33:44:55", FirstSeen: first.Format(time.RFC3339Nano), LastSeen: last.Format(time.RFC3339Nano)}}}
	full, light := base, base
	full.IPMACHistory, full.AccessHistory = fullIPs, fullAccess
	light.IPMACHistory, light.AccessHistory = ips, accesses
	f, _ := BuildEndpointIdentityProfile(full, "endpoint")
	l, _ := BuildEndpointIdentityProfile(light, "endpoint")
	if !reflect.DeepEqual(BuildEndpointDeviceInventory(f), BuildEndpointDeviceInventory(l)) {
		t.Fatal("narrow history changed recognition or account/IP conflict semantics")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
