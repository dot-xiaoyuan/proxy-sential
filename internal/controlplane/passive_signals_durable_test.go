package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDurableDHCPCluesKeepBindingAndEventProvenance(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	observed := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL jit=off").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM unnest").WithArgs("aa:bb:cc:dd:ee:ff").WillReturnRows(
		sqlmock.NewRows([]string{"sensor_id", "mac", "ip", "vlan", "address_binding", "recognition_fields", "observed_at", "visible_event_key", "historical"}).
			AddRow("sensor-a", "aa:bb:cc:dd:ee:ff", "192.0.2.3", "8", true, []byte(`{"hostname":"DESKTOP-3","dhcp_vendor_class":"MSFT 5.0","dhcp_requested_options":"1,3,6","dhcp_client_id_hwtype":"1","dhcp_option93_present":"true"}`), observed, "event-ack", false).
			AddRow("sensor-a", "aa:bb:cc:dd:ee:ff", "192.0.2.4", "8", false, []byte(`{"dhcp_vendor_class":"android-dhcp"}`), observed.Add(-time.Minute), "event-request", true))
	mock.ExpectCommit()
	items, err := readDurableDHCPSignals(context.Background(), db, []string{"aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].SensorID != "sensor-a" || items[0].IP != "192.0.2.3" || items[0].DHCPEvidenceID != "event-ack" || items[0].OSFamily != "Windows" || items[0].DHCPClientIDHWType != "1" || !items[0].DHCPOption93Present || items[0].DHCPHistorical || items[1].IP != "" || items[1].OSFamily != "Android" || !items[1].DHCPHistorical || items[1].OSConfidence != "weak" {
		t.Fatalf("durable DHCP clues lost scope, evidence or binding semantics: %+v", items)
	}
	byKey := map[string]*PassiveSignal{}
	for i := range items {
		mergePassiveSignal(byKey, &items[i])
	}
	if len(byKey) != 1 || !byKey["sensor-a|mac:aa:bb:cc:dd:ee:ff|8"].OSConflict {
		t.Fatalf("conflicting durable OS clues were hidden: %+v", byKey)
	}
	if byKey["sensor-a|mac:aa:bb:cc:dd:ee:ff|8"].OSConfidence != "weak" {
		t.Fatalf("historical DHCP clue must keep merged OS confidence weak: %+v", byKey)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHistoricalDHCPClueDoesNotInheritCurrentOSConfidence(t *testing.T) {
	byKey := map[string]*PassiveSignal{}
	mergePassiveSignal(byKey, &PassiveSignal{SensorID: "sensor-a", MAC: "aa:bb:cc:dd:ee:ff", DHCPVLAN: "8", OSFamily: "Windows", OSConfidence: "weak", DHCPHistorical: true})
	mergePassiveSignal(byKey, &PassiveSignal{SensorID: "sensor-a", MAC: "aa:bb:cc:dd:ee:ff", DHCPVLAN: "8", OSFamily: "Windows", OSConfidence: "medium"})
	if got := byKey["sensor-a|mac:aa:bb:cc:dd:ee:ff|8"]; got == nil || got.OSConfidence != "weak" || !got.DHCPHistorical {
		t.Fatalf("merged historical DHCP clue gained current confidence: %+v", got)
	}
}
