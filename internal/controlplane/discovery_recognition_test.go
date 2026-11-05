package controlplane

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/discovery"
)

func TestEnrichDiscoveryRecognitionJoinsByMAC(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	page := map[string]any{"items": []map[string]any{
		{"id": "a", "mac": "AA:BB:CC:DD:EE:01"},
		{"id": "b", "mac": "aa:bb:cc:dd:ee:02"},
		{"id": "c"},
	}}
	mock.ExpectQuery(`SELECT lower\(primary_mac\)`).WithArgs("{aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02}").WillReturnRows(
		sqlmock.NewRows([]string{"mac", "os_family", "role", "brand", "model", "confidence", "rule_version"}).
			AddRow("aa:bb:cc:dd:ee:01", "Android", "mobile", "", "", 0.84, "offline-test"),
	)
	enrichDiscoveryRecognition(context.Background(), db, page)
	items := page["items"].([]map[string]any)
	first, ok := items[0]["recognition"].(discoveryRecognition)
	if !ok || first.OSFamily != "Android" || first.DeviceType != "mobile" || first.Confidence != 0.84 {
		t.Fatalf("first recognition = %#v", items[0]["recognition"])
	}
	if _, ok := items[1]["recognition"]; ok {
		t.Fatal("device without a matching summary must stay unchanged")
	}
	if _, ok := items[2]["recognition"]; ok {
		t.Fatal("device without a MAC must stay unchanged")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichDiscoveryRecognitionJoinsIndexedDeviceViews(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	page := map[string]any{"items": []discovery.DeviceView{{ID: "arp-device", MAC: "AA:BB:CC:DD:EE:01"}}}
	mock.ExpectQuery(`SELECT lower\(primary_mac\)`).WithArgs("{aa:bb:cc:dd:ee:01}").WillReturnRows(
		sqlmock.NewRows([]string{"mac", "os_family", "role", "brand", "model", "confidence", "rule_version"}).
			AddRow("aa:bb:cc:dd:ee:01", "", "access_point", "", "", 0.9, "replay"),
	)
	enrichDiscoveryRecognition(context.Background(), db, page)
	items, ok := page["items"].([]map[string]any)
	if !ok || len(items) != 1 || items[0]["mac"] != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("indexed page was not preserved: %#v", page["items"])
	}
	got, ok := items[0]["recognition"].(discoveryRecognition)
	if !ok || got.DeviceType != "access_point" {
		t.Fatalf("indexed recognition = %#v", items[0]["recognition"])
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichDiscoveryRecognitionSkipsEmptyPages(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	enrichDiscoveryRecognition(context.Background(), db, map[string]any{"items": []map[string]any{}})
	enrichDiscoveryRecognition(context.Background(), db, map[string]any{"items": []map[string]any{{"id": "no-mac"}}})
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichDiscoveryRecognitionKeepsPageOnJoinFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	page := map[string]any{"items": []map[string]any{{"id": "a", "mac": "aa:bb:cc:dd:ee:01"}}}
	mock.ExpectQuery(`SELECT lower\(primary_mac\)`).WithArgs("{aa:bb:cc:dd:ee:01}").WillReturnError(errors.New("db down"))
	enrichDiscoveryRecognition(context.Background(), db, page)
	items := page["items"].([]map[string]any)
	if _, ok := items[0]["recognition"]; ok {
		t.Fatal("failed join must not decorate the page")
	}
	if _, ok := items[0]["id"]; !ok {
		t.Fatal("failed join must keep the original item")
	}
}

func TestDiscoveryRecognitionDoesNotOverrideConflictOrExpiry(t *testing.T) {
	for _, state := range []string{"conflict", "expired"} {
		items := []map[string]any{{"mac": "00:11:22:33:44:55", "classification_status": state}}
		applyDiscoveryRecognition(items, map[string][]int{"00:11:22:33:44:55": {0}}, map[string]discoveryRecognition{"00:11:22:33:44:55": {DeviceType: "printer", Confidence: .95, OSFamily: "Linux"}})
		got := items[0]["recognition"].(discoveryRecognition)
		if got.DeviceType != "" || got.OSFamily != "Linux" {
			t.Fatalf("%s: %+v", state, got)
		}
	}
}
