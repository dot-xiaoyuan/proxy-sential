package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIndexedCursorIncludesEveryFilter(t *testing.T) {
	q := DeviceQuery{Mode: "passive", Window: 24 * time.Hour}
	cursor, err := encodeIndexedDeviceCursor(q, DeviceView{ID: "x", LastSeen: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DeviceQuery){func(q *DeviceQuery) { q.Protocol = "arp" }, func(q *DeviceQuery) { q.State = "identified" }, func(q *DeviceQuery) { q.Domain = "school" }, func(q *DeviceQuery) { q.VLAN = "204" }} {
		other := q
		other.Cursor = cursor
		change(&other)
		if _, err := decodeIndexedDeviceCursor(other); err == nil {
			t.Fatal("cursor reused across different filters")
		}
	}
}

func TestIndexedTypeFilterUsesRecognitionBeforePagingAndKeepsOtherEvidence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	o := Observation{ID: "arp", Origin: "arp", MAC: "00:11:22:33:44:55", Node: "s204", Domain: "mirror", VLAN: "10", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
	raw, _ := json.Marshal(o)
	mock.ExpectQuery(`(?s)candidate_rows AS.*endpoint_recognition_summary.*candidate_source AS.*classification_status.*candidates AS.*effective_types.*LIMIT`).WillReturnRows(sqlmock.NewRows([]string{"device_key", "data", "endpoint_id", "role", "confidence", "conflict"}).AddRow("device", raw, "mac:00:11:22:33:44:55", "access_point", .95, false))
	page, err := (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", DeviceType: "access_point", Protocol: "arp", State: "identified", Domain: "mirror", VLAN: "10", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]DeviceView)
	if len(items) != 1 || items[0].DeviceType != "access_point" || items[0].ClassificationStatus != "identified" || items[0].SensorID != "s204" {
		t.Fatalf("filtered item: %+v", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIndexedClassificationKeepsExpiredAndConflictSeparate(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{ID: "printer", Origin: "dns_sd", MAC: "00:11:22:33:44:55", DeviceType: "printer", ObservedAt: now.Add(-time.Hour), ValidUntil: now.Add(-time.Minute)}
	expired := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "a", Observation: base}}, now)[0]
	if expired.DeviceType != "" || expired.LastDeviceType != "printer" || expired.ClassificationStatus != "expired" {
		t.Fatalf("expired promoted current: %+v", expired)
	}
	base.ValidUntil = now.Add(time.Hour)
	conflict := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "a", Observation: base, ProfileDeviceType: "camera", ProfileTypeConfidence: .95}}, now)[0]
	if conflict.DeviceType != "" || conflict.ClassificationStatus != "conflict" {
		t.Fatalf("conflict promoted certainty: %+v", conflict)
	}
	candidate := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "a", Observation: Observation{Origin: "arp", ObservedAt: now, ValidUntil: now.Add(time.Hour)}, ProfileDeviceType: "camera", ProfileTypeConfidence: .5}}, now)[0]
	if candidate.DeviceType != "" || candidate.ClassificationStatus != "candidate" {
		t.Fatalf("low-confidence profile promoted: %+v", candidate)
	}
}

func TestDiscoveryTypeCatalogueCoversNetworkAndPersonalTerminals(t *testing.T) {
	got := map[string]bool{}
	for _, kind := range DeviceTypes {
		if got[kind.ID] {
			t.Fatalf("duplicate %s", kind.ID)
		}
		got[kind.ID] = true
	}
	for _, kind := range []string{"printer", "access_point", "router", "switch", "gateway", "desktop", "laptop", "mobile", "tablet", "server", "camera"} {
		if !got[kind] {
			t.Errorf("missing type %s", kind)
		}
	}
}

func TestIndexedClassificationRefinesGenericMobileEvidence(t *testing.T) {
	now := time.Now().UTC()
	observation := Observation{ID: "dhcp", Origin: "dhcp", DeviceType: "mobile", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
	for _, specific := range []string{"tablet", "phone", "smartphone"} {
		got := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "mobile", Observation: observation, ProfileDeviceType: specific, ProfileTypeConfidence: .95}}, now)[0]
		if got.DeviceType != specific || got.ClassificationStatus != "identified" {
			t.Fatalf("generic mobile versus %s became a conflict: %+v", specific, got)
		}
		if got.Observations[0].DeviceType != "mobile" {
			t.Fatal("original observation was rewritten")
		}
	}
}

func TestIndexedContinuationCountsCandidateKeysBeforeAliasMerging(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"device_key", "data", "endpoint_id", "role", "confidence", "conflict"})
	for i := 0; i < 64; i++ {
		observation := Observation{ID: fmt.Sprintf("observation-%03d", i), Origin: "arp", MAC: "00:11:22:33:44:55", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
		raw, _ := json.Marshal(observation)
		rows.AddRow(fmt.Sprintf("key-%03d", i), raw, "", "", 0, false)
	}
	mock.ExpectQuery("WITH candidate_rows").WillReturnRows(rows)
	q := DeviceQuery{Mode: "passive", Limit: 1}
	page, err := (Repository{DB: db}).DevicesIndexed(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]DeviceView)) != 1 || page["has_more"] != true || page["next_cursor"] == "" {
		t.Fatalf("merged candidate page lost continuation: has_more=%v cursor=%v", page["has_more"], page["next_cursor"])
	}
	q.Window = 24 * time.Hour
	q.Cursor = page["next_cursor"].(string)
	cursor, err := decodeIndexedDeviceCursor(q)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.DeviceKey != "key-063" {
		t.Fatalf("continuation must consume all selected keys, got %+v", cursor)
	}
}
