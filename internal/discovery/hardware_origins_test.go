package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestHardwarePassiveSelectionAdmitsProductSourcesOnlyWhenEnabled(t *testing.T) {
	for _, export := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			selection, err := buildIndexedDeviceSelection(DeviceQuery{Mode: "passive", HardwareV2: enabled, Export: export})
			if err != nil {
				t.Fatal(err)
			}
			for _, origin := range []string{"snmp", "bacnet", "modbus", "http_device", "rtsp", "sip", "tls_device", "ipp", "onvif", "dhcp_client"} {
				found := false
				for _, arg := range selection.Args {
					found = found || arg == origin
				}
				if found != enabled {
					t.Errorf("source %s: enabled=%v export=%v admitted=%v", origin, enabled, export, found)
				}
			}
		}
	}
}

func TestIndexedHardwareListAndExportKeepRetainedSNMPClue(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(censusArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	o := Observation{ID: "retained", EventID: "snmp-original", IP: "10.131.253.254", VLAN: "4005",
		Origin: "snmp", DeviceType: "switch", Confidence: "confirmed", ModelName: "Core Switch", ObservedAt: now, ValidUntil: now.Add(time.Hour),
		Evidence: normalized.Event{EventID: "snmp-original", RawRef: map[string]any{"log": "snmp_device"},
			Payload: map[string]any{"is_response": true, "response_source_ip": "10.131.253.254", "hardware_identity": "ambiguous_or_missing"}}}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{DB: db, HardwareV2: true}
	for _, export := range []bool{false, true} {
		mock.ExpectQuery("FROM candidate_rows l JOIN candidates").
			WillReturnRows(sqlmock.NewRows([]string{"identity", "key", "data", "endpoint", "role", "confidence", "conflict", "profile_candidate_role", "category", "last_seen", "type_evidence_state"}).
				AddRow("ip-only", "key", raw, "", "", 0, false, "", "identity_only", now, "no_type_clue"))
		mock.ExpectQuery("SELECT identity_key,data FROM passive_hardware_current").
			WillReturnRows(sqlmock.NewRows([]string{"identity_key", "data"}))
		page, err := repo.devicesIndexed(context.Background(), db, DeviceQuery{Mode: "passive", Export: export}, false)
		if err != nil {
			t.Fatal(err)
		}
		item := page["items"].([]DeviceView)[0]
		clue := item.Observations[0]
		if item.DeviceType != "" || item.ClassificationStatus != "candidate" ||
			clue.Confidence != "clue" || clue.DeviceType != "" || clue.ModelName != o.ModelName ||
			clue.Evidence.EventID != "snmp-original" || clue.Evidence.RawRef["log"] != "snmp_device" {
			t.Fatalf("export=%v lost classification boundary or source evidence: %+v", export, clue)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHardwareSNMPOnlyPostgresListMetadataAndExportAfterAddressExpiry(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 2; i++ {
		o := hardwareTestObservation(now.Add(-10 * time.Minute))
		o.ID = fmt.Sprintf("snmp-only-%d", i)
		o.EventID = o.ID
		o.Origin = "snmp"
		o.MAC = fmt.Sprintf("00:11:22:33:44:%02x", i+1)
		o.IP = fmt.Sprintf("10.0.0.%d", i+1)
		o.ValidUntil = now.Add(-9 * time.Minute)
		o.ModelName = ""
		o.Evidence.Payload = map[string]any{"is_response": true, "response_source_ip": o.IP, "hardware_identity": "unique_binding", "system_object_id": "1.3.6.1.4.1.52674.500", "snmp_varbinds": map[string]string{"1.3.6.1.4.1.318.1.4.2.2.1.2.1": "NetBotz 750"}}
		enqueueHardwareTest(t, db, o)
		raw, _ := json.Marshal(o)
		if _, err := db.Exec(`INSERT INTO discovery_observation_latest(id,device_key,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,false,$6)`, o.ID, o.Key(), o.Origin, o.ObservedAt, o.ValidUntil, raw); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			old := o
			old.ID = "old-arp"
			old.EventID = old.ID
			old.Origin = "arp"
			old.ObservedAt = now.Add(-48 * time.Hour)
			old.ValidUntil = now.Add(-47 * time.Hour)
			old.Evidence.Payload = map[string]any{}
			raw, _ = json.Marshal(old)
			if _, err := db.Exec(`INSERT INTO discovery_observation_latest(id,device_key,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,false,$6)`, old.ID, old.Key(), old.Origin, old.ObservedAt, old.ValidUntil, raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	processHardwareTest(t, db)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	repo := Repository{DB: db, HardwareV2: true}
	q := DeviceQuery{Mode: "passive", Window: 24 * time.Hour, SnapshotAt: now, Limit: 50}
	meta, err := repo.DevicesIndexedMetadataSnapshot(ctx, tx, q)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Total != 2 || meta.Identified != 2 {
		t.Fatalf("SNMP hardware disappeared after address/service expiry: %+v", meta)
	}
	for _, export := range []bool{false, true} {
		q.Export = export
		page, err := repo.DevicesIndexedSnapshot(ctx, tx, q)
		if err != nil {
			t.Fatal(err)
		}
		items := page["items"].([]DeviceView)
		if len(items) != 2 {
			t.Fatalf("export=%v rows=%d metadata=%d", export, len(items), meta.Total)
		}
		for _, item := range items {
			if item.HardwareType != "environment_monitor" || item.HardwareTypeStatus != "identified" || item.HardwareModel != "NetBotz 750" || len(item.TypeSources) == 0 {
				t.Fatalf("missing scoped product evidence: %+v", item.HardwareDetails)
			}
		}
	}
	legacy, err := (Repository{DB: db}).DevicesIndexedMetadataSnapshot(ctx, tx, q)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Total != 0 {
		t.Fatalf("184 default passive admission changed: %+v", legacy)
	}
}
