package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func repairFixture() (HardwareRepairWindow, discovery.Observation) {
	at := time.Date(2026, 11, 12, 4, 47, 30, 0, time.UTC)
	return HardwareRepairWindow{Sensor: "sensor", From: at.Add(-time.Hour), Until: at.Add(time.Hour)}, discovery.Observation{ID: "obs", EventID: "event", SourceID: "source", Origin: "sadp", Node: "sensor", Site: "campus", Domain: "access", VLAN: "201", IP: "10.0.0.2", MAC: "00:11:22:33:44:55", ObservedAt: at, ValidUntil: at.Add(-time.Minute), Evidence: normalized.Event{EventID: "event", RawRef: map[string]any{"backend": "capture", "payload_sha256": strings.Repeat("a", 64)}, Payload: map[string]any{"is_response": true, "identity_status": "direct_l2", "claimed_mac": "00:11:22:33:44:55", "claimed_ip": "10.0.0.2", "product_model": "DS-7808N-Q2"}}}
}
func repairManifest(o discovery.Observation) HardwareRepairManifest {
	w, _ := repairFixture()
	raw, _ := json.Marshal(o)
	return HardwareRepairManifest{SchemaVersion: HardwareRepairSchema, Window: w, SnapshotAt: w.Until.Add(time.Minute), Entries: []HardwareRepairEntry{makeHardwareRepairEntry([5]string{"key", "source", o.Origin, "", ""}, raw, o)}}
}
func TestHardwareRepairSnapshotFreezesMissingRefsAndExpiredEvidence(t *testing.T) {
	db, m, _ := sqlmock.New()
	defer db.Close()
	w, o := repairFixture()
	raw, _ := json.Marshal(o)
	absent := o
	absent.ID = "absent"
	absent.EventID = ""
	absent.Evidence.RawRef = nil
	no, _ := json.Marshal(absent)
	m.ExpectBegin()
	m.ExpectQuery("SELECT now\\(\\),count").WillReturnRows(sqlmock.NewRows([]string{"at", "count", "bytes", "max"}).AddRow(w.Until.Add(time.Minute), 2, len(raw)+len(no), len(raw)))
	m.ExpectQuery("SELECT device_key,source_id,origin,service_type,port,id,observed_at,data FROM discovery_observation_latest").WithArgs(w.Sensor, w.From, w.Until, HardwareRepairMaxRows+1).WillReturnRows(sqlmock.NewRows([]string{"device", "source", "origin", "service", "port", "id", "observed_at", "data"}).AddRow("a", "source", "sadp", "", "", o.ID, o.ObservedAt, raw).AddRow("b", "source", "sadp", "", "", absent.ID, absent.ObservedAt, no))
	m.ExpectCommit()
	got, err := SnapshotHardwareRepair(context.Background(), db, w)
	if err != nil || len(got.Entries) != 2 {
		t.Fatalf("snapshot %+v %v", got, err)
	}
	if got.Entries[0].Observation == nil || got.Entries[1].ExcludedReason != "missing_source_reference" {
		t.Fatalf("wrong admission %+v", got.Entries)
	}
	if got.Entries[0].Observation.ValidUntil.After(o.ObservedAt) {
		t.Fatal("expired evidence was rewritten")
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestHardwareRepairSnapshotBoundsBeforeTransferringDocuments(t *testing.T) {
	db, m, _ := sqlmock.New()
	defer db.Close()
	w, _ := repairFixture()
	m.ExpectBegin()
	m.ExpectQuery("SELECT now\\(\\),count").WillReturnRows(sqlmock.NewRows([]string{"at", "count", "bytes", "max"}).AddRow(w.Until.Add(time.Minute), HardwareRepairMaxRows+1, 10, 10))
	m.ExpectRollback()
	if _, err := SnapshotHardwareRepair(context.Background(), db, w); err == nil {
		t.Fatal("over-limit snapshot accepted")
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestHardwareRepairUsesShortTransactionAndRollsBackFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[fail], func(t *testing.T) {
			db, m, _ := sqlmock.New()
			defer db.Close()
			_, o := repairFixture()
			manifest := repairManifest(o)
			m.ExpectBegin()
			m.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
			m.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
			ex := m.ExpectExec("WITH incoming AS")
			if fail {
				ex.WillReturnError(context.DeadlineExceeded)
				m.ExpectRollback()
			} else {
				ex.WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectCommit()
			}
			out, err := ApplyHardwareRepairBatch(context.Background(), db, manifest, 0, 25)
			if fail {
				if !errors.Is(err, context.DeadlineExceeded) || len(out) != 0 {
					t.Fatalf("failed batch advanced %+v %v", out, err)
				}
			} else if err != nil || len(out) != 1 || out[0].Status != "admitted" || out[0].IdentityKey == "" {
				t.Fatalf("apply %+v %v", out, err)
			}
			if err = m.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestHardwareRepairUsesEventTimeAndEveryScopeDimension(t *testing.T) {
	db, m, _ := sqlmock.New()
	defer db.Close()
	_, o := repairFixture()
	o.Origin = "snmp"
	o.MAC = ""
	o.VRF = "vrf"
	o.Evidence.Payload = map[string]any{"is_response": true, "response_source_ip": o.IP, "system_description": "H3C E528C-PWR"}
	m.ExpectBegin()
	m.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	m.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	m.ExpectQuery("SELECT CASE WHEN count\\(DISTINCT mac\\)").WithArgs(o.Node, o.IP, o.ObservedAt, o.Site, o.Domain, o.VLAN, o.VRF).WillReturnRows(sqlmock.NewRows([]string{"mac", "count"}).AddRow(nil, 2))
	m.ExpectCommit()
	out, err := ApplyHardwareRepairBatch(context.Background(), db, repairManifest(o), 0, 25)
	if err != nil || len(out) != 1 || out[0].Status != "excluded" || out[0].Reason != "identity_or_protocol_not_verified" {
		t.Fatalf("ambiguous binding admitted %+v %v", out, err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestHardwareRepairRejectsTamperingAndDoesNotClearScopeFailures(t *testing.T) {
	_, o := repairFixture()
	m := repairManifest(o)
	m.Entries[0].Observation.Evidence.Observer = map[string]any{"capture_scope_issue": "collector_instance_mismatch"}
	if err := m.Validate(); err == nil {
		t.Fatal("changed frozen input accepted")
	}
	raw, _ := json.Marshal(*m.Entries[0].Observation)
	m.Entries[0] = makeHardwareRepairEntry([5]string{"key", "source", "sadp", "", ""}, raw, *m.Entries[0].Observation)
	if m.Entries[0].ExcludedReason != "capture_scope_issue" || m.Entries[0].Observation != nil {
		t.Fatal("scope failure promoted")
	}
}

func TestHardwareRepairWithdrawalUsesExistingTombstonePath(t *testing.T) {
	db, m, _ := sqlmock.New()
	defer db.Close()
	_, o := repairFixture()
	o.Withdrawn = true
	m.ExpectBegin()
	m.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	m.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	m.ExpectExec("WITH incoming AS").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec("UPDATE passive_hardware_facts SET revoked=true").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	out, err := ApplyHardwareRepairBatch(context.Background(), db, repairManifest(o), 0, 25)
	if err != nil || len(out) != 1 || out[0].Status != "admitted" {
		t.Fatalf("withdrawal lost %+v %v", out, err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestHardwareRepairWindowIsExclusiveAndBatchLimitIsExplicit(t *testing.T) {
	_, o := repairFixture()
	m := repairManifest(o)
	m.Window.Until = o.ObservedAt
	if err := m.Validate(); err == nil {
		t.Fatal("exclusive end admitted")
	}
	m = repairManifest(o)
	if _, err := ApplyHardwareRepairBatch(context.Background(), nil, m, 0, 51); err == nil {
		t.Fatal("oversize batch accepted")
	}
}
