package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func backfillWatermarkRows(facts ...streamDiscoveryFact) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"device_key", "fact_key", "device_type", "protocol", "semantic_hash", "event_key", "visible_event_key", "revision", "first_observed_at", "observed_at", "valid_until", "withdrawn"})
	for _, fact := range facts {
		rows.AddRow(fact.Device, fact.Key, fact.DeviceType, fact.Protocol, fact.SemanticHash, fact.Event, fact.EvidenceEvent, fact.Revision,
			fact.FirstObserved, fact.Observed, fact.ValidUntil, fact.Withdrawn)
	}
	return rows
}

func TestSelectStreamNetworkBackfillPageKeepsUnprocessedCursor(t *testing.T) {
	page := []streamNetworkBackfillFact{
		{Device: "a", Fact: "01", Type: "router", Protocol: "ssdp"},
		{Device: "a", Fact: "02", Type: "router", Protocol: "ssdp"},
		{Device: "b", Fact: "01", Type: "printer", Protocol: "mdns"},
		{Device: "c", Fact: "01", Type: "gateway", Protocol: "ssdp"},
	}
	selected, err := selectStreamNetworkBackfillPage(page, 4, StreamNetworkBackfillLimits{MaxRows: 4, MaxDevices: 1, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Scanned != 3 || selected.CursorDevice != "b" || selected.CursorFact != "01" || selected.Complete || len(selected.Devices) != 1 || selected.Devices[0] != "a" {
		t.Fatalf("cursor skipped unprocessed candidate: %+v", selected)
	}
	selected, err = selectStreamNetworkBackfillPage(page[:3], 3, StreamNetworkBackfillLimits{MaxRows: 5, MaxDevices: 1, MaxBytes: 1024})
	if err != nil || !selected.Complete || selected.CursorDevice != "b" || len(selected.Devices) != 1 {
		t.Fatalf("complete page did not retain its candidate: %+v %v", selected, err)
	}
	if _, err := selectStreamNetworkBackfillPage(page[:1], 1, StreamNetworkBackfillLimits{MaxRows: 1, MaxDevices: 1, MaxBytes: 1}); err == nil {
		t.Fatal("oversized first row must fail without cursor movement")
	}
}

func TestSelectStreamNetworkBackfillPageStopsBeforeSecondDevice(t *testing.T) {
	page := make([]streamNetworkBackfillFact, 2)
	for i := range page {
		page[i] = streamNetworkBackfillFact{Device: fmt.Sprintf("d%02d", i+1), Fact: "01", Type: "router", Protocol: "ssdp"}
	}
	selected, err := selectStreamNetworkBackfillPage(page, 2, StreamNetworkBackfillLimits{MaxRows: 10, MaxDevices: 1, MaxBytes: 1024})
	if err != nil || selected.Scanned != 1 || selected.CursorDevice != "d01" || selected.Complete || len(selected.Devices) != 1 {
		t.Fatalf("second network device must remain after checkpoint: %+v %v", selected, err)
	}
}

func TestStreamNetworkBackfillBusyDeviceDoesNotAdvanceCheckpoint(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_progress").WithArgs("epoch-a").WillReturnRows(sqlmock.NewRows([]string{"status", "cursor_device_key", "cursor_fact_key", "scanned_rows", "projected_devices", "active"}).AddRow("running", "", "", 0, 0, true))
	mock.ExpectQuery("FROM stream_discovery_facts").WithArgs("epoch-a", "", "", 2).WillReturnRows(sqlmock.NewRows([]string{"device_key", "fact_key", "device_type", "protocol"}).AddRow("a", "01", "router", "ssdp"))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_devices").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key"}))
	mock.ExpectRollback()
	projected := false
	_, err = (StreamDiscoveryProjector{DB: db}).backfillStreamNetworkStateStep(context.Background(), "epoch-a", StreamNetworkBackfillLimits{MaxRows: 2, MaxDevices: 1, MaxBytes: 1024}, func(stepCtx context.Context, _ *sql.Tx, _ string, _ []string) error {
		deadline, ok := stepCtx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatalf("backfill transaction lacks total deadline: %v %t", deadline, ok)
		}
		projected = true
		return ErrStreamNetworkBackfillBusy
	})
	if !errors.Is(err, ErrStreamNetworkBackfillBusy) || !projected {
		t.Fatalf("busy realtime device should yield without checkpoint: %v projected=%t", err, projected)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkBackfillProcessedDeviceAdvancesWithoutRebuild(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_progress").WithArgs("epoch-a").WillReturnRows(sqlmock.NewRows([]string{"status", "cursor_device_key", "cursor_fact_key", "scanned_rows", "projected_devices", "active"}).AddRow("running", "a", "01", 1, 1, true))
	mock.ExpectQuery("FROM stream_discovery_facts").WithArgs("epoch-a", "a", "01", 2).WillReturnRows(sqlmock.NewRows([]string{"device_key", "fact_key", "device_type", "protocol"}).AddRow("a", "02", "router", "ssdp"))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_devices").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key"}).AddRow("a"))
	mock.ExpectExec("UPDATE stream_discovery_network_backfill_progress").WithArgs("epoch-a", "a", "02", 1, 0, "complete").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	projected := false
	status, err := (StreamDiscoveryProjector{DB: db}).backfillStreamNetworkStateStep(context.Background(), "epoch-a", StreamNetworkBackfillLimits{MaxRows: 2, MaxDevices: 1, MaxBytes: 1024}, func(context.Context, *sql.Tx, string, []string) error {
		projected = true
		return nil
	})
	if err != nil || projected || status.ScannedRows != 2 || status.ProjectedDevices != 1 || status.Status != "complete" {
		t.Fatalf("processed device was rebuilt or cursor failed: %+v %v projected=%t", status, err, projected)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkBackfillStepCommitsOnlyAfterProjection(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_progress").WithArgs("epoch-a").WillReturnRows(sqlmock.NewRows([]string{"status", "cursor_device_key", "cursor_fact_key", "scanned_rows", "projected_devices", "active"}).AddRow("running", "", "", 0, 0, true))
	mock.ExpectQuery("FROM stream_discovery_facts").WithArgs("epoch-a", "", "", 3).WillReturnRows(sqlmock.NewRows([]string{"device_key", "fact_key", "device_type", "protocol"}).AddRow("a", "01", "router", "ssdp").AddRow("b", "01", "printer", "mdns"))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_devices").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key"}))
	mock.ExpectExec("INSERT INTO stream_discovery_network_backfill_devices").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE stream_discovery_network_backfill_gaps SET resolved_at").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE stream_discovery_network_backfill_progress").WithArgs("epoch-a", "b", "01", 2, 1, "complete").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	projected := false
	project := func(_ context.Context, _ *sql.Tx, epoch string, keys []string) error {
		if epoch != "epoch-a" || len(keys) != 1 || keys[0] != "a" {
			t.Fatalf("unexpected projection input: %s %v", epoch, keys)
		}
		projected = true
		return nil
	}
	status, err := (StreamDiscoveryProjector{DB: db}).backfillStreamNetworkStateStep(context.Background(), "epoch-a", StreamNetworkBackfillLimits{MaxRows: 3, MaxDevices: 1, MaxBytes: 1024}, project)
	if err != nil || !projected || status.Status != "complete" || status.ScannedRows != 2 || status.ProjectedDevices != 1 {
		t.Fatalf("step failed: %+v %v projected=%t", status, err, projected)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkBackfillFailureKeepsCheckpointAndRecordsGap(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_progress").WithArgs("epoch-a").WillReturnRows(sqlmock.NewRows([]string{"status", "cursor_device_key", "cursor_fact_key", "scanned_rows", "projected_devices", "active"}).AddRow("running", "a", "01", 1, 0, true))
	mock.ExpectQuery("FROM stream_discovery_facts").WithArgs("epoch-a", "a", "01", 2).WillReturnRows(sqlmock.NewRows([]string{"device_key", "fact_key", "device_type", "protocol"}).AddRow("b", "01", "router", "ssdp"))
	mock.ExpectQuery("FROM stream_discovery_network_backfill_devices").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key"}))
	mock.ExpectRollback()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_discovery_network_backfill_gaps").WithArgs("epoch-a", "b", "01", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE stream_discovery_network_backfill_progress SET status='failed'").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	_, err = (StreamDiscoveryProjector{DB: db}).backfillStreamNetworkStateStep(context.Background(), "epoch-a", StreamNetworkBackfillLimits{MaxRows: 2, MaxDevices: 1, MaxBytes: 1024}, func(context.Context, *sql.Tx, string, []string) error { return errors.New("projection failed") })
	if err == nil || err.Error() != "projection failed" {
		t.Fatalf("expected projection failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkBackfillWithdrawnFactOnlyRemovesDerivedType(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	fact := streamDiscoveryFact{Epoch: "epoch-a", Device: "d1", Key: "router-1", Scope: "scope-a", Protocol: "ssdp", DeviceType: "router", Event: "event-1", EvidenceEvent: "event-1", FirstObserved: now.Add(-time.Hour), Observed: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), Withdrawn: true}
	factRaw, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state").WithArgs("epoch-a", "d1").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "result_version", "document"}).AddRow("scope-a", int64(10), []byte(`{"network_device_type":"router","network_type_status":"clue","current":true}`)))
	mock.ExpectQuery("SELECT to_jsonb\\(f\\) FROM stream_discovery_facts").WithArgs("epoch-a", "d1", "scope-a").WillReturnRows(sqlmock.NewRows([]string{"fact"}).AddRow(factRaw))
	mock.ExpectExec("SET LOCAL statement_timeout='100ms'").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("hashtextextended").WithArgs("d1").WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	mock.ExpectQuery("SELECT device_key,scope_id,result_version").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "result_version"}).AddRow("d1", "scope-a", int64(10)))
	mock.ExpectQuery("FROM jsonb_to_recordset").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(backfillWatermarkRows(fact))
	mock.ExpectQuery("pg_try_advisory_xact_lock\\(9184,213\\)").WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	mock.ExpectExec("UPDATE stream_discovery_device_state SET").WithArgs("epoch-a", "d1", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM stream_discovery_network_state").WithArgs("epoch-a", "d1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := backfillStreamNetworkDeviceStates(context.Background(), tx, "epoch-a", []string{"d1"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkBackfillIdenticalStateDoesNotBumpVersion(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	fact := streamDiscoveryFact{Epoch: "epoch-a", Device: "d1", Key: "router-1", Scope: "scope-a", Protocol: "ssdp", DeviceType: "gateway", Event: "event-1", EvidenceEvent: "event-1", FirstObserved: now.Add(-time.Hour), Observed: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
	state, err := buildStreamDiscoveryState("epoch-a", "d1", []streamDiscoveryFact{fact}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	factRaw, _ := json.Marshal(fact)
	oldRaw, _ := json.Marshal(state.Document)
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state").WithArgs("epoch-a", "d1").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "result_version", "document"}).AddRow("scope-a", int64(10), oldRaw))
	mock.ExpectQuery("SELECT to_jsonb\\(f\\) FROM stream_discovery_facts").WithArgs("epoch-a", "d1", "scope-a").WillReturnRows(sqlmock.NewRows([]string{"fact"}).AddRow(factRaw))
	mock.ExpectExec("SET LOCAL statement_timeout='100ms'").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("hashtextextended").WithArgs("d1").WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	mock.ExpectQuery("SELECT device_key,scope_id,result_version").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "result_version"}).AddRow("d1", "scope-a", int64(10)))
	mock.ExpectQuery("FROM jsonb_to_recordset").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(backfillWatermarkRows(fact))
	mock.ExpectExec("INSERT INTO stream_discovery_network_state").WithArgs("epoch-a", "d1", "scope-a", "gateway", "clue", fact.Observed, fact.ValidUntil).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := backfillStreamNetworkDeviceStates(context.Background(), tx, "epoch-a", []string{"d1"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkBackfillBuildsBeforeDeviceAndVersionLocks(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	mock.ExpectBegin()
	facts := make([]streamDiscoveryFact, 0, 1)
	for _, key := range []string{"d1"} {
		fact := streamDiscoveryFact{Epoch: "epoch-a", Device: key, Key: "router-1", Scope: "scope-a", Protocol: "ssdp", DeviceType: "router", Event: "event-" + key, EvidenceEvent: "event-" + key, FirstObserved: now.Add(-time.Hour), Observed: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
		facts = append(facts, fact)
		raw, err := json.Marshal(fact)
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery("FROM stream_discovery_device_state").WithArgs("epoch-a", key).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "result_version", "document"}).AddRow("scope-a", int64(10), []byte(`{"current":true}`)))
		mock.ExpectQuery("SELECT to_jsonb\\(f\\) FROM stream_discovery_facts").WithArgs("epoch-a", key, "scope-a").WillReturnRows(sqlmock.NewRows([]string{"fact"}).AddRow(raw))
	}
	mock.ExpectExec("SET LOCAL statement_timeout='100ms'").WillReturnResult(sqlmock.NewResult(0, 0))
	for _, key := range []string{"d1"} {
		mock.ExpectQuery("hashtextextended").WithArgs(key).WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	}
	mock.ExpectQuery("SELECT device_key,scope_id,result_version").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "result_version"}).AddRow("d1", "scope-a", int64(10)))
	mock.ExpectQuery("FROM jsonb_to_recordset").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(backfillWatermarkRows(facts...))
	mock.ExpectQuery("pg_try_advisory_xact_lock\\(9184,213\\)").WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	for _, key := range []string{"d1"} {
		mock.ExpectExec("UPDATE stream_discovery_device_state SET").WithArgs("epoch-a", key, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("INSERT INTO stream_discovery_network_state").WithArgs("epoch-a", key, "scope-a", "router", "clue", now.Add(-time.Minute), now.Add(time.Hour)).WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := backfillStreamNetworkDeviceStates(context.Background(), tx, "epoch-a", []string{"d1"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkBackfillYieldsWhenRealtimeChangesStateOrFact(t *testing.T) {
	for _, tc := range []struct {
		name           string
		version        int64
		factLeaseMoved bool
	}{
		{name: "state version", version: 11},
		{name: "network fact lease", version: 10, factLeaseMoved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Now().UTC().Truncate(time.Second)
			fact := streamDiscoveryFact{Epoch: "epoch-a", Device: "d1", Key: "router-1", Scope: "scope-a", Protocol: "ssdp", DeviceType: "router", Event: "event-1", EvidenceEvent: "event-1", FirstObserved: now.Add(-time.Hour), Observed: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
			raw, _ := json.Marshal(fact)
			mock.ExpectBegin()
			mock.ExpectQuery("FROM stream_discovery_device_state").WithArgs("epoch-a", "d1").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "result_version", "document"}).AddRow("scope-a", int64(10), []byte(`{"current":true}`)))
			mock.ExpectQuery("SELECT to_jsonb\\(f\\) FROM stream_discovery_facts").WithArgs("epoch-a", "d1", "scope-a").WillReturnRows(sqlmock.NewRows([]string{"fact"}).AddRow(raw))
			mock.ExpectExec("SET LOCAL statement_timeout='100ms'").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("hashtextextended").WithArgs("d1").WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
			mock.ExpectQuery("SELECT device_key,scope_id,result_version").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"device_key", "scope_id", "result_version"}).AddRow("d1", "scope-a", tc.version))
			if tc.factLeaseMoved {
				changed := fact
				changed.ValidUntil = changed.ValidUntil.Add(time.Minute)
				mock.ExpectQuery("FROM jsonb_to_recordset").WithArgs("epoch-a", sqlmock.AnyArg()).WillReturnRows(backfillWatermarkRows(changed))
			}
			mock.ExpectRollback()
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			err = backfillStreamNetworkDeviceStates(context.Background(), tx, "epoch-a", []string{"d1"})
			if !errors.Is(err, ErrStreamNetworkBackfillBusy) {
				t.Fatalf("concurrent change must yield before derived writes: %v", err)
			}
			_ = tx.Rollback()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
