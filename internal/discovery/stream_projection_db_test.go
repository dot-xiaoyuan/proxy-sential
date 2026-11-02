package discovery

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type streamJSONFields map[string]string

type streamArchiveKeys []streamDiscoveryReceipt

type streamManifestResults []any

func (want streamManifestResults) Match(v driver.Value) bool {
	raw, ok := v.([]byte)
	if !ok {
		if value, isString := v.(string); isString {
			raw, ok = []byte(value), true
		}
	}
	if !ok {
		return false
	}
	var got []any
	return json.Unmarshal(raw, &got) == nil && reflect.DeepEqual(got, []any(want))
}

func TestLoadStreamFactVersionsRetainsCaptureScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	observed := time.Date(2026, 10, 31, 13, 29, 15, 0, time.UTC)
	mock.ExpectBegin()
	columns := []string{"device_key", "fact_key", "scope_id", "event_key", "visible_event_key", "revision", "first_observed_at", "observed_at", "valid_until", "withdrawn", "semantic_hash", "mac", "recognition_fields", "ip", "sensor_id", "site", "domain", "vlan", "vrf", "interface_name", "protocol", "address_binding"}
	mock.ExpectQuery("SELECT f.device_key,f.fact_key,f.scope_id").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows(columns).AddRow("device-1", "fact-1", "scope-1", "event-1", "event-1", 1, observed, observed, observed.Add(time.Minute), false, "hash", "", []byte(`{}`), "", "sensor", "site", "domain", "", "", "bond0", "arp", false))
	items := []streamPreparedDiscovery{{HasFact: true, Fact: streamDiscoveryFact{Device: "device-1", Key: "fact-1"}}}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	facts, err := loadStreamFactVersions(context.Background(), tx, "fresh", items)
	if err != nil {
		t.Fatal(err)
	}
	if facts["device-1\x00fact-1"].Scope != "scope-1" {
		t.Fatalf("capture scope lost while loading prior fact: %+v", facts)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func (want streamArchiveKeys) Match(v driver.Value) bool {
	raw, ok := v.([]byte)
	if !ok {
		if value, isString := v.(string); isString {
			raw, ok = []byte(value), true
		}
	}
	if !ok {
		return false
	}
	var rows []struct {
		Ordinal int    `json:"ordinal"`
		Scope   string `json:"scope_id"`
		Key     string `json:"event_key"`
		Hash    string `json:"content_sha256"`
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != len(want) {
		return false
	}
	for i, row := range rows {
		if row.Ordinal != i || row.Scope != want[i].Scope || row.Key != want[i].Key || row.Hash != want[i].Hash {
			return false
		}
	}
	return true
}

func (want streamJSONFields) Match(v driver.Value) bool {
	raw, ok := v.(string)
	if !ok {
		if b, isBytes := v.([]byte); isBytes {
			raw, ok = string(b), true
		}
	}
	if !ok {
		return false
	}
	var rows []map[string]any
	if json.Unmarshal([]byte(raw), &rows) != nil || len(rows) != 1 {
		return false
	}
	for key, value := range want {
		var actual any = rows[0]
		for _, part := range strings.Split(key, ".") {
			object, ok := actual.(map[string]any)
			if !ok {
				return false
			}
			actual = object[part]
		}
		if actual != value {
			return false
		}
	}
	return true
}

func TestReserveStreamDiscoveryKeysAvoidsFullReceiptLookup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("new", "2026-11-01T08:00:00Z", 600)}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys").WithArgs("fresh", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(items[0].Receipt.Scope, items[0].Receipt.Key, items[0].Receipt.Hash))
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := reserveStreamDiscoveryKeys(context.Background(), tx, segment.Epoch, streamAcceptedMonth(segment.AcceptedAt), items)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 1 || !fresh[items[0].Receipt.Scope+"\x00"+items[0].Receipt.Key] {
		t.Fatalf("fresh key missing: %+v", fresh)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReserveCompactKeysDualWritesForCompatibleRollback(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("stream2-fixed", "2026-11-01T08:00:00Z", 600)}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	key := items[0].Receipt
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(key.Scope, key.Key, key.Hash))
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys\\(").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(key.Scope, key.Key, key.Hash))
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := reserveStreamDiscoveryCompactKeys(context.Background(), tx, segment.Epoch, streamAcceptedMonth(segment.AcceptedAt), items, true, "")
	if err != nil || !fresh[key.Scope+"\x00"+key.Key] {
		t.Fatalf("dual write lost fresh key: %v %v", fresh, err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReserveCompactKeysRollbackDoesNotReplayCommittedCompactOnlyKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("stream2-fixed", "2026-11-01T08:00:00Z", 600)}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	key := items[0].Receipt
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}))
	mock.ExpectQuery("JOIN stream_discovery_event_keys_compact k").WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(key.Scope, key.Key, key.Hash))
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := reserveStreamDiscoveryCompactKeys(context.Background(), tx, segment.Epoch, streamAcceptedMonth(segment.AcceptedAt), items, true, "")
	if err != nil || len(fresh) != 0 {
		t.Fatalf("rollback replayed committed compact key: %v %v", fresh, err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReserveCompactKeysOnlyNeedsCompactLedgerAfterCutover(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("stream2-fixed", "2026-11-01T08:00:00Z", 600)}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	key := items[0].Receipt
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(key.Scope, key.Key, key.Hash))
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := reserveStreamDiscoveryCompactKeys(context.Background(), tx, segment.Epoch, streamAcceptedMonth(segment.AcceptedAt), items, false, "")
	if err != nil || !fresh[key.Scope+"\x00"+key.Key] {
		t.Fatalf("compact key not admitted: %v %v", fresh, err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReserveCompactKeyDigestCollisionFailsClosed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("stream2-fixed", "2026-11-01T08:00:00Z", 600)}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}))
	mock.ExpectQuery("JOIN stream_discovery_event_keys_compact k").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}))
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reserveStreamDiscoveryCompactKeys(context.Background(), tx, segment.Epoch, streamAcceptedMonth(segment.AcceptedAt), items, false, ""); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("digest collision did not fail closed: %v", err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReserveStreamDiscoveryKeysReadsOnlyCollisions(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{
		streamDiscoveryEvent("new", "2026-11-01T08:00:00Z", 600),
		streamDiscoveryEvent("repeat", "2026-11-01T08:00:00Z", 600),
	}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys").WithArgs("fresh", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(items[0].Receipt.Scope, items[0].Receipt.Key, items[0].Receipt.Hash))
	mock.ExpectQuery("FROM stream_discovery_event_keys r").WithArgs("fresh", streamJSONFields{"event_key": items[1].Receipt.Key, "scope_id": items[1].Receipt.Scope}).WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(items[1].Receipt.Scope, items[1].Receipt.Key, items[1].Receipt.Hash))
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := reserveStreamDiscoveryKeys(context.Background(), tx, segment.Epoch, streamAcceptedMonth(segment.AcceptedAt), items)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 1 || !fresh[items[0].Receipt.Scope+"\x00"+items[0].Receipt.Key] || fresh[items[1].Receipt.Scope+"\x00"+items[1].Receipt.Key] {
		t.Fatalf("collision must not project twice: %+v", fresh)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryCrossMonthRetryUsesGlobalEventKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", SourcePath: "/log/dns.log", ArchiveMonth: "202611", AcceptedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Events: []normalized.Event{event}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys").WithArgs("fresh", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}))
	mock.ExpectQuery("FROM stream_discovery_event_keys r").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "november-retry", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryConflictingRetryRollsBack(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}))
	mock.ExpectQuery("FROM stream_discovery_event_keys r").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow("scope-a", "fresh:fixed-position", "different-content"))
	mock.ExpectRollback()
	err = (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "november-conflict", segment)
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("content conflict was not isolated: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryReceiptCarriesStableBodyLocator(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := streamDiscoveryEvent("event-a", "2026-10-24T10:00:00Z", 600)
	segment := streamlog.Segment{Epoch: "fresh", ArchiveMonth: "202610", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{event}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_discovery_receipts").WithArgs(sqlmock.AnyArg(), "fresh", streamJSONFields{"event_key": "fresh:event-a", "scope_id": "scope-a", "body_ref.class": "evidence", "body_ref.month": "202610", "body_ref.scope": "scope-a", "body_ref.key": "fresh:event-a", "body_ref.sha256": items[0].Receipt.Hash}, "pending", nil).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = writeStreamDiscoveryReceipts(context.Background(), tx, streamAcceptedMonth(segment.AcceptedAt), segment, "segment-a", "event", items); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoverySegmentReceiptBindsMarkerWithoutPendingState(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := finalizationWitnessSegment()
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_discovery_receipts").WithArgs(sqlmock.AnyArg(), segment.Epoch,
		streamJSONFields{"event_key": items[0].Receipt.Key, "scope_id": items[0].Receipt.Scope}, "segment", "segment-a").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStreamDiscoveryReceipts(context.Background(), tx, streamAcceptedMonth(segment.AcceptedAt), segment, "segment-a", "segment", items); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExpireStreamDiscoveryStatesUsesBoundedDueKeys(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state WHERE expires_at<=now\\(\\)").WithArgs(100).WillReturnRows(sqlmock.NewRows([]string{"epoch", "device_key"}))
	mock.ExpectCommit()
	count, err := (StreamDiscoveryProjector{DB: db}).ExpireStreamDiscoveryStates(context.Background(), 100)
	if err != nil || count != 0 {
		t.Fatalf("empty due set: %d %v", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamArchiveConfirmationUsesOriginalMonthAndAtomicReceiptChecks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		matched bool
	}{
		{"cross_month_and_idempotent", true},
		{"missing_or_conflicting_receipt_rolls_back", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			segment := streamlog.Segment{Epoch: "fresh", ArchiveMonth: "202611", AcceptedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Events: []normalized.Event{
				streamDiscoveryEvent("first", "2026-10-24T10:00:00Z", 600),
				streamDiscoveryEvent("second", "2026-10-24T10:00:00Z", 600),
			}}
			items, err := prepareStreamDiscovery(segment)
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectBegin()
			matched := 2
			if !tc.matched {
				matched = 1
			}
			mock.ExpectQuery(`WITH input AS MATERIALIZED.*jsonb_to_recordset.*ORDER BY v\.ordinal.*FOR UPDATE.*UPDATE stream_discovery_receipts.*SELECT count\(\*\) FROM receipt`).
				WithArgs(segment.Epoch, streamArchiveKeys{items[0].Receipt, items[1].Receipt}).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(matched))
			if tc.matched {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
			err = (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "november-retry", segment)
			if tc.matched && err != nil {
				t.Fatal(err)
			}
			if !tc.matched && !errors.Is(err, streamlog.ErrUnconfirmed) {
				t.Fatalf("missing receipt accepted: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReconcileStreamProjectionReadsCommittedMarkerWithoutRewriting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", SourcePath: "/log/dns.log", ArchiveMonth: "202611", AcceptedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	digest := contentHash(struct {
		Epoch, Source, Path, File, RawSHA string
		Start, End                        int64
		Events                            []streamDiscoveryReceipt
	}{segment.Epoch, segment.Source, segment.SourcePath, segment.FileID, segment.RawSHA256, segment.StartOffset, segment.EndOffset, streamReceiptList(prepared)})
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(digest))
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionDetectsConflictingCommittedMarker(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow("other"))
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("expected content conflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionMissingMarkerRetriesProjection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}))
	mock.ExpectQuery("FROM stream_discovery_event_keys r").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionMissingMarkerRacesCommittedWriter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	digest := streamProjectionSegmentHash(segment, prepared)
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1 FOR UPDATE`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(digest))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionReadFailureDoesNotAssumeMissing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	readErr := errors.New("database unavailable")
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnError(readErr)
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); !errors.Is(err, readErr) {
		t.Fatalf("expected read failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
