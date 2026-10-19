package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// passthroughConverter keeps []string array arguments intact, as the pgx driver does at runtime.
type passthroughConverter struct{}

func (passthroughConverter) ConvertValue(v any) (driver.Value, error) { return v, nil }

func newReconcileMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp), sqlmock.ValueConverterOption(passthroughConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, mock
}

func TestSessionInScopeAcceptsLegacyEmptySensorOnly(t *testing.T) {
	row := eventRow("s", "a", "10.0.0.1", reconcileObserved)
	if !sessionInScope(row, reconcileScope) {
		t.Fatal("same scope rejected")
	}
	row.SensorID = ""
	if !sessionInScope(row, reconcileScope) {
		t.Fatal("legacy empty sensor must match by source, campus and domain")
	}
	row.SensorID = "ncu-other-sensor"
	if sessionInScope(row, reconcileScope) {
		t.Fatal("different non-empty sensor matched")
	}
	row.SensorID = reconcileScope.SensorID
	row.CampusID = "other-campus"
	if sessionInScope(row, reconcileScope) {
		t.Fatal("different campus matched")
	}
}

func TestAccountSessionFromReconcileCarriesKeyScopeAndProvenance(t *testing.T) {
	snapshot := snapshotWith()
	member := keyedMember("instance-B:S-1", rotatedLoginKey)
	row := accountSessionFromReconcile(member, snapshot)
	if row.SessionID != member.ID || row.LoginKey != rotatedLoginKey || row.SensorID != reconcileScope.SensorID {
		t.Fatalf("identity lost: %+v", row)
	}
	if row.Source != reconcileScope.Source || row.CampusID != reconcileScope.CampusID || row.AccessDomain != reconcileScope.AccessDomain {
		t.Fatalf("scope lost: %+v", row)
	}
	if row.SessionStatus != "reconcile" || row.EndedAt != "" {
		t.Fatalf("status or end wrong: %+v", row)
	}
	if row.LastConfirmedAt != reconcileObserved.Format(time.RFC3339Nano) {
		t.Fatalf("confirmed=%q", row.LastConfirmedAt)
	}
	if row.StartedAt != member.StartedAt.Format(time.RFC3339Nano) {
		t.Fatalf("started=%q", row.StartedAt)
	}
	if row.RawRef["snapshot_id"] != snapshot.SnapshotID || row.RawRef["sensor_id"] != reconcileScope.SensorID {
		t.Fatalf("provenance missing: %+v", row.RawRef)
	}
}

func TestStoredRowRoundTripsToPolicySession(t *testing.T) {
	confirmed := reconcileObserved.Add(-time.Minute)
	stored := storedSession{
		SessionID: "sess-R", AccountID: "acct-R", IP: "10.9.9.9", MAC: "aa:bb", Source: reconcileScope.Source,
		SensorID: reconcileScope.SensorID, CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain,
		LoginKey: rotatedLoginKey, StartedAt: reconcileObserved.Add(-time.Hour), LastConfirmedAt: confirmed.Format(time.RFC3339Nano),
	}
	row := sessionFromStoredRow(stored)
	if row.ID != "sess-R" || row.LoginKey != rotatedLoginKey || !sessionInScope(row, reconcileScope) {
		t.Fatalf("stored row lost identity or scope: %+v", row)
	}
	if !row.ConfirmedAt.Equal(confirmed) || !row.EndedAt.IsZero() {
		t.Fatalf("confirmed=%s ended=%s", row.ConfirmedAt, row.EndedAt)
	}
	stored.EndedAt = sql.NullTime{Time: reconcileObserved, Valid: true}
	if got := sessionFromStoredRow(stored); !got.EndedAt.Equal(reconcileObserved) {
		t.Fatalf("ended=%s", got.EndedAt)
	}
}

func TestLoadSnapshotSessionRowsReadsScopeAndMemberKeys(t *testing.T) {
	db, mock := newReconcileMock(t)
	columns := sessionRowColumns()
	mock.ExpectQuery(`WITH m AS \(SELECT unnest\(\$5::text\[\]\)`).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, sqlmock.AnyArg(), sqlmock.AnyArg(), reconcileEndBatch).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("sess-open", "acct-1", "", "10.157.2.191", "", reconcileScope.Source, reconcileObserved.Add(-time.Hour), nil, rotatedLoginKey, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "2026-10-16T06:10:00Z"))
	mock.ExpectQuery(`WHERE session_id = ANY\(\$1::text\[\]\)`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(columns))
	mock.ExpectQuery(`WHERE login_key <> '' AND login_key = ANY\(\$1::text\[\]\)`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("instance-A:S-1", "acct-1", "", "10.157.2.191", "", reconcileScope.Source, reconcileObserved.Add(-2*time.Hour), nil, rotatedLoginKey, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "2026-10-16T06:10:00Z"))
	snapshot := snapshotWith(keyedMember("instance-B:S-1", rotatedLoginKey))
	rows, err := loadSnapshotSessionRows(context.Background(), db, snapshot, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d want open row and key match", len(rows))
	}
	for _, row := range rows {
		if row.LoginKey != rotatedLoginKey || row.SensorID != reconcileScope.SensorID || row.AccessDomain != reconcileScope.AccessDomain {
			t.Fatalf("row not reconstructed: %+v", row)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplySessionReconcileActionsWritesEachKindOnce(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectExec(`INSERT INTO account_sessions\(`).WillReturnResult(sqlmock.NewResult(0, 1))
	// The session upsert also rewrites policy_metadata in a second statement.
	mock.ExpectExec(`UPDATE account_sessions s SET policy_metadata = NULLIF`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE account_sessions AS s SET policy_metadata`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE account_sessions AS s SET ended_at`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	actions := []sessionReconcileAction{
		{Kind: sessionReconcileInsert, SessionID: "new", Row: keyedMember("new", "k|1")},
		{Kind: sessionReconcileConfirm, SessionID: "held", At: reconcileObserved},
		{Kind: sessionReconcileEnd, SessionID: "gone", At: reconcileObserved},
	}
	stats, err := applySessionReconcileActions(context.Background(), db, snapshotWith(), actions)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Inserted != 1 || stats.Confirmed != 1 || stats.Ended != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplySessionReconcileActionsWithNothingToDoIssuesNoStatement(t *testing.T) {
	db, mock := newReconcileMock(t)
	stats, err := applySessionReconcileActions(context.Background(), db, snapshotWith(), nil)
	if err != nil || stats != (sessionReconcileStats{}) {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAccessDomainIsReadFromMetadataNotColumn(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectQuery(`COALESCE\(policy_metadata->>'access_domain'`).WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	mock.ExpectQuery(`.*`).WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	mock.ExpectQuery(`.*`).WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	if _, err := loadSnapshotSessionRows(context.Background(), db, snapshotWith(keyedMember("x", "k|1")), true); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sessionSelectSQL, " access_domain,") {
		t.Fatal("access_domain must not be selected as a column")
	}
}

// Only open rows that are absent from the snapshot are read as end candidates, in bounded batches.
// Reading every open row of the source costs hundreds of thousands of rows per snapshot.
func TestEndCandidatesAreAbsentOpenRowsOnly(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectQuery(`WITH m AS \(SELECT unnest\(\$5::text\[\]\)`).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, sqlmock.AnyArg(), sqlmock.AnyArg(), reconcileEndBatch).
		WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	snapshot := snapshotWith()
	if _, err := loadSnapshotSessionRows(context.Background(), db, snapshot, true); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A full open-row scan must not be issued.
func TestNoFullOpenRowScanPerSnapshot(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`WHERE session_id = ANY`).WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	mock.ExpectQuery(`NOT EXISTS`).WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	if _, err := loadSnapshotSessionRows(context.Background(), db, snapshotWith(snapshotMember("sess-A", "acct-1", "10.0.0.1")), true); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// With ends disabled the pass must not issue the end-candidate read at all.
func TestDisabledEndsIssueNoCandidateRead(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectQuery(`WHERE session_id = ANY`).WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	if _, err := loadSnapshotSessionRows(context.Background(), db, snapshotWith(snapshotMember("sess-A", "acct-1", "10.0.0.1")), false); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
