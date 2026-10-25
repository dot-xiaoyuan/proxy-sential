package store

import (
	"context"
	"database/sql/driver"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// noDocument matches an applied-events payload that carries no event documents: only the old
// calibration replay read them, and they were the bulk of that table.
type noDocument struct{}

func (noDocument) Match(v driver.Value) bool {
	raw, ok := v.([]byte)
	if !ok {
		text, isText := v.(string)
		raw, ok = []byte(text), isText
	}
	return ok && !strings.Contains(string(raw), `"document"`)
}

func TestFreshFragmentApplyUsesPositionFactsWithoutLegacyRandomIndexes(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "false")
	db, mock := newReconcileMock(t)
	snapshot := adapterSnapshot(t, "s1", "a1", "10.0.0.1")
	w := identityInboxWork{Scope: IdentityScopeKey(reconcileScope), BatchID: "fresh-batch", Generation: "initial", Epoch: 7, Sequence: 1, Events: snapshot.Events,
		Batches: []identityInboxBatch{{BatchID: "fresh-batch", Sequence: 1, Offset: 0, Count: len(snapshot.Events), Format: "fragments", AcceptedAt: time.Now().UTC()}}}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT COALESCE\(lease_epoch=\$2`).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(true))
	mock.ExpectExec(`INSERT INTO identity_stream_policy_facts`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT shared_wake_identity_stream_batch`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`UPDATE identity_ingest_batches b SET processed_offset`).WillReturnRows(sqlmock.NewRows([]string{"sequence", "completed"}).AddRow(int64(1), true))
	mock.ExpectExec(`SELECT scope_key FROM identity_pipeline_scopes WHERE scope_key=\$1 FOR UPDATE`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(applyScopeProgressSQL)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`WITH ready AS`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	if err := (&PostgresStore{db: db}).applyIdentityInbox(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// An apply records facts, deduplication and progress only. It must not maintain the generation-keyed
// current-state tables (identity_apply_address) or write per-batch statistics: both locked hot rows
// on every batch and fed the index bloat that saturated the disk.
func TestInboxApplyWritesFactsDedupAndProgressOnly(t *testing.T) {
	db, mock := newReconcileMock(t)
	snapshot := adapterSnapshot(t, "s1", "a1", "10.0.0.1")
	w := identityInboxWork{Scope: IdentityScopeKey(reconcileScope), BatchID: "b1", Generation: "initial", Epoch: 7, Sequence: 1, Events: snapshot.Events,
		Batches: []identityInboxBatch{{BatchID: "b1", Sequence: 1, Offset: 0, Count: len(snapshot.Events)}}}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT COALESCE\(lease_epoch=\$2`).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(true))
	mock.ExpectExec(`INSERT INTO policy_identity_observations`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO identity_applied_events(scope_key,event_id,batch_sequence,ordinal,observed_at)`)).
		WithArgs(w.Scope, noDocument{}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`UPDATE identity_ingest_batches b SET processed_offset`).WillReturnRows(sqlmock.NewRows([]string{"sequence", "completed"}).AddRow(int64(1), true))
	mock.ExpectExec(`SELECT scope_key FROM identity_pipeline_scopes WHERE scope_key=\$1 FOR UPDATE`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(applyScopeProgressSQL)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (&PostgresStore{db: db}).applyIdentityInbox(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityInboxCanceledWorkerReleasesOnlyItsLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := identityInboxWork{Scope: "scope", Epoch: 7, Generation: "generation"}
	mock.ExpectExec(`UPDATE identity_pipeline_scopes SET lease_until=.*lease_epoch=\$2 AND current_generation=\$4`).WithArgs("scope", int64(7), "identity_processing_failed", "generation").WillReturnResult(sqlmock.NewResult(0, 1))
	if err = (&PostgresStore{db: db}).releaseIdentityInboxFailure(ctx, w); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
