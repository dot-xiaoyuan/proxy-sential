package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func identityRecoveryMockRows(batchCount int64) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"accepted_sequence", "processed_sequence", "pending_records", "export_pending_records",
		"current_generation", "lease_epoch", "epoch", "start_offset", "file_id", "parser_version", "capture_scope_sha256",
		"legacy_cutoff_at", "sensor_id", "legacy_cancel_id", "cancel_manifest_sha256", "batches", "fragments", "ready", "pending_ips", "receive", "consume", "export"}).
		AddRow(int64(673156), int64(672823), int64(2041), int64(9894), "generation", int64(7),
			"identity-fresh-b2-20261025", int64(784452), "redis:list:antiproxy:127.0.0.1", "identity-http-v2", "",
			time.Date(2026, 10, 25, 0, 20, 1, 0, time.UTC), "ncu-auth-redis", "redis-quarantine:identity-fresh-b2-20261025", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", batchCount, int64(0), int64(0), int64(0), int64(0), int64(0), int64(0))
}

func TestPlanIdentityFreshRecoveryPreservesUnverifiableGap(t *testing.T) {
	request := IdentityFreshRecoveryRequest{
		Scope:    IdentityScope{Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth"},
		OldEpoch: "identity-fresh-b2-20261025", NewEpoch: "identity-fresh-b3-20261102",
		PreviousRelease:          "2026.11.02-mirror-discovery-r59b",
		ExpectedAcceptedSequence: 673156, ExpectedProcessedSequence: 672823,
		ExpectedPendingRecords: 2041, ExpectedExportPendingRecords: 9894,
		ExpectedOldStartOffset: 784452,
		RedisAuditSHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RedisEventList:         "list:antiproxy:127.0.0.1",
		RedisProcessingList:    "list:antiproxy:127.0.0.1:proxy-sentinel-processing",
		RedisSourceLength:      100000,
		RedisProcessingLength:  2,
		RedisSampleAt:          time.Date(2026, 11, 2, 11, 50, 0, 0, time.UTC),
		RedisBoundaryJSON:      `{}`,
	}
	snapshot := identityFreshRecoverySnapshot{
		ScopeExists: true, ActiveEpoch: request.OldEpoch, ActiveStartOffset: 784452,
		AcceptedSequence: 673156, ProcessedSequence: 672823, PendingRecords: 2041,
		ExportPendingRecords: 9894, BatchCount: 0, FragmentCount: 0, PendingIPCount: 0,
		ParserVersion:        "identity-http-v2",
		FileID:               "redis:list:antiproxy:127.0.0.1",
		ReceiveProgressCount: 0, ConsumeProgressCount: 0, ExportProgressCount: 0,
	}
	plan, err := planIdentityFreshRecovery(request, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NewStartOffset != 673156 || plan.NextSequence != 673157 || plan.GapFirstSequence != 672824 || plan.GapLastSequence != 673156 {
		t.Fatalf("wrong fixed start or unresolved range: %+v", plan)
	}
	if plan.GapStatus != "unverifiable_gap" || plan.LegacyPendingRecords != 2041 || plan.LegacyExportPendingRecords != 9894 {
		t.Fatalf("old responsibilities were hidden or called complete: %+v", plan)
	}
	if plan.CancelRedisQueue || plan.MarkLegacyCompleted {
		t.Fatalf("valid Redis queue or old responsibilities would be skipped: %+v", plan)
	}
}

func TestPlanIdentityFreshRecoveryFailsClosedOnChangingEvidence(t *testing.T) {
	request := IdentityFreshRecoveryRequest{
		Scope:    IdentityScope{Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth"},
		OldEpoch: "old", NewEpoch: "new", PreviousRelease: "r59b",
		ExpectedAcceptedSequence: 673156, ExpectedProcessedSequence: 672823,
		ExpectedPendingRecords: 2041, ExpectedExportPendingRecords: 9894,
		ExpectedOldStartOffset: 784452,
		RedisAuditSHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RedisEventList:         "list:antiproxy:127.0.0.1",
		RedisProcessingList:    "list:antiproxy:127.0.0.1:proxy-sentinel-processing",
		RedisSourceLength:      100000,
		RedisProcessingLength:  2,
		RedisSampleAt:          time.Date(2026, 11, 2, 11, 50, 0, 0, time.UTC),
		RedisBoundaryJSON:      `{}`,
	}
	base := identityFreshRecoverySnapshot{ScopeExists: true, ActiveEpoch: "old", ActiveStartOffset: 784452,
		AcceptedSequence: 673156, ProcessedSequence: 672823, PendingRecords: 2041, ExportPendingRecords: 9894,
		ParserVersion: "identity-http-v2", FileID: "redis:list:antiproxy:127.0.0.1"}
	for name, mutate := range map[string]func(*identityFreshRecoverySnapshot){
		"new batch appeared":         func(s *identityFreshRecoverySnapshot) { s.BatchCount = 1 },
		"old cursor changed":         func(s *identityFreshRecoverySnapshot) { s.AcceptedSequence++ },
		"old cutover changed":        func(s *identityFreshRecoverySnapshot) { s.ActiveEpoch = "other" },
		"split progress exists":      func(s *identityFreshRecoverySnapshot) { s.ReceiveProgressCount = 1 },
		"pending IP evidence exists": func(s *identityFreshRecoverySnapshot) { s.PendingIPCount = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := base
			mutate(&snapshot)
			if _, err := planIdentityFreshRecovery(request, snapshot); err == nil {
				t.Fatal("unsafe recovery plan accepted")
			}
		})
	}
}

func TestApplyIdentityFreshRecoveryAtomicallyStartsOnlyNewProgress(t *testing.T) {
	request := IdentityFreshRecoveryRequest{
		Scope:    IdentityScope{Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth"},
		OldEpoch: "identity-fresh-b2-20261025", NewEpoch: "identity-fresh-b3-20261102", PreviousRelease: "r59b",
		ExpectedAcceptedSequence: 673156, ExpectedProcessedSequence: 672823, ExpectedPendingRecords: 2041,
		ExpectedExportPendingRecords: 9894, ExpectedOldStartOffset: 784452,
		RedisAuditSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RedisEventList:      "list:antiproxy:127.0.0.1",
		RedisProcessingList: "list:antiproxy:127.0.0.1:proxy-sentinel-processing",
		RedisSourceLength:   100000, RedisProcessingLength: 2,
		RedisSampleAt:     time.Date(2026, 11, 2, 11, 50, 0, 0, time.UTC),
		RedisBoundaryJSON: `{}`,
	}
	db, mock := newReconcileMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL lock_timeout`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SET LOCAL statement_timeout`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT s.accepted_sequence`).WithArgs(IdentityScopeKey(request.Scope)).WillReturnRows(identityRecoveryMockRows(0))
	mock.ExpectExec(`INSERT INTO identity_fresh_recovery_gaps`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_receive_progress`).WithArgs(IdentityScopeKey(request.Scope), int64(673156)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_consume_progress`).WithArgs(IdentityScopeKey(request.Scope), int64(673156), "generation", int64(8)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_export_progress`).WithArgs(IdentityScopeKey(request.Scope)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE stream_source_cutovers SET state='closed'`).WithArgs(request.OldEpoch, IdentityScopeKey(request.Scope), int64(784452)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_source_cutovers`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	plan, err := (&PostgresStore{db: db}).ApplyIdentityFreshRecovery(context.Background(), request)
	if err != nil || plan.NextSequence != 673157 || plan.GapStatus != "unverifiable_gap" {
		t.Fatalf("recovery plan=%+v err=%v", plan, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyIdentityFreshRecoveryRollsBackBeforeCutoverOnWriteFailure(t *testing.T) {
	request := IdentityFreshRecoveryRequest{
		Scope:    IdentityScope{Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth"},
		OldEpoch: "identity-fresh-b2-20261025", NewEpoch: "identity-fresh-b3-20261102", PreviousRelease: "r59b",
		ExpectedAcceptedSequence: 673156, ExpectedProcessedSequence: 672823, ExpectedPendingRecords: 2041,
		ExpectedExportPendingRecords: 9894, ExpectedOldStartOffset: 784452,
		RedisAuditSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RedisEventList:      "list:antiproxy:127.0.0.1",
		RedisProcessingList: "list:antiproxy:127.0.0.1:proxy-sentinel-processing",
		RedisSourceLength:   100000, RedisProcessingLength: 2,
		RedisSampleAt:     time.Date(2026, 11, 2, 11, 50, 0, 0, time.UTC),
		RedisBoundaryJSON: `{}`,
	}
	db, mock := newReconcileMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL lock_timeout`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SET LOCAL statement_timeout`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT s.accepted_sequence`).WillReturnRows(identityRecoveryMockRows(0))
	mock.ExpectExec(`INSERT INTO identity_fresh_recovery_gaps`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_receive_progress`).WillReturnError(errors.New("injected disk failure"))
	mock.ExpectRollback()
	if _, err := (&PostgresStore{db: db}).ApplyIdentityFreshRecovery(context.Background(), request); err == nil {
		t.Fatal("partial recovery was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyIdentityFreshRecoveryRefusesNewInboxBatch(t *testing.T) {
	request := IdentityFreshRecoveryRequest{
		Scope:    IdentityScope{Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth"},
		OldEpoch: "identity-fresh-b2-20261025", NewEpoch: "identity-fresh-b3-20261102", PreviousRelease: "r59b",
		ExpectedAcceptedSequence: 673156, ExpectedProcessedSequence: 672823, ExpectedPendingRecords: 2041,
		ExpectedExportPendingRecords: 9894, ExpectedOldStartOffset: 784452,
		RedisAuditSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RedisEventList:      "list:antiproxy:127.0.0.1",
		RedisProcessingList: "list:antiproxy:127.0.0.1:proxy-sentinel-processing",
		RedisSourceLength:   100000, RedisProcessingLength: 2,
		RedisSampleAt:     time.Date(2026, 11, 2, 11, 50, 0, 0, time.UTC),
		RedisBoundaryJSON: `{}`,
	}
	db, mock := newReconcileMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL lock_timeout`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SET LOCAL statement_timeout`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT s.accepted_sequence`).WillReturnRows(identityRecoveryMockRows(1))
	mock.ExpectRollback()
	if _, err := (&PostgresStore{db: db}).ApplyIdentityFreshRecovery(context.Background(), request); err == nil {
		t.Fatal("pre-existing inbox evidence would be skipped")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
