package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IdentityFreshRecoveryRequest is a one-time, compare-and-swap repair of an
// orphaned legacy scope summary. The retained Redis queue is never changed.
type IdentityFreshRecoveryRequest struct {
	Scope                        IdentityScope `json:"scope"`
	OldEpoch                     string        `json:"old_epoch"`
	NewEpoch                     string        `json:"new_epoch"`
	PreviousRelease              string        `json:"previous_release"`
	ExpectedAcceptedSequence     int64         `json:"expected_accepted_sequence"`
	ExpectedProcessedSequence    int64         `json:"expected_processed_sequence"`
	ExpectedPendingRecords       int64         `json:"expected_pending_records"`
	ExpectedExportPendingRecords int64         `json:"expected_export_pending_records"`
	ExpectedOldStartOffset       int64         `json:"expected_old_start_offset"`
	RedisAuditSHA256             string        `json:"redis_audit_sha256"`
	RedisEventList               string        `json:"redis_event_list"`
	RedisProcessingList          string        `json:"redis_processing_list"`
	RedisSourceLength            int64         `json:"redis_source_length"`
	RedisProcessingLength        int64         `json:"redis_processing_length"`
	RedisSampleAt                time.Time     `json:"redis_sample_at"`
	RedisBoundaryJSON            string        `json:"redis_boundary_json"`
}

type IdentityFreshRecoveryInspection struct {
	ScopeKey                string    `json:"scope_key"`
	ScopeExists             bool      `json:"scope_exists"`
	ActiveEpoch             string    `json:"active_epoch"`
	ActiveStartOffset       int64     `json:"active_start_offset"`
	FileID                  string    `json:"file_id"`
	OldLegacyCancelID       string    `json:"old_legacy_cancel_id"`
	OldCancelManifestSHA256 string    `json:"old_cancel_manifest_sha256"`
	AcceptedSequence        int64     `json:"legacy_accepted_sequence"`
	ProcessedSequence       int64     `json:"legacy_processed_sequence"`
	PendingRecords          int64     `json:"legacy_pending_records"`
	ExportPendingRecords    int64     `json:"legacy_export_pending_records"`
	RetainedBatches         int64     `json:"retained_batches"`
	RetainedFragments       int64     `json:"retained_fragments"`
	RetainedReady           int64     `json:"retained_ready"`
	PendingIPRows           int64     `json:"pending_ip_rows"`
	ReceiveProgressRows     int64     `json:"receive_progress_rows"`
	ConsumeProgressRows     int64     `json:"consume_progress_rows"`
	ExportProgressRows      int64     `json:"export_progress_rows"`
	InspectedAt             time.Time `json:"inspected_at"`
}

type IdentityFreshRecoveryPlan struct {
	NewStartOffset             int64  `json:"new_start_offset"`
	NextSequence               int64  `json:"next_sequence"`
	GapFirstSequence           int64  `json:"gap_first_sequence"`
	GapLastSequence            int64  `json:"gap_last_sequence"`
	GapStatus                  string `json:"gap_status"`
	LegacyPendingRecords       int64  `json:"legacy_pending_records"`
	LegacyExportPendingRecords int64  `json:"legacy_export_pending_records"`
	AuditSHA256                string `json:"audit_sha256"`
	CancelRedisQueue           bool   `json:"cancel_redis_queue"`
	MarkLegacyCompleted        bool   `json:"mark_legacy_completed"`
}

type identityFreshRecoverySnapshot struct {
	ScopeExists             bool
	ActiveEpoch             string
	ActiveStartOffset       int64
	AcceptedSequence        int64
	ProcessedSequence       int64
	PendingRecords          int64
	ExportPendingRecords    int64
	BatchCount              int64
	FragmentCount           int64
	ReadyCount              int64
	PendingIPCount          int64
	ReceiveProgressCount    int64
	ConsumeProgressCount    int64
	ExportProgressCount     int64
	CurrentGeneration       string
	LeaseEpoch              int64
	FileID                  string
	ParserVersion           string
	CaptureScopeSHA256      string
	LegacyCutoffAt          time.Time
	SensorID                string
	OldLegacyCancelID       string
	OldCancelManifestSHA256 string
}

func validRecoveryHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func planIdentityFreshRecovery(request IdentityFreshRecoveryRequest, snapshot identityFreshRecoverySnapshot) (IdentityFreshRecoveryPlan, error) {
	plan := IdentityFreshRecoveryPlan{}
	if request.Scope.Source == "" || request.Scope.SensorID == "" || request.Scope.CampusID == "" || request.Scope.AccessDomain == "" ||
		request.OldEpoch == "" || request.NewEpoch == "" || request.NewEpoch == request.OldEpoch || request.PreviousRelease == "" || !validRecoveryHash(request.RedisAuditSHA256) || request.RedisEventList == "" || request.RedisProcessingList == "" || request.RedisSourceLength < 0 || request.RedisProcessingLength < 0 || request.RedisSampleAt.IsZero() || len(request.RedisBoundaryJSON) > 16384 || !json.Valid([]byte(request.RedisBoundaryJSON)) {
		return plan, errors.New("identity fresh recovery requires an exact scope, distinct epochs, release and Redis evidence hash")
	}
	if !snapshot.ScopeExists || snapshot.ActiveEpoch != request.OldEpoch || snapshot.ActiveStartOffset != request.ExpectedOldStartOffset ||
		snapshot.AcceptedSequence != request.ExpectedAcceptedSequence || snapshot.ProcessedSequence != request.ExpectedProcessedSequence ||
		snapshot.PendingRecords != request.ExpectedPendingRecords || snapshot.ExportPendingRecords != request.ExpectedExportPendingRecords {
		return plan, errors.New("identity fresh recovery preflight changed; inspect again")
	}
	if snapshot.ActiveStartOffset <= snapshot.AcceptedSequence || snapshot.ProcessedSequence >= snapshot.AcceptedSequence ||
		snapshot.PendingRecords <= 0 || snapshot.ExportPendingRecords < 0 || snapshot.ParserVersion != "identity-http-v2" ||
		snapshot.SensorID != "" && snapshot.SensorID != request.Scope.SensorID || snapshot.FileID != "redis:"+request.RedisEventList ||
		snapshot.BatchCount != 0 || snapshot.FragmentCount != 0 || snapshot.ReadyCount != 0 || snapshot.PendingIPCount != 0 ||
		snapshot.ReceiveProgressCount != 0 || snapshot.ConsumeProgressCount != 0 || snapshot.ExportProgressCount != 0 {
		return plan, errors.New("identity fresh recovery refuses existing inbox evidence, split progress or a non-orphaned cutover")
	}
	if snapshot.AcceptedSequence == int64(^uint64(0)>>1) {
		return plan, errors.New("identity sequence overflow")
	}
	plan.NewStartOffset = snapshot.AcceptedSequence
	plan.NextSequence = snapshot.AcceptedSequence + 1
	plan.GapFirstSequence = snapshot.ProcessedSequence + 1
	plan.GapLastSequence = snapshot.AcceptedSequence
	plan.GapStatus = "unverifiable_gap"
	plan.LegacyPendingRecords = snapshot.PendingRecords
	plan.LegacyExportPendingRecords = snapshot.ExportPendingRecords
	manifest := struct {
		OldEpoch, NewEpoch, ScopeKey, Status, Reason, RedisAuditSHA256, RedisEventList, RedisProcessingList, OldLegacyCancelID, OldCancelManifestSHA256, RedisBoundaryJSON string
		OldStartOffset, AcceptedSequence, ProcessedSequence, PendingRecords, ExportPendingRecords                                                                          int64
		RedisSourceLength, RedisProcessingLength                                                                                                                           int64
		RedisSampleAt                                                                                                                                                      time.Time
	}{request.OldEpoch, request.NewEpoch, IdentityScopeKey(request.Scope), plan.GapStatus,
		"legacy scope counters have no retained PostgreSQL inbox batches; raw lineage and per-batch completion cannot be verified",
		request.RedisAuditSHA256, request.RedisEventList, request.RedisProcessingList, snapshot.OldLegacyCancelID, snapshot.OldCancelManifestSHA256, request.RedisBoundaryJSON,
		snapshot.ActiveStartOffset, snapshot.AcceptedSequence, snapshot.ProcessedSequence, snapshot.PendingRecords, snapshot.ExportPendingRecords,
		request.RedisSourceLength, request.RedisProcessingLength, request.RedisSampleAt}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return IdentityFreshRecoveryPlan{}, err
	}
	sum := sha256.Sum256(raw)
	plan.AuditSHA256 = hex.EncodeToString(sum[:])
	return plan, nil
}

type identityFreshRecoveryRow interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readIdentityFreshRecovery(ctx context.Context, q identityFreshRecoveryRow, scope IdentityScope, lock bool) (identityFreshRecoverySnapshot, error) {
	var snapshot identityFreshRecoverySnapshot
	query := `SELECT s.accepted_sequence,s.processed_sequence,s.pending_records,s.export_pending_records,
 s.current_generation,s.lease_epoch,c.epoch,c.start_offset,c.file_id,c.parser_version,c.capture_scope_sha256,c.legacy_cutoff_at,c.sensor_id,c.legacy_cancel_id,c.cancel_manifest_sha256,
 (SELECT count(*) FROM identity_ingest_batches b WHERE b.scope_key=s.scope_key),
 (SELECT count(*) FROM identity_ingest_fragments f JOIN identity_ingest_batches b ON b.batch_id=f.batch_id WHERE b.scope_key=s.scope_key),
 (SELECT count(*) FROM identity_derived_ready d JOIN identity_ingest_batches b ON b.batch_id=d.batch_id WHERE b.scope_key=s.scope_key),
 (SELECT count(*) FROM identity_inbox_ip_pending p WHERE p.scope_key=s.scope_key),
 (SELECT count(*) FROM identity_receive_progress r WHERE r.scope_key=s.scope_key),
 (SELECT count(*) FROM identity_consume_progress r WHERE r.scope_key=s.scope_key),
 (SELECT count(*) FROM identity_export_progress r WHERE r.scope_key=s.scope_key)
 FROM identity_pipeline_scopes s JOIN stream_source_cutovers c ON c.source_kind='identity-http' AND c.source_path=s.scope_key AND c.state='active'
 WHERE s.scope_key=$1`
	if lock {
		query += ` FOR UPDATE OF s,c`
	}
	err := q.QueryRowContext(ctx, query, IdentityScopeKey(scope)).Scan(
		&snapshot.AcceptedSequence, &snapshot.ProcessedSequence, &snapshot.PendingRecords, &snapshot.ExportPendingRecords,
		&snapshot.CurrentGeneration, &snapshot.LeaseEpoch, &snapshot.ActiveEpoch, &snapshot.ActiveStartOffset,
		&snapshot.FileID, &snapshot.ParserVersion, &snapshot.CaptureScopeSHA256, &snapshot.LegacyCutoffAt, &snapshot.SensorID, &snapshot.OldLegacyCancelID, &snapshot.OldCancelManifestSHA256,
		&snapshot.BatchCount, &snapshot.FragmentCount, &snapshot.ReadyCount, &snapshot.PendingIPCount,
		&snapshot.ReceiveProgressCount, &snapshot.ConsumeProgressCount, &snapshot.ExportProgressCount)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, errors.New("active identity source or scope is absent")
	}
	if err != nil {
		return snapshot, err
	}
	snapshot.ScopeExists = true
	return snapshot, nil
}

func (s *PostgresStore) InspectIdentityFreshRecovery(ctx context.Context, scope IdentityScope) (IdentityFreshRecoveryInspection, error) {
	snapshot, err := readIdentityFreshRecovery(ctx, s.db, scope, false)
	if err != nil {
		return IdentityFreshRecoveryInspection{}, err
	}
	return IdentityFreshRecoveryInspection{
		ScopeKey: IdentityScopeKey(scope), ScopeExists: snapshot.ScopeExists, ActiveEpoch: snapshot.ActiveEpoch,
		ActiveStartOffset: snapshot.ActiveStartOffset, FileID: snapshot.FileID, OldLegacyCancelID: snapshot.OldLegacyCancelID, OldCancelManifestSHA256: snapshot.OldCancelManifestSHA256, AcceptedSequence: snapshot.AcceptedSequence,
		ProcessedSequence: snapshot.ProcessedSequence, PendingRecords: snapshot.PendingRecords,
		ExportPendingRecords: snapshot.ExportPendingRecords, RetainedBatches: snapshot.BatchCount,
		RetainedFragments: snapshot.FragmentCount, RetainedReady: snapshot.ReadyCount, PendingIPRows: snapshot.PendingIPCount,
		ReceiveProgressRows: snapshot.ReceiveProgressCount, ConsumeProgressRows: snapshot.ConsumeProgressCount,
		ExportProgressRows: snapshot.ExportProgressCount, InspectedAt: time.Now().UTC(),
	}, nil
}

func (s *PostgresStore) ApplyIdentityFreshRecovery(ctx context.Context, request IdentityFreshRecoveryRequest) (plan IdentityFreshRecoveryPlan, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return plan, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='5s'`); err != nil {
		return plan, err
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='30s'`); err != nil {
		return plan, err
	}
	snapshot, err := readIdentityFreshRecovery(ctx, tx, request.Scope, true)
	if err != nil {
		return plan, err
	}
	plan, err = planIdentityFreshRecovery(request, snapshot)
	if err != nil {
		return plan, err
	}
	key := IdentityScopeKey(request.Scope)
	const reason = "legacy scope counters have no retained PostgreSQL inbox batches; raw lineage and per-batch completion cannot be verified"
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_fresh_recovery_gaps(new_epoch,old_epoch,scope_key,old_start_offset,accepted_sequence,processed_sequence,legacy_pending_records,legacy_export_pending_records,retained_batch_count,retained_fragment_count,retained_ready_count,retained_pending_ip_count,old_legacy_cancel_id,old_cancel_manifest_sha256,redis_boundary,redis_event_list,redis_processing_list,redis_source_length,redis_processing_length,redis_sample_at,redis_audit_sha256,audit_sha256,state,reason)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,0,0,0,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18,'unverifiable_gap',$19)`, request.NewEpoch, request.OldEpoch, key, snapshot.ActiveStartOffset, snapshot.AcceptedSequence, snapshot.ProcessedSequence, snapshot.PendingRecords, snapshot.ExportPendingRecords, snapshot.OldLegacyCancelID, snapshot.OldCancelManifestSHA256, request.RedisBoundaryJSON, request.RedisEventList, request.RedisProcessingList, request.RedisSourceLength, request.RedisProcessingLength, request.RedisSampleAt, request.RedisAuditSHA256, plan.AuditSHA256, reason)
	if err != nil {
		return plan, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_receive_progress(scope_key,accepted_sequence,total_records,accepted_at,ip_tracking_after_sequence) VALUES($1,$2,0,NULL,$2)`, key, snapshot.AcceptedSequence)
	if err != nil {
		return plan, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_consume_progress(scope_key,processed_sequence,processed_records,current_generation,lease_epoch,lease_until,oldest_pending_at,processed_at,heartbeat_at,last_error)
 VALUES($1,$2,0,$3,$4,NULL,NULL,NULL,NULL,'')`, key, snapshot.AcceptedSequence, snapshot.CurrentGeneration, snapshot.LeaseEpoch+1)
	if err != nil {
		return plan, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_export_progress(scope_key,exported_records,export_last_error,export_heartbeat_at,export_completed_at) VALUES($1,0,'',NULL,NULL)`, key)
	if err != nil {
		return plan, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='closed' WHERE epoch=$1 AND source_kind='identity-http' AND source_path=$2 AND state='active' AND start_offset=$3`, request.OldEpoch, key, snapshot.ActiveStartOffset)
	if err != nil {
		return plan, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return plan, errors.New("identity cutover changed during recovery")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_source_cutovers(epoch,source_kind,source_path,sensor_id,file_id,start_offset,parser_version,previous_release,legacy_cutoff_at,legacy_cancel_id,cancel_manifest_sha256,capture_scope_sha256,state)
 VALUES($1,'identity-http',$2,$3,$4,$5,'identity-http-v2',$6,$7,$8,$9,$10,'active')`, request.NewEpoch, key, request.Scope.SensorID, snapshot.FileID, plan.NewStartOffset, request.PreviousRelease, snapshot.LegacyCutoffAt, "unverifiable-gap:"+request.NewEpoch, plan.AuditSHA256, snapshot.CaptureScopeSHA256)
	if err != nil {
		return plan, err
	}
	if err = tx.Commit(); err != nil {
		return plan, fmt.Errorf("commit identity fresh recovery: %w", err)
	}
	return plan, nil
}
