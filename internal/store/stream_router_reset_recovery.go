package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

// StreamRouterResetRecoveryRequest pins the original cutover and the first
// post-reset index row observed before recovery. The expected row prevents a
// later TTL loss from silently changing the recovery boundary.
type StreamRouterResetRecoveryRequest struct {
	SensorID               string
	ResetID                string
	AuthorizationRef       string
	FixedCutoverAt         time.Time
	FixedCancelID          string
	ResetStartedAt         time.Time
	ExpectedFirstIndexedAt time.Time
	ExpectedFirstEventKey  string
	ExpectedFirstSHA256    string
}

type StreamRouterResetRecoveryProof struct {
	BeforeResetRows   int64     `json:"before_reset_index_rows"`
	ResetToFirstRows  int64     `json:"reset_to_first_index_rows"`
	FirstIndexedAt    time.Time `json:"first_indexed_at"`
	FirstEventKey     string    `json:"first_event_key"`
	FirstSHA256       string    `json:"first_content_sha256"`
	FirstBodyVerified bool      `json:"first_body_verified"`
}

// RestoreStreamRouterAfterReset restores a cursor lost in an authorized test
// reset. It never changes the immutable fresh cutover or counts the deleted
// interval as processed. The missing row count remains unknown in the audit.
func (s *DBStore) RestoreStreamRouterAfterReset(ctx context.Context, req StreamRouterResetRecoveryRequest) (StreamRouterResetRecoveryProof, error) {
	var proof StreamRouterResetRecoveryProof
	if s == nil || s.pg == nil || s.pg.db == nil || s.ch == nil ||
		req.SensorID == "" || req.ResetID == "" || req.AuthorizationRef == "" || req.FixedCancelID == "" ||
		req.ExpectedFirstEventKey == "" || len(req.ExpectedFirstSHA256) != 64 ||
		req.FixedCutoverAt.IsZero() || req.ResetStartedAt.IsZero() || req.ExpectedFirstIndexedAt.IsZero() ||
		!req.FixedCutoverAt.Equal(req.FixedCutoverAt.UTC().Truncate(time.Microsecond)) ||
		!req.ResetStartedAt.Equal(req.ResetStartedAt.UTC().Truncate(time.Microsecond)) ||
		!req.ExpectedFirstIndexedAt.Equal(req.ExpectedFirstIndexedAt.UTC().Truncate(time.Microsecond)) ||
		!req.FixedCutoverAt.Before(req.ResetStartedAt) || req.ExpectedFirstIndexedAt.Before(req.ResetStartedAt) ||
		!req.ExpectedFirstIndexedAt.Before(time.Now().UTC()) || !time.Now().UTC().Before(req.ResetStartedAt.Add(6*24*time.Hour)) {
		return proof, errors.New("invalid router reset recovery boundary or expired short index window")
	}
	if _, err := hex.DecodeString(req.ExpectedFirstSHA256); err != nil || req.ExpectedFirstSHA256 != strings.ToLower(req.ExpectedFirstSHA256) {
		return proof, errors.New("invalid router reset recovery hash")
	}
	resetStamp := "parseDateTime64BestEffort(" + chQuote(req.ResetStartedAt.UTC().Format(time.RFC3339Nano)) + ",6)"
	firstStamp := "parseDateTime64BestEffort(" + chQuote(req.ExpectedFirstIndexedAt.UTC().Format(time.RFC3339Nano)) + ",6)"
	query := fmt.Sprintf(`SELECT countIf(indexed_at<%s),countIf(indexed_at>=%s)
FROM stream_router_signal_index WHERE sensor_id=%s AND indexed_at<%s
SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=15 FORMAT TSV`,
		resetStamp, resetStamp, chQuote(req.SensorID), firstStamp)
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return proof, fmt.Errorf("verify router reset index range: %w", err)
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), "\t")
	if len(parts) != 2 {
		return proof, errors.New("invalid router reset index count proof")
	}
	proof.BeforeResetRows, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return proof, fmt.Errorf("parse pre-reset index count: %w", err)
	}
	proof.ResetToFirstRows, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil || proof.BeforeResetRows != 0 || proof.ResetToFirstRows != 0 {
		return proof, fmt.Errorf("router reset recovery would skip retained rows: before=%d between=%d parse_error=%v", proof.BeforeResetRows, proof.ResetToFirstRows, err)
	}
	// Query from one microsecond before the pinned first row. The ordered read
	// checks event-key order at the same indexed_at timestamp as well.
	first, err := s.ch.ListStreamRouterSignalRefs(ctx, req.SensorID, req.ExpectedFirstIndexedAt.Add(-time.Microsecond), "", 1)
	if err != nil {
		return proof, fmt.Errorf("verify first router index row: %w", err)
	}
	if len(first) != 1 || !first[0].IndexedAt.Equal(req.ExpectedFirstIndexedAt) ||
		first[0].EventKey != req.ExpectedFirstEventKey || first[0].Body.SHA256 != req.ExpectedFirstSHA256 {
		return proof, errors.New("first router index row changed after reset preflight")
	}
	if _, err = s.ch.GetStreamEventsByRefs(ctx, []StreamBodyRef{first[0].Body}); err != nil {
		return proof, fmt.Errorf("verify first router event body: %w", err)
	}
	proof.FirstIndexedAt, proof.FirstEventKey, proof.FirstSHA256, proof.FirstBodyVerified =
		first[0].IndexedAt, first[0].EventKey, first[0].Body.SHA256, true

	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return proof, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('stream-router-fresh-cutover'),hashtext($1))`, req.SensorID); err != nil {
		return proof, err
	}
	var cancelID string
	var fixedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT cancel_id,indexed_after FROM stream_router_fresh_cutovers
WHERE sensor_id=$1 ORDER BY indexed_after DESC LIMIT 1 FOR SHARE`, req.SensorID).Scan(&cancelID, &fixedAt)
	if err != nil || cancelID != req.FixedCancelID || !fixedAt.Equal(req.FixedCutoverAt) {
		return proof, fmt.Errorf("last router cutover differs from reset recovery proof: cancel=%q cutoff=%s error=%v", cancelID, fixedAt, err)
	}
	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM stream_router_recognition_state WHERE sensor_id=$1 FOR UPDATE`, req.SensorID).Scan(&one)
	if err == nil {
		return proof, errors.New("router recognition state already exists; reset recovery cannot overwrite it")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return proof, err
	}
	var earlierResetID string
	err = tx.QueryRowContext(ctx, `SELECT reset_id FROM stream_router_reset_recoveries
WHERE sensor_id=$1 ORDER BY created_at DESC LIMIT 1 FOR SHARE`, req.SensorID).Scan(&earlierResetID)
	if err == nil {
		return proof, fmt.Errorf("router reset recovery audit already exists: %s", earlierResetID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return proof, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_router_reset_recoveries(
sensor_id,reset_id,fixed_cutover_at,fixed_cancel_id,reset_started_at,first_indexed_at,first_event_key,
first_content_sha256,retained_before_reset_rows,retained_reset_to_first_rows,authorization_ref)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, req.SensorID, req.ResetID, req.FixedCutoverAt,
		req.FixedCancelID, req.ResetStartedAt, proof.FirstIndexedAt, proof.FirstEventKey,
		proof.FirstSHA256, proof.BeforeResetRows, proof.ResetToFirstRows, req.AuthorizationRef)
	if err != nil {
		return proof, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_router_recognition_state(
sensor_id,fresh_cutoff_at,cancel_id,cursor_indexed_at,cursor_event_key,processed_events,rule_version)
VALUES($1,$2,$3,$4,'',0,$5)`, req.SensorID, req.FixedCutoverAt, req.FixedCancelID,
		req.ResetStartedAt, fingerprint.DefaultRouterRuleSet().Version)
	if err != nil {
		return proof, err
	}
	if err = tx.Commit(); err != nil {
		return proof, err
	}
	return proof, nil
}
