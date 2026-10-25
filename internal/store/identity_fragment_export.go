package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type identityExportFragment struct {
	BatchID, Scope, Source, Epoch, Month, Hash, KeyScheme string
	First, Count                                          int
	Accepted                                              time.Time
	Payload                                               []byte
	BodyState, SearchState                                string
	LeaseEpoch                                            int64
	DerivedLeaseEpoch                                     int64
}

// PostgreSQL is the durable source for HTTP identity input. Each fragment has
// its own fixed ClickHouse token and separate body/search acknowledgements.
// An attempted write is verified before any further action; an absent row is
// left for bounded operator repair rather than blindly sent with a new token.
func (s *DBStore) exportIdentityInboxFragment(ctx context.Context) error {
	fragment, err := s.pg.claimIdentityExportFragment(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			_ = s.pg.reportIdentityExportFragmentError(report, fragment, err)
		}
	}()
	segment, token, err := identityFragmentSegment(fragment)
	if err != nil {
		return err
	}
	if fragment.BodyState != "completed" {
		if fragment.BodyState == "attempted" {
			var confirmed bool
			confirmed, err = s.ch.VerifyStreamBody(ctx, segment)
			if err == nil && !confirmed {
				err = streamlog.ErrUnconfirmed
			}
		} else {
			err = s.ch.WriteStreamBody(ctx, token, segment)
		}
		if err != nil {
			return err
		}
		err = s.pg.finishIdentityExportFragment(ctx, fragment, "body")
		return err
	}
	if fragment.SearchState == "attempted" {
		var confirmed bool
		confirmed, err = s.ch.VerifyStreamSearch(ctx, segment)
		if err == nil && !confirmed {
			err = streamlog.ErrUnconfirmed
		}
	} else {
		err = s.ch.WriteStreamSearch(ctx, token, segment)
	}
	if err != nil {
		return err
	}
	err = s.pg.finishIdentityExportFragment(ctx, fragment, "search")
	return err
}

func (s *PostgresStore) claimIdentityExportFragment(ctx context.Context) (fragment identityExportFragment, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fragment, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT f.batch_id,b.scope_key,b.source,b.stream_epoch,f.archive_month,f.content_sha256,f.key_scheme,f.first_ordinal,f.record_count,b.accepted_at,f.normalized_events,f.body_state,f.search_state FROM identity_ingest_fragments f JOIN identity_ingest_batches b USING(batch_id) WHERE b.protocol_version=2 AND b.sensor_id=$1 AND b.payload_format='fragments' AND b.export_state<>'completed' AND f.body_state IN ('pending','attempted','completed') AND f.search_state IN ('pending','attempted','completed') AND (f.body_state<>'completed' OR f.search_state<>'completed') AND (f.lease_until IS NULL OR f.lease_until<now()) ORDER BY b.accepted_at,f.batch_id,f.first_ordinal LIMIT 1 FOR UPDATE OF f SKIP LOCKED`, s.sensorID).Scan(&fragment.BatchID, &fragment.Scope, &fragment.Source, &fragment.Epoch, &fragment.Month, &fragment.Hash, &fragment.KeyScheme, &fragment.First, &fragment.Count, &fragment.Accepted, &fragment.Payload, &fragment.BodyState, &fragment.SearchState)
	if err != nil {
		return fragment, err
	}
	if fragment.BodyState != "pending" && fragment.BodyState != "attempted" && fragment.BodyState != "completed" || fragment.SearchState != "pending" && fragment.SearchState != "attempted" && fragment.SearchState != "completed" {
		return fragment, fmt.Errorf("identity fragment has invalid archive state")
	}
	err = tx.QueryRowContext(ctx, `UPDATE identity_ingest_fragments SET lease_epoch=lease_epoch+1,lease_until=now()+interval '60 seconds',last_attempt_at=now(),body_state=CASE WHEN body_state='pending' THEN 'attempted' ELSE body_state END,search_state=CASE WHEN body_state='completed' AND search_state='pending' THEN 'attempted' ELSE search_state END WHERE batch_id=$1 AND first_ordinal=$2 RETURNING lease_epoch`, fragment.BatchID, fragment.First).Scan(&fragment.LeaseEpoch)
	if err != nil {
		return fragment, err
	}
	return fragment, tx.Commit()
}

func identityFragmentSegment(fragment identityExportFragment) (streamlog.Segment, string, error) {
	if fragment.BatchID == "" || fragment.Scope == "" || fragment.Epoch == "" || fragment.Month == "" || fragment.First < 0 || fragment.Count < 1 || fragment.Count > identityInboxFragmentMaxEvents || fragment.Accepted.IsZero() {
		return streamlog.Segment{}, "", ErrInvalidIdentityBatch
	}
	var events []normalized.Event
	if err := json.Unmarshal(fragment.Payload, &events); err != nil {
		return streamlog.Segment{}, "", fmt.Errorf("decode identity fragment: %w", ErrInvalidIdentityBatch)
	}
	if len(events) != fragment.Count {
		return streamlog.Segment{}, "", ErrInvalidIdentityBatch
	}
	canonical, err := json.Marshal(events)
	if err != nil {
		return streamlog.Segment{}, "", err
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != fragment.Hash {
		return streamlog.Segment{}, "", streamlog.ErrContentConflict
	}
	if fragment.Month != fragment.Accepted.UTC().Format("200601") {
		return streamlog.Segment{}, "", streamlog.ErrContentConflict
	}
	id := sha256.Sum256([]byte(fragment.Epoch + "\x00" + fragment.BatchID + "\x00" + strconv.Itoa(fragment.First)))
	segment := streamlog.Segment{
		Epoch: fragment.Epoch, Source: fragment.Source, SourcePath: fragment.Scope,
		FileID: fragment.BatchID, StartOffset: int64(fragment.First), EndOffset: int64(fragment.First + fragment.Count),
		ParserVersion: "identity-http-v2", KeyScheme: fragment.KeyScheme, ArchiveMonth: fragment.Month, AcceptedAt: fragment.Accepted,
		Events: events,
	}
	if _, err = prepareStreamEvents(segment); err != nil {
		return streamlog.Segment{}, "", fmt.Errorf("prepare identity fragment: %w", ErrInvalidIdentityBatch)
	}
	return segment, hex.EncodeToString(id[:]), nil
}

func (s *PostgresStore) finishIdentityExportFragment(ctx context.Context, fragment identityExportFragment, lane string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if lane == "body" {
		result, execErr := tx.ExecContext(ctx, `UPDATE identity_ingest_fragments SET body_state='completed',archived_at=now(),lease_until=NULL,last_error='' WHERE batch_id=$1 AND first_ordinal=$2 AND lease_epoch=$3 AND body_state='attempted'`, fragment.BatchID, fragment.First, fragment.LeaseEpoch)
		if execErr != nil {
			return execErr
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrIdentityLeaseExpired
		}
		if _, err = tx.ExecContext(ctx, `UPDATE identity_ingest_batches SET export_state='pending',export_error=NULL WHERE batch_id=$1 AND export_state='failed'`, fragment.BatchID); err != nil {
			return err
		}
		return tx.Commit()
	}
	if lane != "search" {
		return errors.New("invalid identity archive lane")
	}
	var scope string
	err = tx.QueryRowContext(ctx, `UPDATE identity_ingest_fragments f SET search_state='completed',searched_at=now(),lease_until=NULL,last_error='' FROM identity_ingest_batches b WHERE b.batch_id=f.batch_id AND f.batch_id=$1 AND f.first_ordinal=$2 AND f.lease_epoch=$3 AND f.body_state='completed' AND f.search_state='attempted' RETURNING b.scope_key`, fragment.BatchID, fragment.First, fragment.LeaseEpoch).Scan(&scope)
	if err == sql.ErrNoRows {
		return ErrIdentityLeaseExpired
	}
	if err != nil {
		return err
	}
	var result sql.Result
	if identitySplitProgressEnabled() {
		result, err = tx.ExecContext(ctx, `UPDATE identity_export_progress SET exported_records=exported_records+$2,export_last_error='',export_heartbeat_at=now(),export_completed_at=now() WHERE scope_key=$1`, scope, fragment.Count)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET export_pending_records=export_pending_records-$2,export_last_error='',export_heartbeat_at=now(),export_completed_at=now() WHERE scope_key=$1`, scope, fragment.Count)
	}
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrIdentityLeaseExpired
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_ingest_batches b SET export_state=CASE WHEN NOT EXISTS (SELECT 1 FROM identity_ingest_fragments f WHERE f.batch_id=b.batch_id AND (f.body_state<>'completed' OR f.search_state<>'completed')) THEN 'completed' ELSE 'pending' END,export_error=NULL,export_lease_until=NULL WHERE b.batch_id=$1`, fragment.BatchID)
	if err != nil {
		return err
	}
	if err = reclaimIdentityFragmentPayload(ctx, tx, []string{fragment.BatchID}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) reportIdentityExportFragmentError(ctx context.Context, fragment identityExportFragment, cause error) error {
	code := "archive_storage_error"
	permanent := false
	if errors.Is(cause, streamlog.ErrContentConflict) {
		code, permanent = "archive_content_conflict", true
	} else if errors.Is(cause, ErrInvalidIdentityBatch) {
		code, permanent = "archive_invalid_fragment", true
	} else if errors.Is(cause, streamlog.ErrUnconfirmed) {
		code = "archive_unconfirmed"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var result sql.Result
	if permanent {
		result, err = tx.ExecContext(ctx, `UPDATE identity_ingest_fragments SET body_state=CASE WHEN body_state<>'completed' THEN 'failed' ELSE body_state END,search_state=CASE WHEN body_state='completed' THEN 'failed' ELSE search_state END,last_error=$4,lease_until=NULL WHERE batch_id=$1 AND first_ordinal=$2 AND lease_epoch=$3`, fragment.BatchID, fragment.First, fragment.LeaseEpoch, code)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE identity_ingest_fragments SET last_error=$4 WHERE batch_id=$1 AND first_ordinal=$2 AND lease_epoch=$3`, fragment.BatchID, fragment.First, fragment.LeaseEpoch, code)
	}
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrIdentityLeaseExpired
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_ingest_batches SET export_state='failed',export_error=$2 WHERE batch_id=$1 AND export_state<>'completed'`, fragment.BatchID, code)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func reclaimIdentityFragmentPayload(ctx context.Context, tx *sql.Tx, batchIDs []string) error {
	if len(batchIDs) == 0 {
		return nil
	}
	// The projection transaction can already own the batch header while an
	// exporter owns one fragment. Skip that fragment instead of taking locks in
	// opposite order; the exporter performs the same cleanup after it commits.
	_, err := tx.ExecContext(ctx, `WITH ready AS (SELECT f.ctid FROM identity_ingest_fragments f JOIN identity_ingest_batches b ON b.batch_id=f.batch_id WHERE b.batch_id=ANY($1::text[]) AND b.payload_format='fragments' AND b.status='completed' AND b.export_state='completed' AND f.body_state='completed' AND f.search_state='completed' AND f.derived_state='completed' AND f.released_at IS NULL FOR UPDATE OF f SKIP LOCKED) UPDATE identity_ingest_fragments f SET normalized_events='[]'::jsonb,released_at=now() FROM ready WHERE f.ctid=ready.ctid`, batchIDs)
	return err
}
