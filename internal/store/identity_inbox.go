package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"

	"proxy-sentinel/internal/identityprotocol"
	"proxy-sentinel/internal/normalized"
)

var ErrIdentityBatchConflict = errors.New("identity batch ID already has different content")
var ErrInvalidIdentityBatch = errors.New("invalid scoped identity batch")
var ErrIdentityInboxFull = errors.New("identity inbox capacity reached")
var ErrIdentityLeaseExpired = errors.New("identity worker lease expired")
var ErrIdentityCutoverNotActive = errors.New("identity stream cutover is not active")

func IdentityScopeKey(scope IdentityScope) string { raw, _ := json.Marshal(scope); return string(raw) }

type DurableIdentityIngester interface {
	AcceptIdentityBatch(context.Context, string, string, IdentityScope, []normalized.Event, int) (identityprotocol.Receipt, error)
}

type DurableIdentityReceiptReader interface {
	LookupIdentityReceipt(context.Context, string, string, int) (identityprotocol.Receipt, bool, error)
}

func (s *DBStore) LookupIdentityReceipt(ctx context.Context, id, hash string, count int) (identityprotocol.Receipt, bool, error) {
	var protocol, records int
	var storedHash string
	var accepted time.Time
	err := s.pg.db.QueryRowContext(ctx, `SELECT protocol_version,COALESCE(content_sha256,''),records_read,COALESCE(accepted_at,received_at) FROM identity_ingest_batches WHERE batch_id=$1`, id).Scan(&protocol, &storedHash, &records, &accepted)
	if err == sql.ErrNoRows {
		return identityprotocol.Receipt{}, false, nil
	}
	if err != nil {
		return identityprotocol.Receipt{}, false, err
	}
	if protocol != identityprotocol.Version || storedHash != hash || records != count {
		return identityprotocol.Receipt{}, false, ErrIdentityBatchConflict
	}
	return identityprotocol.Receipt{ProtocolVersion: protocol, BatchID: id, ContentSHA256: hash, RecordCount: count, DurablyAccepted: true, AcceptedAt: accepted.UTC().Format(time.RFC3339Nano)}, true, nil
}

func (s *DBStore) AcceptIdentityBatch(ctx context.Context, id, hash string, scope IdentityScope, events []normalized.Event, count int) (identityprotocol.Receipt, error) {
	return s.pg.acceptIdentityBatch(ctx, id, hash, scope, events, count)
}
func validIdentityInboxEvent(scope IdentityScope, event normalized.Event) bool {
	rows := policyRows([]normalized.Event{event})
	if event.EventID == "" || eventIdentityScope(event) != scope || len(rows) != 1 || len(BuildIdentityState([]normalized.Event{event}).Sessions) != 1 {
		return false
	}
	address, err := netip.ParseAddr(rows[0].IP)
	return err == nil && !address.IsUnspecified() && !address.IsMulticast()
}
func (s *PostgresStore) acceptIdentityBatch(ctx context.Context, id, hash string, scope IdentityScope, events []normalized.Event, count int) (identityprotocol.Receipt, error) {
	var receipt identityprotocol.Receipt
	if id == "" || hash == "" || count <= 0 || len(events) == 0 || scope.Source == "" || scope.SensorID == "" || scope.CampusID == "" || scope.AccessDomain == "" {
		return receipt, ErrInvalidIdentityBatch
	}
	for _, event := range events {
		if !validIdentityInboxEvent(scope, event) {
			return receipt, ErrInvalidIdentityBatch
		}
	}
	format := "legacy_json"
	streamEpoch := ""
	var fragments []identityInboxFragment
	if os.Getenv("PROXY_SENTINEL_IDENTITY_FRAGMENT_WRITES") == "true" {
		format = "fragments"
		streamEpoch = os.Getenv("PROXY_SENTINEL_IDENTITY_STREAM_EPOCH")
		if streamEpoch == "" {
			return receipt, ErrInvalidIdentityBatch
		}
		var splitErr error
		fragments, splitErr = splitIdentityInboxFragments(events)
		if splitErr != nil {
			return receipt, splitErr
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer tx.Rollback()
	key := IdentityScopeKey(scope)
	// Per-ID locking also serializes conflicting submissions across distinct scopes.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7182))`, id); err != nil {
		return receipt, err
	}
	var priorHash string
	var accepted time.Time
	var priorCount, protocol int
	err = tx.QueryRowContext(ctx, `SELECT protocol_version,COALESCE(content_sha256,''),records_read,COALESCE(accepted_at,received_at) FROM identity_ingest_batches WHERE batch_id=$1`, id).Scan(&protocol, &priorHash, &priorCount, &accepted)
	if err == nil {
		if protocol != identityprotocol.Version || priorHash != hash || priorCount != count {
			return receipt, ErrIdentityBatchConflict
		}
		return identityprotocol.Receipt{ProtocolVersion: protocol, BatchID: id, ContentSHA256: hash, RecordCount: count, DurablyAccepted: true, AcceptedAt: accepted.UTC().Format(time.RFC3339Nano)}, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return receipt, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, key, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain); err != nil {
		return receipt, err
	}
	var sequence int64
	if identitySplitProgressEnabled() {
		if err = ensureIdentityProgress(ctx, tx, key); err != nil {
			return receipt, err
		}
		// Scope ownership changes once; steady-state acceptance owns only receive progress.
		if _, err = tx.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET enabled=true WHERE scope_key=$1 AND NOT enabled`, key); err != nil {
			return receipt, err
		}
		err = tx.QueryRowContext(ctx, acceptIdentitySplitSQL, key, len(events), identityInboxCapacity()).Scan(&sequence)
	} else {
		err = tx.QueryRowContext(ctx, `UPDATE identity_pipeline_scopes SET enabled=true,accepted_sequence=accepted_sequence+1,pending_records=pending_records+$2,export_pending_records=export_pending_records+$2,oldest_pending_at=COALESCE(oldest_pending_at,now()) WHERE scope_key=$1 AND pending_records+$2<=$3 AND export_pending_records+$2<=$3 RETURNING accepted_sequence`, key, len(events), identityInboxCapacity()).Scan(&sequence)
	}
	if err == sql.ErrNoRows {
		return receipt, ErrIdentityInboxFull
	}
	if err != nil {
		return receipt, err
	}
	if format == "fragments" {
		var active bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM stream_source_cutovers WHERE epoch=$1 AND source_kind='identity-http' AND source_path=$2 AND sensor_id=$3 AND parser_version='identity-http-v2' AND state='active' AND start_offset<$4)`, streamEpoch, key, scope.SensorID, sequence).Scan(&active); err != nil {
			return receipt, err
		}
		if !active {
			return receipt, ErrIdentityCutoverNotActive
		}
	}
	raw := []byte("[]")
	if format == "legacy_json" {
		raw, err = json.Marshal(events)
		if err != nil {
			return receipt, err
		}
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,received_at,normalized_events,protocol_version,scope_key,content_sha256,accepted_at,sequence,export_state,payload_format,stream_epoch) VALUES($1,$2,$3,'accepted',$4,$5,now(),$6,2,$7,$8,now(),$9,'pending',$10,$11) RETURNING accepted_at`, id, scope.Source, scope.SensorID, count, len(events), raw, key, hash, sequence, format, streamEpoch).Scan(&accepted)
	if err != nil {
		return receipt, err
	}
	if format == "fragments" {
		rows := make([]map[string]any, 0, len(fragments))
		for _, fragment := range fragments {
			rows = append(rows, map[string]any{"first_ordinal": fragment.FirstOrdinal, "record_count": fragment.Count, "normalized_events": json.RawMessage(fragment.JSON), "content_sha256": fragment.SHA256})
		}
		encoded, marshalErr := json.Marshal(rows)
		if marshalErr != nil {
			return receipt, marshalErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO identity_ingest_fragments(batch_id,first_ordinal,record_count,normalized_events,content_sha256,archive_month,key_scheme) SELECT $1,r.first_ordinal,r.record_count,r.normalized_events,r.content_sha256,$3,'source_position_v1' FROM jsonb_to_recordset($2::jsonb) r(first_ordinal integer,record_count integer,normalized_events jsonb,content_sha256 text)`, id, encoded, accepted.UTC().Format("200601"))
		if err != nil {
			return receipt, err
		}
	}
	if identitySplitProgressEnabled() {
		if err = recordIdentityPendingIPs(ctx, tx, id, key, events); err != nil {
			return receipt, err
		}
	}
	if err = tx.Commit(); err != nil {
		return receipt, err
	}
	return identityprotocol.Receipt{ProtocolVersion: 2, BatchID: id, ContentSHA256: hash, RecordCount: count, DurablyAccepted: true, AcceptedAt: accepted.UTC().Format(time.RFC3339Nano)}, nil
}

type identityInboxBatch struct {
	AcceptedAt time.Time `json:"-"`
	BatchID    string    `json:"batch_id"`
	Sequence   int64     `json:"sequence"`
	Offset     int       `json:"offset"`
	Count      int       `json:"count"`
	Format     string    `json:"-"`
}
type identityInboxWork struct {
	Batches    []identityInboxBatch
	Scope      string
	BatchID    string
	Generation string
	Epoch      int64
	Offset     int
	Events     []normalized.Event
	Sequence   int64
	SnapshotAt sql.NullTime
}

func (s *PostgresStore) claimIdentityInbox(ctx context.Context, sensor string, limit int) (w identityInboxWork, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return w, err
	}
	defer tx.Rollback()
	claimSQL := `SELECT scope_key,current_generation,lease_epoch+1,processed_sequence+1,snapshot_at FROM identity_pipeline_scopes WHERE sensor_id=$1 AND enabled AND pending_records>0 AND (lease_until IS NULL OR lease_until<now()) ORDER BY oldest_pending_at,scope_key FOR UPDATE LIMIT 1`
	if identitySplitProgressEnabled() {
		claimSQL = claimIdentitySplitSQL
	}
	err = tx.QueryRowContext(ctx, claimSQL, sensor).Scan(&w.Scope, &w.Generation, &w.Epoch, &w.Sequence, &w.SnapshotAt)
	if err != nil {
		return w, err
	}
	_, err = tx.ExecContext(ctx, identityConsumeSQL(`UPDATE identity_pipeline_scopes SET lease_epoch=$2,lease_until=now()+make_interval(secs=>$3),heartbeat_at=now() WHERE scope_key=$1`), w.Scope, w.Epoch, identityInboxLease.Seconds())
	if err != nil {
		return w, err
	}
	if err = tx.Commit(); err != nil {
		return w, err
	}
	// A receipt/export heartbeat briefly locks this same summary. Waiting for its
	// short commit avoids SKIP LOCKED repeatedly treating live work as an idle scope.
	// Payload reads and normalization never hold that row lock.
	defer func() {
		if err != nil {
			release, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_, _ = s.db.ExecContext(release, identityConsumeSQL(`UPDATE identity_pipeline_scopes SET lease_until=NULL WHERE scope_key=$1 AND lease_epoch=$2`), w.Scope, w.Epoch)
		}
	}()
	// A compatibility reader understands both the legacy whole-batch JSONB and
	// bounded fragment rows. The lateral limit prevents a 10,000-record HTTP
	// envelope from becoming one unbounded PostgreSQL response.
	payloadSQL := `WITH candidates AS MATERIALIZED (SELECT batch_id,sequence,processed_offset,records_emitted FROM identity_ingest_batches WHERE scope_key=$1 AND sequence>=$2 AND protocol_version=2 ORDER BY sequence LIMIT 500), bounded AS (SELECT *,COALESCE(sum(records_emitted-processed_offset) OVER (ORDER BY sequence ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0) AS preceding_records FROM candidates) SELECT b.batch_id,b.sequence,b.processed_offset,b.records_emitted,b.payload_format,COALESCE(f.first_ordinal,0),CASE WHEN b.payload_format='fragments' THEN f.normalized_events ELSE b.normalized_events END,b.accepted_at FROM bounded c JOIN identity_ingest_batches b USING(batch_id) LEFT JOIN LATERAL (SELECT first_ordinal,normalized_events FROM identity_ingest_fragments WHERE batch_id=b.batch_id AND first_ordinal+record_count>b.processed_offset ORDER BY first_ordinal LIMIT 40) f ON b.payload_format='fragments' WHERE c.preceding_records<$3 ORDER BY b.sequence,f.first_ordinal LIMIT 100`
	rows, err := s.db.QueryContext(ctx, payloadSQL, w.Scope, w.Sequence, limit)
	if err != nil {
		return w, err
	}
	bytes := 0
	previousTotal := 0
	for rows.Next() && len(w.Events) < limit {
		var raw []byte
		var batch identityInboxBatch
		var total, fragmentFirst int
		var format string
		if err = rows.Scan(&batch.BatchID, &batch.Sequence, &batch.Offset, &total, &format, &fragmentFirst, &raw, &batch.AcceptedAt); err != nil {
			rows.Close()
			return w, err
		}
		batch.Format = format
		newBatch := len(w.Batches) == 0 || batch.Sequence != w.Batches[len(w.Batches)-1].Sequence
		if newBatch && len(w.Batches) > 0 {
			previous := w.Batches[len(w.Batches)-1]
			if previous.Offset+previous.Count < previousTotal {
				break
			}
		}
		if newBatch && batch.Sequence != w.Sequence+int64(len(w.Batches)) {
			rows.Close()
			return w, fmt.Errorf("inbox sequence gap")
		}
		if !newBatch {
			previous := w.Batches[len(w.Batches)-1]
			batch.Offset = previous.Offset + previous.Count
			if batch.Offset >= total || fragmentFirst != batch.Offset {
				rows.Close()
				return w, fmt.Errorf("duplicate or out-of-order inbox fragment")
			}
		}
		previousTotal = total
		var events []normalized.Event
		if err = json.Unmarshal(raw, &events); err != nil {
			rows.Close()
			return w, err
		}
		if format == "legacy_json" && fragmentFirst != 0 || format != "legacy_json" && format != "fragments" || batch.Offset < fragmentFirst || batch.Offset >= fragmentFirst+len(events) || fragmentFirst+len(events) > total {
			rows.Close()
			return w, fmt.Errorf("invalid inbox processing offset")
		}
		start := batch.Offset - fragmentFirst
		end := min(len(events), start+limit-len(w.Events))
		for i := start; i < end; i++ {
			item, e := json.Marshal(events[i])
			if e != nil {
				rows.Close()
				return w, e
			}
			if len(item) > identityInboxMaxBytes {
				rows.Close()
				return w, fmt.Errorf("identity event exceeds processing byte limit")
			}
			if bytes+len(item) > identityInboxMaxBytes {
				end = i
				break
			}
			bytes += len(item)
		}
		if end == start {
			break
		}
		batch.Count = end - start
		w.Events = append(w.Events, events[start:end]...)
		if newBatch {
			w.Batches = append(w.Batches, batch)
		} else {
			w.Batches[len(w.Batches)-1].Count += batch.Count
		}
		if end < len(events) {
			break
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return w, err
	}
	if len(w.Batches) == 0 {
		return w, sql.ErrNoRows
	}
	w.BatchID, w.Offset = w.Batches[0].BatchID, w.Batches[0].Offset
	return w, nil
}
func (s *PostgresStore) applyIdentityInbox(ctx context.Context, w identityInboxWork) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var valid bool
	err = tx.QueryRowContext(ctx, identityConsumeSQL(`SELECT COALESCE(lease_epoch=$2 AND lease_until>now() AND current_generation=$3,false) FROM identity_pipeline_scopes WHERE scope_key=$1`), w.Scope, w.Epoch, w.Generation).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrIdentityLeaseExpired
	}
	batches := w.Batches
	if len(batches) == 0 {
		batches = []identityInboxBatch{{BatchID: w.BatchID, Sequence: w.Sequence, Offset: w.Offset, Count: len(w.Events)}}
	}
	// The fresh inbox offset is an ordered receipt. Legacy batches still use
	// event-ID deduplication, while fresh selected facts are keyed by position.
	documents := make([]map[string]any, 0, len(w.Events))
	legacyEvents := make([]normalized.Event, 0, len(w.Events))
	freshFacts := make([]identityStreamPolicyInput, 0, len(w.Events))
	index := 0
	for _, batch := range batches {
		for i := 0; i < batch.Count; i++ {
			event := w.Events[index]
			index++
			if batch.Format == "fragments" {
				freshFacts = append(freshFacts, identityStreamPolicyInput{Event: event, Sequence: batch.Sequence, Ordinal: batch.Offset + i, Accepted: batch.AcceptedAt})
			} else {
				legacyEvents = append(legacyEvents, event)
				documents = append(documents, map[string]any{"event_id": event.EventID, "sequence": batch.Sequence, "ordinal": batch.Offset + i, "observed_at": event.Timestamp})
			}
		}
	}
	if err = writePolicyIdentityEvents(ctx, tx, legacyEvents); err != nil {
		return err
	}
	if err = writeIdentityStreamPolicyFacts(ctx, tx, w.Scope, freshFacts); err != nil {
		return err
	}
	// Deduplication only. Event documents were stored for the old calibration replay, and the
	// generation-keyed current-state tables it fed are no longer maintained per event: publication
	// now happens with the complete snapshot (see publishSnapshotTx).
	if len(documents) != 0 {
		raw, marshalErr := json.Marshal(documents)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_applied_events(scope_key,event_id,batch_sequence,ordinal,observed_at) SELECT $1,r.event_id,r.sequence,r.ordinal,r.observed_at FROM jsonb_to_recordset($2::jsonb) r(event_id text,sequence bigint,ordinal integer,observed_at timestamptz) ORDER BY r.sequence,r.ordinal ON CONFLICT DO NOTHING`, w.Scope, raw); err != nil {
			return err
		}
	}
	batchJSON, err := json.Marshal(batches)
	if err != nil {
		return err
	}
	updated, err := tx.QueryContext(ctx, `UPDATE identity_ingest_batches b SET processed_offset=b.processed_offset+r.count,status=CASE WHEN b.processed_offset+r.count=b.records_emitted THEN 'completed' ELSE 'processing' END,completed_at=CASE WHEN b.processed_offset+r.count=b.records_emitted THEN now() END,error_message=NULL FROM jsonb_to_recordset($1::jsonb) r(batch_id text,"offset" integer,count integer) WHERE b.batch_id=r.batch_id AND b.processed_offset=r."offset" RETURNING b.sequence,b.status='completed'`, batchJSON)
	if err != nil {
		return err
	}
	var done bool
	var lastSequence int64
	changedBatches := 0
	for updated.Next() {
		var sequence int64
		var completed bool
		if err = updated.Scan(&sequence, &completed); err != nil {
			updated.Close()
			return err
		}
		changedBatches++
		if sequence > lastSequence {
			lastSequence, done = sequence, completed
		}
	}
	err = updated.Err()
	updated.Close()
	if err != nil {
		return err
	}
	if changedBatches != len(batches) {
		return ErrIdentityLeaseExpired
	}
	if identitySplitProgressEnabled() {
		if _, err = tx.ExecContext(ctx, `DELETE FROM identity_inbox_ip_pending p USING identity_ingest_batches b WHERE p.batch_id=b.batch_id AND b.protocol_version=2 AND b.scope_key=$1 AND b.sequence BETWEEN $2 AND $3 AND b.status='completed'`, w.Scope, w.Sequence, lastSequence); err != nil {
			return err
		}
	}
	// Only the final progress publication locks the summary. Receipt insertion can
	// proceed while facts and address references are being written. A fresh statement
	// after this lock sees any concurrently committed next batch for oldest_pending_at.
	if _, err = tx.ExecContext(ctx, identityConsumeSQL(`SELECT scope_key FROM identity_pipeline_scopes WHERE scope_key=$1 FOR UPDATE`), w.Scope); err != nil {
		return err
	}
	progressSQL := applyScopeProgressSQL
	if identitySplitProgressEnabled() {
		progressSQL = applyIdentitySplitSQL
	}
	result, err := tx.ExecContext(ctx, progressSQL, w.Scope, w.Epoch, len(w.Events), done, lastSequence, w.Generation)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrIdentityLeaseExpired
	}
	batchIDs := make([]string, 0, len(batches))
	for _, batch := range batches {
		if batch.Format == "fragments" {
			batchIDs = append(batchIDs, batch.BatchID)
		}
	}
	if err = reclaimIdentityFragmentPayload(ctx, tx, batchIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func identityInboxCapacity() int {
	value, err := strconv.Atoi(os.Getenv("PROXY_SENTINEL_IDENTITY_INBOX_MAX_RECORDS"))
	if err != nil || value < 10000 {
		return 1000000
	}
	return value
}

// applyScopeProgressSQL advances processing progress in the apply transaction. Account and session
// totals are published with each complete snapshot, not accumulated per batch.
const applyScopeProgressSQL = `UPDATE identity_pipeline_scopes SET processed_at=now(),pending_records=pending_records-$3,processed_sequence=$5-CASE WHEN $4 THEN 0 ELSE 1 END,lease_until=NULL,heartbeat_at=now(),last_error='',oldest_pending_at=(SELECT accepted_at FROM identity_ingest_batches WHERE protocol_version=2 AND scope_key=$1 AND sequence=CASE WHEN $4 THEN $5+1 ELSE $5 END) WHERE scope_key=$1 AND lease_epoch=$2 AND lease_until>clock_timestamp() AND current_generation=$6`
