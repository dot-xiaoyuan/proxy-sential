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
	err = tx.QueryRowContext(ctx, `UPDATE identity_pipeline_scopes SET enabled=true,accepted_sequence=accepted_sequence+1,pending_records=pending_records+$2,export_pending_records=export_pending_records+$2,oldest_pending_at=COALESCE(oldest_pending_at,now()) WHERE scope_key=$1 AND pending_records+$2<=$3 AND export_pending_records+$2<=$3 RETURNING accepted_sequence`, key, len(events), identityInboxCapacity()).Scan(&sequence)
	if err == sql.ErrNoRows {
		return receipt, ErrIdentityInboxFull
	}
	if err != nil {
		return receipt, err
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return receipt, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,received_at,normalized_events,protocol_version,scope_key,content_sha256,accepted_at,sequence,export_state) VALUES($1,$2,$3,'accepted',$4,$5,now(),$6,2,$7,$8,now(),$9,'pending') RETURNING accepted_at`, id, scope.Source, scope.SensorID, count, len(events), raw, key, hash, sequence).Scan(&accepted)
	if err != nil {
		return receipt, err
	}
	if err = tx.Commit(); err != nil {
		return receipt, err
	}
	return identityprotocol.Receipt{ProtocolVersion: 2, BatchID: id, ContentSHA256: hash, RecordCount: count, DurablyAccepted: true, AcceptedAt: accepted.UTC().Format(time.RFC3339Nano)}, nil
}

type identityInboxBatch struct {
	BatchID  string `json:"batch_id"`
	Sequence int64  `json:"sequence"`
	Offset   int    `json:"offset"`
	Count    int    `json:"count"`
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
	err = tx.QueryRowContext(ctx, `SELECT scope_key,current_generation,lease_epoch+1,processed_sequence+1,snapshot_at FROM identity_pipeline_scopes WHERE sensor_id=$1 AND enabled AND pending_records>0 AND (lease_until IS NULL OR lease_until<now()) ORDER BY oldest_pending_at,scope_key FOR UPDATE LIMIT 1`, sensor).Scan(&w.Scope, &w.Generation, &w.Epoch, &w.Sequence, &w.SnapshotAt)
	if err != nil {
		return w, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET lease_epoch=$2,lease_until=now()+make_interval(secs=>$3),heartbeat_at=now() WHERE scope_key=$1`, w.Scope, w.Epoch, identityInboxLease.Seconds())
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
			_, _ = s.db.ExecContext(release, `UPDATE identity_pipeline_scopes SET lease_until=NULL WHERE scope_key=$1 AND lease_epoch=$2`, w.Scope, w.Epoch)
		}
	}()
	rows, err := s.db.QueryContext(ctx, `WITH candidates AS MATERIALIZED (SELECT batch_id,sequence,processed_offset,records_emitted FROM identity_ingest_batches WHERE scope_key=$1 AND sequence>=$2 AND protocol_version=2 ORDER BY sequence LIMIT 500), bounded AS (SELECT *,COALESCE(sum(records_emitted-processed_offset) OVER (ORDER BY sequence ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0) AS preceding_records FROM candidates) SELECT b.batch_id,b.sequence,b.processed_offset,b.normalized_events FROM bounded c JOIN identity_ingest_batches b USING(batch_id) WHERE c.preceding_records<$3 ORDER BY b.sequence`, w.Scope, w.Sequence, limit)
	if err != nil {
		return w, err
	}
	for rows.Next() && len(w.Events) < limit {
		var raw []byte
		var batch identityInboxBatch
		if err = rows.Scan(&batch.BatchID, &batch.Sequence, &batch.Offset, &raw); err != nil {
			rows.Close()
			return w, err
		}
		if batch.Sequence != w.Sequence+int64(len(w.Batches)) {
			rows.Close()
			return w, fmt.Errorf("inbox sequence gap")
		}
		var events []normalized.Event
		if err = json.Unmarshal(raw, &events); err != nil {
			rows.Close()
			return w, err
		}
		if batch.Offset < 0 || batch.Offset >= len(events) {
			rows.Close()
			return w, fmt.Errorf("invalid inbox processing offset")
		}
		end := min(len(events), batch.Offset+limit-len(w.Events))
		batch.Count = end - batch.Offset
		w.Events = append(w.Events, events[batch.Offset:end]...)
		w.Batches = append(w.Batches, batch)
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
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(lease_epoch=$2 AND lease_until>now() AND current_generation=$3,false) FROM identity_pipeline_scopes WHERE scope_key=$1`, w.Scope, w.Epoch, w.Generation).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrIdentityLeaseExpired
	}
	if err = writePolicyIdentityEvents(ctx, tx, w.Events); err != nil {
		return err
	}
	// Persist application deduplication in one round trip. Retain input order for
	// conflicting online/offline events; RETURNING itself has no ordering contract.
	documents := make([]map[string]any, 0, len(w.Events))
	batches := w.Batches
	if len(batches) == 0 {
		batches = []identityInboxBatch{{BatchID: w.BatchID, Sequence: w.Sequence, Offset: w.Offset, Count: len(w.Events)}}
	}
	index := 0
	for _, batch := range batches {
		for i := 0; i < batch.Count; i++ {
			event := w.Events[index]
			index++
			documents = append(documents, map[string]any{"event_id": event.EventID, "sequence": batch.Sequence, "ordinal": batch.Offset + i, "observed_at": event.Timestamp, "document": event})
		}
	}
	raw, err := json.Marshal(documents)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `INSERT INTO identity_applied_events(scope_key,event_id,batch_sequence,ordinal,observed_at,document) SELECT $1,r.event_id,r.sequence,r.ordinal,r.observed_at,r.document FROM jsonb_to_recordset($2::jsonb) r(event_id text,sequence bigint,ordinal integer,observed_at timestamptz,document jsonb) ORDER BY r.sequence,r.ordinal ON CONFLICT DO NOTHING RETURNING event_id`, w.Scope, raw)
	if err != nil {
		return err
	}
	inserted := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		inserted[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	fresh := make([]normalized.Event, 0, len(inserted))
	for _, event := range w.Events {
		if inserted[event.EventID] {
			fresh = append(fresh, event)
			delete(inserted, event.EventID)
		}
	}
	accounts, sessions, err := applyCurrentIdentityEvents(ctx, tx, w.Scope, w.Generation, fresh, w.SnapshotAt)
	if err != nil {
		return err
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
	// Only the final progress publication locks the summary. Receipt insertion can
	// proceed while facts and address references are being written. A fresh statement
	// after this lock sees any concurrently committed next batch for oldest_pending_at.
	if _, err = tx.ExecContext(ctx, `SELECT scope_key FROM identity_pipeline_scopes WHERE scope_key=$1 FOR UPDATE`, w.Scope); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET accounts=accounts+$3,sessions=sessions+$4,statistics_at=now(),processed_at=now(),pending_records=pending_records-$5,processed_sequence=$7-CASE WHEN $6 THEN 0 ELSE 1 END,lease_until=NULL,heartbeat_at=now(),last_error='',oldest_pending_at=(SELECT accepted_at FROM identity_ingest_batches WHERE scope_key=$1 AND sequence=CASE WHEN $6 THEN $7+1 ELSE $7 END) WHERE scope_key=$1 AND lease_epoch=$2 AND lease_until>clock_timestamp() AND current_generation=$8`, w.Scope, w.Epoch, accounts, sessions, len(w.Events), done, lastSequence, w.Generation)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrIdentityLeaseExpired
	}
	return tx.Commit()
}
func applyCurrentIdentityEvents(ctx context.Context, tx *sql.Tx, key, generation string, events []normalized.Event, snapshotAt sql.NullTime) (int, int, error) {
	documents := make([]map[string]any, 0, len(events))
	for ordinal, event := range events {
		rows := policyRows([]normalized.Event{event})
		if len(rows) != 1 {
			return 0, 0, fmt.Errorf("identity event must have one scoped session")
		}
		row := rows[0]
		if snapshotAt.Valid && !row.ConfirmedAt.After(snapshotAt.Time) {
			continue
		}
		session := BuildIdentityState([]normalized.Event{event}).Sessions[0]
		address, err := netip.ParseAddr(row.IP)
		if err != nil {
			return 0, 0, err
		}
		session.IP = address.Unmap().String()
		documents = append(documents, map[string]any{"ordinal": ordinal, "session_id": row.ID, "ip": session.IP, "account_id": row.AccountID, "observed_at": row.ConfirmedAt, "active": row.EndedAt.IsZero(), "document": session})
	}
	if len(documents) == 0 {
		return 0, 0, nil
	}
	raw, err := json.Marshal(documents)
	if err != nil {
		return 0, 0, err
	}
	var accounts, sessions int
	err = tx.QueryRowContext(ctx, `WITH ordered AS MATERIALIZED (SELECT * FROM jsonb_to_recordset($3::jsonb) r(ordinal integer,session_id text,ip text,account_id text,observed_at timestamptz,active boolean,document jsonb) ORDER BY ordinal), applied AS MATERIALIZED (SELECT identity_apply_address($1,$2,session_id,ip,account_id,observed_at,active,document) AS delta FROM ordered ORDER BY ordinal) SELECT COALESCE(sum(delta[1]),0),COALESCE(sum(delta[2]),0) FROM applied`, key, generation, raw).Scan(&accounts, &sessions)
	return accounts, sessions, err
}

func identityInboxCapacity() int {
	value, err := strconv.Atoi(os.Getenv("PROXY_SENTINEL_IDENTITY_INBOX_MAX_RECORDS"))
	if err != nil || value < 10000 {
		return 1000000
	}
	return value
}
