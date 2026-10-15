package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"proxy-sentinel/internal/normalized"
	"strings"
	"time"
)

const inventorySnapshotChunkSize = 2000
const inventorySnapshotApplySize = 100

// Immutable authority snapshots have their own primary-key cursor. Processing
// never changes account synchronization or policy membership semantics.
func (s *PostgresStore) backfillInventorySnapshots(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cursorRaw []byte
	var done bool
	if err = tx.QueryRowContext(ctx, `SELECT snapshot_cursor,snapshot_backfill_complete FROM endpoint_inventory_projection_state WHERE singleton FOR UPDATE`).Scan(&cursorRaw, &done); err != nil {
		return err
	}
	if done {
		return nil
	}
	var cursor [5]string
	if err = json.Unmarshal(cursorRaw, &cursor); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT source,sensor_id,campus_id,access_domain,snapshot_id FROM identity_full_snapshots WHERE (source,sensor_id,campus_id,access_domain,snapshot_id)>($1,$2,$3,$4,$5) ORDER BY source,sensor_id,campus_id,access_domain,snapshot_id LIMIT 2000`, cursor[0], cursor[1], cursor[2], cursor[3], cursor[4])
	if err != nil {
		return err
	}
	keys := [][5]string{}
	for rows.Next() {
		var k [5]string
		if err = rows.Scan(&k[0], &k[1], &k[2], &k[3], &k[4]); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, k := range keys {
		if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_snapshot_jobs(source,sensor_id,campus_id,access_domain,snapshot_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, k[0], k[1], k[2], k[3], k[4]); err != nil {
			return err
		}
		cursor = k
	}
	cursorRaw, _ = json.Marshal(cursor)
	if _, err = tx.ExecContext(ctx, `UPDATE endpoint_inventory_projection_state SET snapshot_cursor=$1,snapshot_backfill_complete=$2 WHERE singleton`, cursorRaw, len(keys) < 2000); err != nil {
		return err
	}
	return tx.Commit()
}

// Stage each immutable JSON document once into bounded durable chunks. On
// interruption, replaying the parser is safe; each chunk has a stable key.
func (s *PostgresStore) stageInventorySnapshot(ctx context.Context, k [5]string, offset int) (int, error) {
	var count sql.NullInt64
	var available bool
	err := s.db.QueryRowContext(ctx, `SELECT staged_count,EXISTS(SELECT 1 FROM endpoint_inventory_snapshot_chunks c WHERE c.source=j.source AND c.sensor_id=j.sensor_id AND c.campus_id=j.campus_id AND c.access_domain=j.access_domain AND c.snapshot_id=j.snapshot_id AND c.start_offset=$6) FROM endpoint_inventory_snapshot_jobs j WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, k[0], k[1], k[2], k[3], k[4], offset/inventorySnapshotChunkSize*inventorySnapshotChunkSize).Scan(&count, &available)
	if err != nil {
		return 0, err
	}
	if count.Valid && (available || int(count.Int64) == offset) {
		return int(count.Int64), nil
	}
	// Stage every chunk in one PostgreSQL statement. The previous Go-side decoder re-read the
	// whole jsonb document and re-parsed it from the first event on every resume, relying on
	// ON CONFLICT DO NOTHING for chunks already written, so resuming at chunk K cost O(K) event
	// parses: a ~35k-event snapshot staged 1,000 at a time burned ~600M parses, and the field
	// measured ~12 events/s against an 8.06M-event backlog (about eight days).
	// Chunk keys and stored bodies are unchanged (jsonb_agg yields the same JSON array the Go
	// marshal produced), so this stays idempotent and skips nothing.
	var total int
	if err = s.db.QueryRowContext(ctx, `SELECT coalesce(jsonb_array_length(document->'events'),0) FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, k[0], k[1], k[2], k[3], k[4]).Scan(&total); err != nil {
		return 0, fmt.Errorf("snapshot retry input unavailable: %w", err)
	}
	if total == 0 {
		return 0, fmt.Errorf("snapshot events missing")
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_inventory_snapshot_chunks
 SELECT $1,$2,$3,$4,$5,((ord-1)/$7)*$7,jsonb_agg(e ORDER BY ord)
 FROM identity_full_snapshots s
 CROSS JOIN LATERAL jsonb_array_elements(s.document->'events') WITH ORDINALITY AS t(e,ord)
 WHERE s.source=$1 AND s.sensor_id=$2 AND s.campus_id=$3 AND s.access_domain=$4 AND s.snapshot_id=$5
 GROUP BY (ord-1)/$7
 ON CONFLICT DO NOTHING`, k[0], k[1], k[2], k[3], k[4], inventorySnapshotChunkSize); err != nil {
		return 0, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE endpoint_inventory_snapshot_jobs SET staged_count=$6 WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, k[0], k[1], k[2], k[3], k[4], total)
	return total, err
}

func (s *PostgresStore) projectInventorySnapshotBatch(ctx context.Context) (bool, error) {
	var k [5]string
	var offset int
	err := s.db.QueryRowContext(ctx, `SELECT source,sensor_id,campus_id,access_domain,snapshot_id,event_cursor FROM endpoint_inventory_snapshot_jobs WHERE NOT processed ORDER BY source,sensor_id,campus_id,access_domain,snapshot_id LIMIT 1`).Scan(&k[0], &k[1], &k[2], &k[3], &k[4], &offset)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	count, err := s.stageInventorySnapshot(ctx, k, offset)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var lockedOffset int
	err = tx.QueryRowContext(ctx, `SELECT event_cursor FROM endpoint_inventory_snapshot_jobs WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5 AND NOT processed FOR UPDATE SKIP LOCKED`, k[0], k[1], k[2], k[3], k[4]).Scan(&lockedOffset)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if lockedOffset != offset {
		return true, nil
	}
	var observed time.Time
	if err = tx.QueryRowContext(ctx, `SELECT observed_at FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, k[0], k[1], k[2], k[3], k[4]).Scan(&observed); err != nil {
		return false, err
	}
	events := []normalized.Event{}
	if offset < count {
		var raw []byte
		if err = tx.QueryRowContext(ctx, `SELECT events FROM endpoint_inventory_snapshot_chunks WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5 AND start_offset=$6`, k[0], k[1], k[2], k[3], k[4], offset/inventorySnapshotChunkSize*inventorySnapshotChunkSize).Scan(&raw); err != nil {
			return false, err
		}
		if err = json.Unmarshal(raw, &events); err != nil {
			return false, err
		}
		// Parser chunks remain durable and large enough to avoid re-reading the
		// original JSON. Apply a smaller slice so source notification locks are
		// held for at most 100 events, including when resuming inside a chunk.
		start := offset % inventorySnapshotChunkSize
		if start >= len(events) || len(events) > inventorySnapshotChunkSize {
			return false, fmt.Errorf("snapshot cursor outside durable chunk")
		}
		events = events[start:min(start+inventorySnapshotApplySize, len(events))]
	}
	end := offset + len(events)
	if offset > count || end > count || len(events) > inventorySnapshotApplySize {
		return false, fmt.Errorf("snapshot cursor outside immutable snapshot")
	}
	type fact struct {
		Record, Endpoint, Account, IP, Access, Event string
		Confidence                                   float64
	}
	facts := []fact{}
	for _, event := range events {
		if event.EventID == "" {
			return false, fmt.Errorf("snapshot observation has no standard event ID")
		}
		state := BuildIdentityState([]normalized.Event{event})
		if len(state.Sessions) != 1 {
			return false, fmt.Errorf("snapshot has no unique session")
		}
		v := state.Sessions[0]
		if strings.TrimSpace(v.EndpointID) == "" {
			continue
		}
		sum := sha256.Sum256([]byte(k[0] + "\x00" + event.EventID))
		ip := ""
		if parsed := net.ParseIP(v.IP); parsed != nil {
			ip = parsed.String()
		}
		facts = append(facts, fact{fmt.Sprintf("%x", sum), v.EndpointID, v.AccountID, ip, v.AccessID, event.EventID, v.IdentityConfidence})
	}
	body, err := json.Marshal(facts)
	if err != nil {
		return false, err
	}
	ref, _ := json.Marshal(k)
	// Source batches touch notification rows in their own business order. Do
	// not hold a subset and wait for the rest: that creates a lock cycle with
	// an authentication snapshot. Defer this exact slice if any job is busy.
	ids := make([]string, 0, len(facts))
	for _, f := range facts {
		ids = append(ids, f.Endpoint)
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		return false, err
	}
	// lock_timeout above bounds the wait; NOWAIT used to give up instantly, which live-locked
	// against the projection churning the same job rows: the batch could never win a lock and
	// endpoint_inventory_snapshot_jobs stopped advancing, keeping ready=false forever.
	locked, lockErr := tx.QueryContext(ctx, `SELECT endpoint_id FROM endpoint_inventory_projection_jobs WHERE endpoint_id=ANY($1::text[]) ORDER BY endpoint_id FOR UPDATE`, ids)
	if lockErr == nil {
		for locked.Next() {
		}
		lockErr = locked.Err()
		locked.Close()
	}
	if lockErr != nil {
		if inventoryProjectionErrorCode(lockErr) == "sqlstate:55P03" {
			return false, nil
		}
		return false, lockErr
	}
	// One SQL batch; per-row triggers atomically record notification and delta.
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_snapshot_facts
 SELECT x."Record",x."Endpoint",x."Account",nullif(x."IP",'')::inet,x."Access",$2,$3,x."Confidence",x."Event",$4
 FROM jsonb_to_recordset($1::jsonb) AS x("Record" text,"Endpoint" text,"Account" text,"IP" text,"Access" text,"Event" text,"Confidence" double precision) ORDER BY x."Endpoint",x."Record" ON CONFLICT(record_id) DO NOTHING`, body, k[0], observed, ref)
	if err != nil {
		if inventoryProjectionErrorCode(err) == "sqlstate:55P03" {
			return false, nil
		}
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE endpoint_inventory_snapshot_jobs SET event_cursor=$6,processed=$7 WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, k[0], k[1], k[2], k[3], k[4], end, end == count); err != nil {
		return false, err
	}
	if end == count {
		// The immutable source remains the recovery copy. Retire only parser output.
		if _, err = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_snapshot_chunks WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, k[0], k[1], k[2], k[3], k[4]); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}
