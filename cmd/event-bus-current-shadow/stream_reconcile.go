package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const streamCurrentBatchRows = 200
const streamCurrentBatchBytes = 8 << 20

type streamCurrentRow struct {
	Epoch     string          `json:"-"`
	DeviceKey string          `json:"device_key"`
	Version   int64           `json:"stream_result_version"`
	LastSeen  time.Time       `json:"last_seen"`
	Document  json.RawMessage `json:"document"`
}

type streamCurrentBatch struct {
	selected map[string]streamCurrentRow
	versions map[string]int64
	bytes    int
}

func newStreamCurrentBatch() *streamCurrentBatch {
	return &streamCurrentBatch{selected: make(map[string]streamCurrentRow), versions: make(map[string]int64)}
}

// add preserves a prefix cursor when the next row would exceed the byte cap.
func (b *streamCurrentBatch) add(row streamCurrentRow) (bool, error) {
	rowBytes := len(row.Document) + len(row.DeviceKey) + len(row.Epoch)
	if b.bytes+rowBytes > streamCurrentBatchBytes {
		if len(b.selected) == 0 {
			return false, fmt.Errorf("stream current row exceeds %d bytes; repair oversized state before advancing", streamCurrentBatchBytes)
		}
		return false, nil
	}
	b.bytes += rowBytes
	if row.Version > b.versions[row.Epoch] {
		b.versions[row.Epoch] = row.Version
	}
	if prior, ok := b.selected[row.DeviceKey]; !ok || row.Version > prior.Version {
		b.selected[row.DeviceKey] = row
	}
	return true, nil
}

// reconcileStreamCurrent advances only after the corresponding current rows
// have been written in the same transaction. The active-epoch cursor starts at
// zero, including for a newly activated epoch with older result versions.
func reconcileStreamCurrent(ctx context.Context, tx pgx.Tx) ([]string, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO discovery_current_stream_progress(epoch)
SELECT DISTINCT epoch FROM stream_source_cutovers WHERE state='active'
ON CONFLICT (epoch) DO NOTHING`); err != nil {
		return nil, fmt.Errorf("initialize stream current progress: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT s.epoch,s.device_key,s.result_version,s.last_seen,s.document
FROM stream_discovery_device_state s
JOIN discovery_current_stream_progress p ON p.epoch=s.epoch
WHERE s.result_version>p.last_result_version
  AND EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.epoch=s.epoch AND c.state='active')
ORDER BY s.result_version,s.epoch,s.device_key LIMIT $1`, streamCurrentBatchRows)
	if err != nil {
		return nil, fmt.Errorf("read stream current updates: %w", err)
	}
	batch := newStreamCurrentBatch()
	for rows.Next() {
		var row streamCurrentRow
		if err := rows.Scan(&row.Epoch, &row.DeviceKey, &row.Version, &row.LastSeen, &row.Document); err != nil {
			rows.Close()
			return nil, err
		}
		accepted, err := batch.add(row)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if !accepted {
			rows.Close()
			break
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(batch.selected) == 0 {
		return nil, nil
	}
	updates := make([]streamCurrentRow, 0, len(batch.selected))
	keys := make([]string, 0, len(batch.selected))
	for key, row := range batch.selected {
		updates = append(updates, row)
		keys = append(keys, key)
	}
	raw, err := json.Marshal(updates)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO discovery_device_current_shadow(device_key,last_seen,fact_count,expired_fact_count,facts,document,stream_result_version,updated_at)
SELECT v.device_key,v.last_seen,0,0,'{}'::jsonb,v.document,v.stream_result_version,now()
FROM jsonb_to_recordset($1::jsonb) AS v(device_key text,last_seen timestamptz,document jsonb,stream_result_version bigint)
ON CONFLICT(device_key) DO UPDATE SET
 last_seen=GREATEST(discovery_device_current_shadow.last_seen,EXCLUDED.last_seen),
 document=CASE WHEN discovery_device_current_shadow.fact_count>0
   THEN EXCLUDED.document||'{"current":true}'::jsonb ELSE EXCLUDED.document END,
 stream_result_version=EXCLUDED.stream_result_version,
 updated_at=now()
WHERE EXCLUDED.stream_result_version>discovery_device_current_shadow.stream_result_version
 OR NOT EXISTS(SELECT 1 FROM stream_source_cutovers active
   WHERE active.epoch=discovery_device_current_shadow.document->>'epoch' AND active.state='active')`, raw); err != nil {
		return nil, fmt.Errorf("write stream current updates: %w", err)
	}
	for epoch, version := range batch.versions {
		if _, err := tx.Exec(ctx, `UPDATE discovery_current_stream_progress
SET last_result_version=$2,updated_at=now()
WHERE epoch=$1 AND last_result_version<$2`, epoch, version); err != nil {
			return nil, fmt.Errorf("advance stream current progress: %w", err)
		}
	}
	return keys, nil
}

// clearInactiveCurrent retires presentation documents and stream-only facts
// from a deactivated epoch in indexed, bounded pages. Event-bus facts are
// restored from their authority as part of this controlled cutover repair.
func clearInactiveCurrent(ctx context.Context, tx pgx.Tx) ([]string, error) {
	var epoch string
	err := tx.QueryRow(ctx, `SELECT p.epoch FROM discovery_current_stream_progress p
WHERE NOT EXISTS(SELECT 1 FROM stream_source_cutovers sc WHERE sc.epoch=p.epoch AND sc.state='active')
  AND NOT EXISTS(
    SELECT 1 FROM discovery_current_stream_progress active
    JOIN stream_source_cutovers sc ON sc.epoch=active.epoch AND sc.state='active'
    JOIN stream_discovery_device_state pending ON pending.epoch=active.epoch
      AND pending.result_version>active.last_result_version
    LIMIT 1)
  AND EXISTS(SELECT 1 FROM discovery_device_current_shadow c
    WHERE c.document ? 'epoch' AND c.document->>'epoch'=p.epoch)
ORDER BY p.epoch LIMIT 1`).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find inactive current epoch: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT device_key FROM discovery_device_current_shadow
WHERE document ? 'epoch' AND document->>'epoch'=$1
ORDER BY device_key LIMIT 200`, epoch)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(keys) == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE discovery_device_current_shadow c
SET document='{}'::jsonb,facts='{}'::jsonb,fact_count=0,expired_fact_count=0,
    stream_result_version=0,updated_at=now()
WHERE c.device_key=ANY($1::text[]) AND c.document->>'epoch'=$2
  AND NOT EXISTS(SELECT 1 FROM stream_source_cutovers sc WHERE sc.epoch=$2 AND sc.state='active')`, keys, epoch); err != nil {
		return nil, fmt.Errorf("clear inactive current documents: %w", err)
	}
	if err := upsertFactCurrent(ctx, tx, keys); err != nil {
		return nil, fmt.Errorf("restore event-bus facts after stream retirement: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM discovery_device_current_shadow
WHERE device_key=ANY($1::text[]) AND fact_count=0 AND document='{}'::jsonb`, keys); err != nil {
		return nil, fmt.Errorf("prune inactive current devices: %w", err)
	}
	return keys, nil
}
