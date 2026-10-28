package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// identityDerivedReadyPage only describes the indexing of already accepted,
// incomplete fragment keys. It does not process events or move source offsets.
type identityDerivedReadyPage struct {
	Scanned, Eligible int
	Done              bool
}

type identityDerivedReadyKey struct {
	BatchID  string    `json:"batch_id"`
	First    int       `json:"first_ordinal"`
	SensorID string    `json:"sensor_id"`
	Accepted time.Time `json:"accepted_at"`
}

// scanIdentityDerivedReadyPage holds the single durable cursor until both the
// ready keys and its next position commit. A progress trigger must already be
// installed before this scan starts so a key whose primary offset advances
// behind the cursor is registered by that transaction instead.
func (s *PostgresStore) scanIdentityDerivedReadyPage(ctx context.Context, limit int) (page identityDerivedReadyPage, err error) {
	if limit < 1 || limit > 256 {
		return page, errors.New("invalid identity derived ready scan page size")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	var batch string
	var ordinal int
	if err = tx.QueryRowContext(ctx, `SELECT cursor_batch,cursor_ordinal,done FROM identity_derived_ready_scan WHERE id=true FOR UPDATE`).Scan(&batch, &ordinal, &page.Done); err != nil {
		return page, err
	}
	if page.Done {
		return page, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `WITH candidates AS MATERIALIZED (
 SELECT f.batch_id,f.first_ordinal,f.record_count,f.derived_state
 FROM identity_ingest_fragments f
 WHERE f.derived_state<>'completed' AND (f.batch_id,f.first_ordinal)>($1,$2)
 ORDER BY f.batch_id,f.first_ordinal LIMIT $3
)
SELECT c.batch_id,c.first_ordinal,b.sensor_id,COALESCE(b.accepted_at,b.received_at),
 (b.protocol_version=2 AND b.payload_format='fragments' AND c.derived_state IN ('pending','attempted') AND b.processed_offset>=c.first_ordinal+c.record_count)
FROM candidates c JOIN identity_ingest_batches b USING(batch_id)
ORDER BY c.batch_id,c.first_ordinal`, batch, ordinal, limit)
	if err != nil {
		return page, err
	}
	keys := make([]identityDerivedReadyKey, 0, limit)
	for rows.Next() {
		var key identityDerivedReadyKey
		var ready bool
		if err = rows.Scan(&key.BatchID, &key.First, &key.SensorID, &key.Accepted, &ready); err != nil {
			rows.Close()
			return page, err
		}
		page.Scanned++
		batch, ordinal = key.BatchID, key.First
		if ready {
			keys = append(keys, key)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	page.Eligible = len(keys)
	if len(keys) > 0 {
		raw, marshalErr := json.Marshal(keys)
		if marshalErr != nil {
			return page, marshalErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO identity_derived_ready(batch_id,first_ordinal,sensor_id,accepted_at,priority)
 SELECT r.batch_id,r.first_ordinal,r.sensor_id,r.accepted_at,1
 FROM jsonb_to_recordset($1::jsonb) r(batch_id text,first_ordinal integer,sensor_id text,accepted_at timestamptz)
 ON CONFLICT(batch_id,first_ordinal) DO NOTHING`, raw)
		if err != nil {
			return page, err
		}
	}
	if page.Scanned == 0 {
		_, err = tx.ExecContext(ctx, `UPDATE identity_derived_ready_scan SET done=true WHERE id=true`)
		page.Done = true
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE identity_derived_ready_scan SET cursor_batch=$1,cursor_ordinal=$2 WHERE id=true`, batch, ordinal)
	}
	if err != nil {
		return page, err
	}
	return page, tx.Commit()
}
