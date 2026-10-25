package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"proxy-sentinel/internal/normalized"
)

type discoveryReceiptKey struct {
	Sensor, Source, Event string
	Revision              int64
}

func receiptKey(e normalized.Event) discoveryReceiptKey {
	return discoveryReceiptKey{str(e.Observer, "sensor_id"), firstText(str(e.Observer, "source_id"), e.Source), e.EventID, int64(number(e.Payload, "revision"))}
}

type priorDiscoveryReceipt struct{ Hash, Batch string }

func loadDiscoveryReceipts(ctx context.Context, tx *sql.Tx, events []normalized.Event) (map[discoveryReceiptKey]priorDiscoveryReceipt, error) {
	type keyRow struct {
		Sensor   string `json:"sensor_id"`
		Source   string `json:"source_id"`
		Event    string `json:"event_id"`
		Revision int64  `json:"revision"`
	}
	input := make([]keyRow, 0, len(events))
	seen := map[discoveryReceiptKey]bool{}
	for _, event := range events {
		key := receiptKey(event)
		if seen[key] {
			continue
		}
		seen[key] = true
		input = append(input, keyRow{key.Sensor, key.Source, key.Event, key.Revision})
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.sensor_id,r.source_id,r.event_id,r.revision,r.content_hash,r.batch_id
 FROM discovery_event_receipts r JOIN jsonb_to_recordset($1::jsonb) AS v(sensor_id text,source_id text,event_id text,revision bigint)
 USING(sensor_id,source_id,event_id,revision)`, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[discoveryReceiptKey]priorDiscoveryReceipt, len(events))
	for rows.Next() {
		var key discoveryReceiptKey
		var prior priorDiscoveryReceipt
		if err = rows.Scan(&key.Sensor, &key.Source, &key.Event, &key.Revision, &prior.Hash, &prior.Batch); err != nil {
			return nil, err
		}
		result[key] = prior
	}
	return result, rows.Err()
}

type discoveryReceiptInsert struct {
	Sensor        string    `json:"sensor_id"`
	Source        string    `json:"source_id"`
	Event         string    `json:"event_id"`
	Revision      int64     `json:"revision"`
	Hash          string    `json:"content_hash"`
	Batch         string    `json:"batch_id"`
	Accepted      time.Time `json:"accepted_at"`
	Result        string    `json:"result"`
	Ordinal       int       `json:"event_ordinal"`
	ArchiveBatch  string    `json:"archive_batch_id"`
	ArchiveOffset int       `json:"archive_ordinal"`
}

func insertDiscoveryReceipts(ctx context.Context, tx *sql.Tx, input []discoveryReceiptInsert) error {
	if len(input) == 0 {
		return nil
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO discovery_event_receipts(sensor_id,source_id,event_id,revision,content_hash,batch_id,accepted_at,result,standard_stored_at,storage_time_uncertain,event_ordinal,archive_batch_id,archive_ordinal)
 SELECT v.sensor_id,v.source_id,v.event_id,v.revision,v.content_hash,v.batch_id,v.accepted_at,v.result,
 coalesce(n.confirmed_at,v.accepted_at),coalesce(n.confirmation_uncertain,true),v.event_ordinal,v.archive_batch_id,v.archive_ordinal
 FROM jsonb_to_recordset($1::jsonb) AS v(sensor_id text,source_id text,event_id text,revision bigint,content_hash text,batch_id text,accepted_at timestamptz,result text,event_ordinal integer,archive_batch_id text,archive_ordinal integer)
 LEFT JOIN discovery_normalized_receipts n USING(sensor_id,source_id,event_id,revision)
 ON CONFLICT(sensor_id,source_id,event_id,revision) DO NOTHING`, raw)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != int64(len(input)) {
		return fmt.Errorf("discovery receipt changed during publication")
	}
	return nil
}
