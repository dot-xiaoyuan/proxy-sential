package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type discoveryChangeInsert struct {
	Device          string          `json:"device_key"`
	Event           string          `json:"event_id"`
	Ingested        time.Time       `json:"ingested_at"`
	Observed        time.Time       `json:"observed_at"`
	Kind            string          `json:"change_kind"`
	Document        json.RawMessage `json:"document"`
	ArchiveVerified *time.Time      `json:"archive_verified_at"`
}

func insertDiscoveryChanges(ctx context.Context, tx *sql.Tx, changes []discoveryChangeInsert) error {
	if len(changes) == 0 {
		return nil
	}
	raw, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_device_changes_v2(device_key,event_id,ingested_at,observed_at,change_kind,document,archive_verified_at)
 SELECT v.device_key,v.event_id,v.ingested_at,v.observed_at,v.change_kind,v.document,v.archive_verified_at
 FROM jsonb_array_elements($1::jsonb) WITH ORDINALITY AS item(value,ordinal)
 CROSS JOIN LATERAL jsonb_to_record(item.value) AS v(device_key text,event_id text,ingested_at timestamptz,observed_at timestamptz,change_kind text,document jsonb,archive_verified_at timestamptz)
 ORDER BY item.ordinal`, raw)
	return err
}
