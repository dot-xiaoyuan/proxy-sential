package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"sort"
)

// Existing retained observations are replayed in bounded pages. A crash before
// progress commit repeats stable batches; the ingest ledger deduplicates them.
func (r Repository) BackfillDiscoveryPage(ctx context.Context) (bool, error) {
	tx, e := r.DB.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(ctx, `INSERT INTO discovery_rebuild_progress(job) VALUES('legacy-discovery-v2') ON CONFLICT DO NOTHING`)
	if e != nil {
		return false, e
	}
	var after string
	var done bool
	e = tx.QueryRowContext(ctx, `SELECT last_key,completed FROM discovery_rebuild_progress WHERE job='legacy-discovery-v2' FOR UPDATE SKIP LOCKED`).Scan(&after, &done)
	if e == sql.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if done {
		return false, nil
	}
	rows, e := tx.QueryContext(ctx, `SELECT id,data FROM discovery_observations WHERE id>$1 ORDER BY id LIMIT 100`, after)
	if e != nil {
		return false, e
	}
	events := []normalized.Event{}
	last := after
	count := 0
	for rows.Next() {
		var id string
		var raw []byte
		if e = rows.Scan(&id, &raw); e != nil {
			rows.Close()
			return false, e
		}
		last = id
		count++
		var o Observation
		if e = json.Unmarshal(raw, &o); e != nil {
			rows.Close()
			return false, e
		}
		if o.Evidence.EventID != "" {
			events = append(events, o.Evidence)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return false, e
	}
	// Release progress locks before registering a batch; a lost progress update
	// is safe because batch IDs are derived from the exact page boundaries.
	tx.Rollback()
	groups := map[string][]normalized.Event{}
	for _, event := range events {
		sensor := str(event.Observer, "sensor_id")
		groups[sensor] = append(groups[sensor], event)
	}
	sensors := []string{}
	for sensor := range groups {
		sensors = append(sensors, sensor)
	}
	sort.Strings(sensors)
	for _, sensor := range sensors {
		id := "discovery-backfill:" + contentHash([]string{after, last, sensor})[:32]
		if e = r.AcceptDiscoveryBatchLane(ctx, id, groups[sensor], "backfill"); e != nil {
			return false, e
		}
	}
	_, e = r.DB.ExecContext(ctx, `UPDATE discovery_rebuild_progress SET last_key=$1,completed=$2,updated_at=now() WHERE job='legacy-discovery-v2' AND last_key=$3`, last, count < 100, after)
	return count > 0, e
}
