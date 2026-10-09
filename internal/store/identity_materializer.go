package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func (s *DBStore) processIdentitySignalBatch(ctx context.Context, phase string) (int, error) {
	sensor := s.pg.sensorID
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO identity_materializer_cursors(sensor_id,phase,cursor_at,cutover_at) SELECT $1,p,CASE WHEN p='live' THEN now()-interval '5 seconds' ELSE now()-interval '7 days' END,now()-interval '5 seconds' FROM unnest(ARRAY['live','backfill']) p ON CONFLICT DO NOTHING`, sensor)
	if err != nil {
		return 0, err
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cursor, cutover time.Time
	var eventID string
	err = tx.QueryRowContext(ctx, `SELECT cursor_at,event_id,cutover_at FROM identity_materializer_cursors WHERE sensor_id=$1 AND phase=$2 FOR UPDATE SKIP LOCKED`, sensor, phase).Scan(&cursor, &eventID, &cutover)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	stamp := func(t time.Time) string {
		return "parseDateTime64BestEffort(" + chQuote(t.UTC().Format(time.RFC3339Nano)) + ",6)"
	}
	bound := "received_at>" + stamp(cutover) + " AND received_at<now64(6)-INTERVAL 5 SECOND"
	if phase == "backfill" {
		bound = "received_at<=" + stamp(cutover)
	}
	// Bound each read to one receipt-day partition. Reading every retained part
	// at once allocates decompression buffers before LIMIT can stop the stream.
	readUntil := cursor.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	ceiling := time.Now().UTC().Add(-5 * time.Second)
	if phase == "backfill" {
		ceiling = cutover
	}
	if readUntil.After(ceiling) {
		readUntil = ceiling
	}
	where := "sensor_id=" + chQuote(sensor) + " AND (received_at,event_id)>(" + stamp(cursor) + "," + chQuote(eventID) + ") AND " + bound
	where += " AND received_at<=" + stamp(readUntil)
	raw, err := s.ch.query(ctx, `SELECT * FROM identity_signal_events_v1 WHERE `+where+` ORDER BY received_at,event_id LIMIT 200 SETTINGS max_threads=1,max_block_size=128,preferred_block_size_bytes=1048576,max_memory_usage=268435456,max_execution_time=15 FORMAT JSONEachRow`)
	if err != nil {
		return 0, err
	}
	events, err := decodeEventRows(raw)
	if err != nil {
		return 0, err
	}
	var rows []struct {
		ReceivedAt string `json:"received_at"`
		EventID    string `json:"event_id"`
	}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return 0, err
	}
	if err = writeIdentityEventsTx(ctx, tx, events); err != nil {
		return 0, err
	}
	// Signal aggregation happens only in this worker, not in the collector loop.
	for _, item := range BuildDeviceInventories("latest-run", events, nil) {
		for _, signal := range item.Signals {
			if err = upsertDeviceSignalFact(ctx, tx, sensor, signal); err != nil {
				return 0, err
			}
		}
	}
	if len(rows) > 0 {
		last := rows[len(rows)-1]
		cursor, err = time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(last.ReceivedAt))
		if err != nil {
			return 0, err
		}
		eventID = last.EventID
	} else if readUntil.After(cursor) {
		cursor, eventID = readUntil, ""
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_materializer_cursors SET cursor_at=$3,event_id=$4,processed_events=processed_events+$5,last_success_at=now(),last_error='' WHERE sensor_id=$1 AND phase=$2`, sensor, phase, cursor, eventID, len(events))
	if err != nil {
		return 0, err
	}
	return len(rows), tx.Commit()
}

func (s *PostgresStore) refreshCurrentDeviceInventory(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,7137))`, s.sensorID).Scan(&locked); err != nil || !locked {
		return err
	}
	now := time.Now().UTC()
	run := Run{RunID: "current-" + now.Format("20060102150405"), SensorID: s.sensorID}
	for _, window := range []string{"10m", "1h", "24h"} {
		inventories, e := s.buildDeviceInventoriesFromFacts(ctx, tx, s.sensorID, now.Format(time.RFC3339Nano), window, nil)
		if e != nil {
			return e
		}
		ips := []string{}
		for _, item := range inventories {
			ips = append(ips, item.IP)
			if e = upsertCurrentDeviceInventory(ctx, tx, run, window, item); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM device_inventory_current WHERE sensor_id=$1 AND "window"=$2 AND NOT(host(ip)=ANY($3::text[]))`, s.sensorID, window, ips); e != nil {
			return e
		}
	}
	return tx.Commit()
}

func (s *DBStore) RunIdentityMaterializer(ctx context.Context) {
	lastRefresh := time.Time{}
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 25*time.Second)
		processed, err := s.processIdentitySignalBatch(work, "live")
		if err == nil {
			err = s.pg.projectPendingIdentitySnapshots(work, 2)
		}
		if err == nil && processed < 200 {
			_, err = s.processIdentitySignalBatch(work, "backfill")
		}
		if err == nil && time.Since(lastRefresh) >= 30*time.Second {
			err = s.pg.refreshCurrentDeviceInventory(work)
			if err == nil {
				lastRefresh = time.Now()
			}
		}
		cancel()
		status := map[string]any{"last_checked_at": time.Now().UTC().Format(time.RFC3339Nano), "processed_live_batch": processed, "last_error": ""}
		if err != nil {
			status["last_error"] = err.Error()
			fmt.Fprintln(os.Stderr, "identity materializer:", err)
		}
		raw, _ := json.Marshal(status)
		health, c := context.WithTimeout(ctx, 5*time.Second)
		_, healthErr := s.pg.db.ExecContext(health, `INSERT INTO read_model_runtime_state(name,state) VALUES('identity-materializer',$1) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, raw)
		c()
		if healthErr != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "identity health:", healthErr)
		}
		delay := time.Second
		if err != nil {
			delay = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (s *DBStore) IdentityMaterializerStatus(ctx context.Context) (map[string]any, error) {
	var raw []byte
	err := s.pg.db.QueryRowContext(ctx, `SELECT jsonb_build_object('health',COALESCE((SELECT state FROM read_model_runtime_state WHERE name='identity-materializer'),'{}'::jsonb),'cursors',COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM identity_materializer_cursors c WHERE sensor_id=$1),'[]'::jsonb),'pending_snapshots',(SELECT count(*) FROM identity_snapshot_projection_jobs))`, s.pg.sensorID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal(raw, &result)
	return result, err
}
