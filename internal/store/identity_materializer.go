package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/normalized"
)

// Identity batches adapt to how fast the field can actually write them. The read is cheap
// once the cursor sits near now, but every identity event costs several PostgreSQL round
// trips (identity_ip_mac_history, account_sessions, endpoint_entities, device profiles),
// and on the congested field a single batch's `INSERT INTO identity_ip_mac_history` was
// observed running for twelve seconds while other statements waited on row locks. A fixed
// batch size therefore either wastes the read or never finishes; halving on a timeout and
// doubling on a full batch lets the worker settle on the batch it can complete.
const (
	identitySignalBatchSize = 150
	identitySignalBatchMin  = 50
	identitySignalBatchMax  = 2000
)

// identityWorkBudget bounds one live/backfill batch. It must cover the ClickHouse read
// (server-side limit 15s) plus the PostgreSQL writes for the whole batch.
const identityWorkBudget = 60 * time.Second

// identityLockWaitBudget bounds how long one live/backfill batch waits for the identity
// write lock before giving the loop back. It stays well inside identityWorkBudget so a
// contended lock still leaves time to read ClickHouse and write the batch.
const identityLockWaitBudget = 8 * time.Second

// identityHealthInterval throttles the lane's read_model_runtime_state beacon. The loop
// runs about once a second, and one autocommit per iteration measured 245 ms against a
// `commit` that already cost 228 ms on the field, so the beacon alone consumed roughly a
// fifth of the lane's database time.
const identityHealthInterval = 10 * time.Second

// nextIdentityBatchSize shrinks the batch after a timeout and grows it after a full batch.
// Other failures keep the size: they are data errors, and shrinking would only make the
// worker retry the same broken row more often.
func nextIdentityBatchSize(current int, runErr error, processed int) int {
	if current <= 0 {
		current = identitySignalBatchSize
	}
	if runErr != nil {
		var postgresError interface{ SQLState() string }
		serverTimeout := errors.As(runErr, &postgresError) && postgresError.SQLState() == "57014"
		if !errors.Is(runErr, context.DeadlineExceeded) && !serverTimeout {
			return current
		}
		if next := current / 2; next >= identitySignalBatchMin {
			return next
		}
		return identitySignalBatchMin
	}
	if processed >= current {
		if next := current * 2; next <= identitySignalBatchMax {
			return next
		}
		return identitySignalBatchMax
	}
	return current
}

// claimIdentityCursor reads a stable resume point without keeping a transaction
// open across the ClickHouse read. Pending history is never skipped.
func (s *DBStore) claimIdentityCursor(ctx context.Context, sensorID, phase string) (time.Time, string, time.Time, bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, "", time.Time{}, false, err
	}
	defer tx.Rollback()
	var cursor, cutover time.Time
	var eventID string
	if err = tx.QueryRowContext(ctx, `SELECT cursor_at,event_id,cutover_at FROM identity_materializer_cursors WHERE sensor_id=$1 AND phase=$2 FOR UPDATE`, sensorID, phase).Scan(&cursor, &eventID, &cutover); err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, "", time.Time{}, false, nil
		}
		return time.Time{}, "", time.Time{}, false, err
	}
	return cursor, eventID, cutover, true, tx.Commit()
}

func (s *DBStore) processIdentitySignalBatch(ctx context.Context, phase string, limit int) (int, identityHistoryStats, error) {
	if limit <= 0 || limit > identitySignalBatchMax {
		limit = identitySignalBatchSize
	}
	sensor := s.pg.sensorID
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO identity_materializer_cursors(sensor_id,phase,cursor_at,cutover_at) SELECT $1,p,CASE WHEN p='live' THEN now()-interval '5 seconds' ELSE now()-interval '7 days' END,now()-interval '5 seconds' FROM unnest(ARRAY['live','backfill']) p ON CONFLICT DO NOTHING`, sensor)
	if err != nil {
		return 0, identityHistoryStats{}, err
	}
	cursor, eventID, cutover, ok, err := s.claimIdentityCursor(ctx, sensor, phase)
	if err != nil || !ok {
		return 0, identityHistoryStats{}, err
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
	// Keep a scalar time bound for pruning and an exact event-ID boundary before LIMIT.
	where := "sensor_id=" + chQuote(sensor) + " AND received_at>=" + stamp(cursor) + " AND (received_at>" + stamp(cursor) + " OR event_id>" + chQuote(eventID) + ") AND " + bound
	where += " AND received_at<=" + stamp(readUntil)
	raw, err := s.ch.query(ctx, fmt.Sprintf(`SELECT * FROM identity_signal_events_v1 WHERE %s ORDER BY sensor_id,received_at,event_id LIMIT %d SETTINGS max_threads=1,max_block_size=128,preferred_block_size_bytes=1048576,max_memory_usage=268435456,max_execution_time=15 FORMAT JSONEachRow`, where, limit))
	if err != nil {
		return 0, identityHistoryStats{}, err
	}
	events, err := decodeEventRows(raw)
	if err != nil {
		return 0, identityHistoryStats{}, err
	}
	var rows []struct {
		ReceivedAt string `json:"received_at"`
		EventID    string `json:"event_id"`
	}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return 0, identityHistoryStats{}, err
	}
	// Rows decoded by decodeEventRows are deduplicated by event_id, so the resume point
	// cannot be applied positionally: collect the accepted event ids first and filter by
	// membership. The cursor advances to the newest row the read returned and never
	// backwards, so a batch that is entirely at the cursor timestamp cannot loop on the
	// same keys.
	accepted := map[string]struct{}{}
	nextCursor, nextEventID := cursor, eventID
	for _, row := range rows {
		receivedAt, parseErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.ReceivedAt))
		if parseErr != nil {
			return 0, identityHistoryStats{}, parseErr
		}
		if !chRowAfterCursor(receivedAt, row.EventID, cursor, eventID) {
			continue
		}
		accepted[row.EventID] = struct{}{}
		if advancedStamp, advancedID, moved := chAdvanceCursor(nextCursor, nextEventID, chCursorRow{Stamp: receivedAt.UTC(), EventID: row.EventID}); moved {
			nextCursor, nextEventID = advancedStamp, advancedID
		}
	}
	if len(rows) > 0 && len(accepted) == 0 {
		fmt.Fprintf(os.Stderr, "identity %s cursor did not advance: all %d rows sit at %s\n", phase, len(rows), cursor.UTC().Format(time.RFC3339Nano))
	}
	if len(accepted) != len(rows) {
		kept := make([]normalized.Event, 0, len(accepted))
		for _, event := range events {
			if _, ok := accepted[event.EventID]; ok {
				kept = append(kept, event)
			}
		}
		events = kept
	}
	// Only the writes and the cursor advance need a transaction.
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, identityHistoryStats{}, err
	}
	defer tx.Rollback()
	var lockedCursor time.Time
	var lockedEventID string
	if err = tx.QueryRowContext(ctx, `SELECT cursor_at,event_id FROM identity_materializer_cursors WHERE sensor_id=$1 AND phase=$2 FOR UPDATE`, sensor, phase).Scan(&lockedCursor, &lockedEventID); err != nil {
		if err == sql.ErrNoRows {
			return 0, identityHistoryStats{}, nil
		}
		return 0, identityHistoryStats{}, err
	}
	// Another worker advanced the cursor while this batch read ClickHouse; drop the batch
	// instead of re-inserting events the winner already wrote.
	if !lockedCursor.Equal(cursor) || lockedEventID != eventID {
		return 0, identityHistoryStats{}, nil
	}
	// Another identity writer holds the lock. Wait a bounded time for it instead of
	// skipping: the domain worker re-acquires this lock continuously, so an instant skip
	// starves this lane permanently. The field measured the live cursor frozen while
	// endpoint_entities stopped advancing, with no error recorded anywhere. The cursor
	// still does not move when the wait expires, so the work is retried on the next loop.
	// An expired wait is reported as an error: returning success hid a frozen lane behind
	// an empty last_error on the field.
	if locked, lockErr := awaitIdentityWriteLock(ctx, tx, identityLockWaitBudget); lockErr != nil {
		return 0, identityHistoryStats{}, lockErr
	} else if !locked {
		return 0, identityHistoryStats{}, ErrIdentityWriteLockBusy
	}
	stats, err := writeIdentityEventsTx(ctx, tx, events)
	if err != nil {
		return 0, identityHistoryStats{}, err
	}
	// Signal aggregation happens only in this worker, not in the collector loop.
	signals := make([]DeviceSignal, 0, len(events))
	for _, item := range BuildDeviceInventories("latest-run", events, nil) {
		signals = append(signals, item.Signals...)
	}
	if err = upsertDeviceSignalFactsBatch(ctx, tx, sensor, signals); err != nil {
		return 0, identityHistoryStats{}, err
	}
	if len(rows) > 0 {
		cursor, eventID = nextCursor, nextEventID
	} else if readUntil.After(cursor) {
		cursor, eventID = readUntil, ""
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_materializer_cursors SET cursor_at=$3,event_id=$4,processed_events=processed_events+$5,last_success_at=now(),last_error='' WHERE sensor_id=$1 AND phase=$2`, sensor, phase, cursor, eventID, len(rows))
	if err != nil {
		return 0, identityHistoryStats{}, err
	}
	return len(rows), stats, tx.Commit()
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

type IdentityMaterializerOptions struct {
	HealthName             string
	Backfill               bool
	ProjectSnapshots       bool
	RefreshDeviceInventory bool
}

func (s *DBStore) RunIdentityMaterializer(ctx context.Context) {
	s.RunIdentityMaterializerWithOptions(ctx, IdentityMaterializerOptions{
		HealthName:             "identity-materializer",
		Backfill:               true,
		ProjectSnapshots:       true,
		RefreshDeviceInventory: true,
	})
}

func (s *DBStore) RunIdentityMaterializerWithOptions(ctx context.Context, options IdentityMaterializerOptions) {
	if options.HealthName == "" {
		options.HealthName = "identity-materializer"
	}
	done := []<-chan struct{}{}
	start := func(run func(context.Context)) {
		finished := make(chan struct{})
		done = append(done, finished)
		go func() {
			defer close(finished)
			run(ctx)
		}()
	}
	start(s.runIdentityInbox)
	start(s.runIdentityInboxExport)
	start(s.runIdentityCalibration)
	if options.ProjectSnapshots {
		start(s.runIdentitySnapshotMaterializer)
	}
	if options.RefreshDeviceInventory {
		start(s.runCurrentDeviceInventoryRefresh)
	}
	defer func() {
		for _, finished := range done {
			<-finished
		}
	}()
	batchSize := identitySignalBatchSize
	var lastHealth time.Time
	for ctx.Err() == nil {
		if s.deferIdentityDerivedWork(ctx) {
			continue
		}
		work, cancel := context.WithTimeout(ctx, identityWorkBudget)
		processed, stats, err := s.processIdentitySignalBatch(work, "live", batchSize)
		if err == nil && options.Backfill && processed < batchSize {
			_, stats, err = s.processIdentitySignalBatch(work, "backfill", batchSize)
		}
		cancel()
		batchSize = nextIdentityBatchSize(batchSize, err, processed)
		status := map[string]any{
			"last_checked_at":        time.Now().UTC().Format(time.RFC3339Nano),
			"processed_live_batch":   processed,
			"batch_size":             batchSize,
			"history_rows":           stats.HistoryRows,
			"history_window_inserts": stats.WindowInserts,
			"history_window_extends": stats.WindowExtends,
			"history_unchanged":      stats.WindowUnchanged,
			"last_error":             "",
		}
		if err != nil {
			status["last_error"] = err.Error()
			fmt.Fprintln(os.Stderr, "identity materializer:", err)
		}
		// The beacon is advisory, and this loop runs about once a second. Writing it every
		// iteration made one autocommit per second: the field measured 90 writes in 100
		// seconds at 245 ms each, ~22% of the lane's database time, on top of a `commit`
		// that already cost 228 ms. Write at most every identityHealthInterval, and always
		// immediately on failure so an error never waits for the next tick.
		if err == nil && time.Since(lastHealth) < identityHealthInterval {
			// Skip the beacon, but keep the loop's normal pacing below.
		} else {
			raw, _ := json.Marshal(status)
			health, c := context.WithTimeout(ctx, 5*time.Second)
			_, healthErr := s.pg.db.ExecContext(health, `INSERT INTO read_model_runtime_state(name,state) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, options.HealthName, raw)
			c()
			if healthErr != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "identity health:", healthErr)
			}
			if healthErr == nil {
				lastHealth = time.Now()
			}
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

// Device inventory refreshes scan a much broader evidence window than the
// realtime identity cursor. Keep that work outside the identity loop so a busy
// campus cannot delay newly arrived online/offline events.
func (s *DBStore) runCurrentDeviceInventoryRefresh(ctx context.Context) {
	for ctx.Err() == nil {
		if s.deferIdentityDerivedWork(ctx) {
			continue
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := s.pg.refreshCurrentDeviceInventory(work)
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "identity device inventory refresh:", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// Complete inventories are intentionally projected outside the realtime signal
// loop. A large campus snapshot must not delay new online/offline events, and a
// failed projection remains queued for an idempotent retry.
func (s *DBStore) runIdentitySnapshotMaterializer(ctx context.Context) {
	for ctx.Err() == nil {
		if s.deferIdentityDerivedWork(ctx) {
			continue
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := s.pg.projectPendingIdentitySnapshots(work, 1)
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "identity snapshot materializer:", err)
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

// Current identities have priority over history projection. Keeping the cursor
// unchanged makes this a pause, never a backlog skip. The indexed summary avoids
// reading evidence/history merely to decide whether work should be deferred.
func (s *DBStore) deferIdentityDerivedWork(ctx context.Context) bool {
	check, cancel := context.WithTimeout(ctx, time.Second)
	var backlog bool
	// Only this sensor's inbox gates its own derived work. The unscoped check let the NCU
	// inbox backlog pause the router-pilot materializer and export as well, silently.
	err := s.pg.db.QueryRowContext(check, `SELECT EXISTS(SELECT 1 FROM identity_pipeline_scopes WHERE sensor_id=$1 AND enabled AND pending_records>0 AND (pending_records>=100 OR oldest_pending_at<now()-interval '5 seconds'))`, s.pg.sensorID).Scan(&backlog)
	cancel()
	if err == nil && !backlog {
		return false
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
	return true
}
