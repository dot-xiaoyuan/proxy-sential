package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type applicationObservationCursor struct {
	WrittenAt   string `json:"written_at"`
	WindowStart string `json:"window_start"`
	SensorID    string `json:"sensor_id"`
	CampusID    string `json:"campus_id"`
}

func (s *DBStore) updateApplicationObservationReadModel(ctx context.Context) (bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO application_observation_read_model_cursor_v2(id) VALUES(1) ON CONFLICT DO NOTHING`); err != nil {
		return false, err
	}
	var raw []byte
	var cursor applicationObservationCursor
	if err = tx.QueryRowContext(ctx, `SELECT cursor_document FROM application_observation_read_model_cursor_v2 WHERE id=1 FOR UPDATE`).Scan(&raw); err != nil {
		return false, err
	}
	if err = json.Unmarshal(raw, &cursor); err != nil {
		return false, err
	}
	where := "1"
	if cursor.WrittenAt != "" {
		where = "(application_observation_dirty_log.written_at,application_observation_dirty_log.window_start,sensor_id,campus_id)>(parseDateTime64BestEffort(" + chQuote(cursor.WrittenAt) + ",9),parseDateTimeBestEffort(" + chQuote(cursor.WindowStart) + ")," + chQuote(cursor.SensorID) + "," + chQuote(cursor.CampusID) + ")"
	}
	// Multiple receipts for the same bucket are represented by their latest
	// receipt. Rebuilding canonical revisions once covers all earlier receipts;
	// order by that receipt keeps the persisted watermark stable.
	raw, err = s.ch.query(ctx, `SELECT concat(replaceOne(toString(latest_receipt),' ','T'),'Z') AS written_at,formatDateTime(window_start,'%Y-%m-%dT%H:%i:%SZ','UTC') AS window_start,sensor_id,campus_id FROM (SELECT max(written_at) AS latest_receipt,window_start,sensor_id,campus_id FROM application_observation_dirty_log WHERE `+where+` GROUP BY window_start,sensor_id,campus_id) ORDER BY latest_receipt,window_start,sensor_id,campus_id LIMIT 20 SETTINGS max_threads=1 FORMAT JSONEachRow`)
	if err != nil {
		return false, err
	}
	var rows []applicationObservationCursor
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return false, err
	}
	if len(rows) == 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE application_observation_read_model_cursor_v2 SET updated_at=now() WHERE id=1`); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	keys := []string{}
	seen := map[string]bool{}
	var first, last time.Time
	for _, row := range rows {
		stamp, err := time.Parse(time.RFC3339Nano, row.WindowStart)
		if err != nil {
			return false, err
		}
		if first.IsZero() || stamp.Before(first) {
			first = stamp
		}
		if last.IsZero() || stamp.After(last) {
			last = stamp
		}
		key := "(parseDateTimeBestEffort(" + chQuote(row.WindowStart) + ")," + chQuote(row.SensorID) + "," + chQuote(row.CampusID) + ")"
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	var revision uint64
	if err = tx.QueryRowContext(ctx, `SELECT nextval('application_connection_summary_revision_seq')`).Scan(&revision); err != nil {
		return false, err
	}
	sourceWhere := "timestamp>=parseDateTime64BestEffort(" + chQuote(first.Format(time.RFC3339Nano)) + ",6) AND timestamp<parseDateTime64BestEffort(" + chQuote(last.Add(5*time.Minute).Format(time.RFC3339Nano)) + ",6) AND (toStartOfFiveMinutes(timestamp),sensor_id,campus_id) IN(" + strings.Join(keys, ",") + ")"
	// Tombstones remove obsolete classification keys before the rebuilt
	// canonical bucket is installed. Distinct revisions avoid equal-version ties.
	oldWhere := "(window_start,sensor_id,campus_id) IN(" + strings.Join(keys, ",") + ")"
	query := fmt.Sprintf(`INSERT INTO application_observation_bucket_facts_v2 SELECT window_start,sensor_id,campus_id,bundle_version,event_type,target_type,target_id,unknown_domain,missing_connection,toUInt64(0),name,category,last_seen,terminals,toUInt64(%d) FROM application_observation_bucket_facts_v2 FINAL WHERE %s SETTINGS max_threads=1,max_memory_usage=268435456,async_insert=0`, revision*2, oldWhere)
	tombstones := strings.Split(query, " SETTINGS ")[0]
	query = fmt.Sprintf(`SELECT toStartOfFiveMinutes(timestamp) AS window_start,sensor_id,campus_id,bundle_version,event_type,target_type,target_id,toUInt8(domain!='' AND target_id='') AS unknown_domain,toUInt8(event_type!='dns' AND connection_id='') AS missing_connection,count() AS event_count,argMax(application_latest_observations.name,timestamp) AS name,argMax(application_latest_observations.category,timestamp) AS category,max(timestamp) AS last_seen,groupUniqArrayIf(tuple(campus_id,ip),ip!='') AS terminals,toUInt64(%d) AS revision FROM application_latest_observations FINAL WHERE %s GROUP BY window_start,sensor_id,campus_id,bundle_version,event_type,target_type,target_id,unknown_domain,missing_connection SETTINGS max_threads=1,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_bytes_before_external_group_by=134217728,max_execution_time=20,async_insert=0`, revision*2+1, sourceWhere)
	if err = s.ch.exec(ctx, tombstones+" UNION ALL "+query); err != nil {
		return false, err
	}

	if err = s.rebuildApplicationObservationCoarseBuckets(ctx, rows, revision); err != nil {
		return false, err
	}
	raw, err = json.Marshal(rows[len(rows)-1])
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE application_observation_read_model_cursor_v2 SET cursor_document=$1,updated_at=$2::timestamptz WHERE id=1`, raw, rows[len(rows)-1].WrittenAt); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *DBStore) DrainApplicationObservationReadModel(ctx context.Context) error {
	for {
		more, err := s.updateApplicationObservationReadModel(ctx)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

func (s *DBStore) RunApplicationObservationReadModel(ctx context.Context) {
	for {
		batchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		more, err := s.updateApplicationObservationReadModel(batchCtx)
		cancel()
		delay := time.Second
		if more && err == nil {
			// Bound background rebuild pressure so continuous ingest cannot starve
			// interactive API queries. The cursor keeps catch-up restartable.
			delay = 5 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func BackfillApplicationObservationKeys(ctx context.Context, db *sql.DB, ch *ClickHouseStore) error {
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO application_read_model_backfills(name,cursor_at,until_at,status) VALUES('application-observation-buckets-v2',$1,$2,'running') ON CONFLICT DO NOTHING`, now.Add(-7*24*time.Hour), now); err != nil {
		return err
	}
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var from, until time.Time
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT cursor_at,until_at,status FROM application_read_model_backfills WHERE name='application-observation-buckets-v2' FOR UPDATE`).Scan(&from, &until, &status); err != nil {
			tx.Rollback()
			return err
		}
		if status == "completed" {
			tx.Rollback()
			return nil
		}
		to := minTime(from.Add(time.Hour), until)
		query := fmt.Sprintf(`INSERT INTO application_observation_dirty_log SELECT now64(9),toStartOfFiveMinutes(timestamp) AS window_start,sensor_id,campus_id FROM application_latest_observations FINAL WHERE timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<parseDateTime64BestEffort(%s,6) GROUP BY window_start,sensor_id,campus_id SETTINGS max_threads=1,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_execution_time=20,async_insert=0`, chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano)))
		if err = ch.exec(ctx, query); err != nil {
			tx.Rollback()
			return err
		}
		next := "running"
		if !to.Before(until) {
			next = "completed"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE application_read_model_backfills SET cursor_at=$1,status=$2,updated_at=now() WHERE name='application-observation-buckets-v2'`, to, next); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
}
