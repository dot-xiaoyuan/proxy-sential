package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type activityV4BackfillBucket struct {
	Bucket string `json:"bucket"`
	Sensor string `json:"sensor_id"`
	Campus string `json:"campus_id"`
}

// EnqueueActivityV4Backfill walks a fixed source range in small, resumable
// pages. The realtime worker consumes v4 jobs only when its v3 lane is idle.
// This function never changes the read switch or deletes the v3 table.
func EnqueueActivityV4Backfill(ctx context.Context, pgDSN, chDSN string, from, until time.Time) error {
	from, until = from.UTC(), until.UTC()
	if !from.Before(until) || from.Second() != 0 || from.Nanosecond() != 0 || from.Minute()%5 != 0 || until.Second() != 0 || until.Nanosecond() != 0 || until.Minute()%5 != 0 {
		return fmt.Errorf("activity v4 backfill requires a nonempty five-minute-aligned UTC range")
	}
	pg, err := sql.Open("pgx", pgDSN)
	if err != nil {
		return err
	}
	defer pg.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: chDSN})
	if err != nil {
		return err
	}
	stamp := func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	name := "activity-v4-backfill:" + stamp(from) + ":" + stamp(until)
	for ctx.Err() == nil {
		tx, err := pg.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		initial := stamp(from.Add(-time.Second))
		_, err = tx.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state)
VALUES($1,jsonb_build_object('cursor_bucket',$2::text,'cursor_sensor','','cursor_campus','','complete',false)) ON CONFLICT DO NOTHING`, name, initial)
		if err != nil {
			tx.Rollback()
			return err
		}
		var cursor, sensor, campus string
		var complete bool
		err = tx.QueryRowContext(ctx, `SELECT state->>'cursor_bucket',state->>'cursor_sensor',state->>'cursor_campus',COALESCE((state->>'complete')::boolean,false)
FROM read_model_runtime_state WHERE name=$1 FOR UPDATE`, name).Scan(&cursor, &sensor, &campus, &complete)
		if err != nil {
			tx.Rollback()
			return err
		}
		if complete {
			tx.Rollback()
			return nil
		}
		query := fmt.Sprintf(`SELECT formatDateTime(bucket_start,'%%Y-%%m-%%dT%%H:%%i:%%SZ','UTC') bucket,sensor_id,campus_id
FROM activity_chart_bucket_versions_v3 WHERE granularity='5m'
 AND bucket_start>=parseDateTimeBestEffort(%s) AND bucket_start<parseDateTimeBestEffort(%s)
 AND (bucket_start,sensor_id,campus_id)>(parseDateTimeBestEffort(%s),%s,%s)
 GROUP BY bucket_start,sensor_id,campus_id ORDER BY bucket_start,sensor_id,campus_id LIMIT 16
 SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=15 FORMAT JSONEachRow`, chQuote(stamp(from)), chQuote(stamp(until)), chQuote(cursor), chQuote(sensor), chQuote(campus))
		readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		raw, err := ch.query(readCtx, query)
		cancel()
		if err != nil {
			tx.Rollback()
			return err
		}
		var buckets []activityV4BackfillBucket
		if err = decodeJSONEachRow(raw, &buckets); err != nil {
			tx.Rollback()
			return err
		}
		for _, bucket := range buckets {
			at, parseErr := time.Parse(time.RFC3339Nano, bucket.Bucket)
			if parseErr != nil {
				tx.Rollback()
				return parseErr
			}
			if !at.Before(until) || at.Before(from) || bucket.Sensor == "" {
				tx.Rollback()
				return fmt.Errorf("activity v4 backfill returned an invalid bucket")
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO read_model_jobs(model,bucket_start,sensor_id,campus_id,not_before)
VALUES($1,$2,$3,$4,now()) ON CONFLICT(model,bucket_start,sensor_id,campus_id) DO NOTHING`, activityV4FiveMinuteModel, at, bucket.Sensor, bucket.Campus); err != nil {
				tx.Rollback()
				return err
			}
			cursor, sensor, campus = bucket.Bucket, bucket.Sensor, bucket.Campus
		}
		_, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=state||jsonb_build_object('cursor_bucket',$2::text,'cursor_sensor',$3::text,'cursor_campus',$4::text,'complete',$5::boolean),updated_at=now() WHERE name=$1`, name, cursor, sensor, campus, len(buckets) < 16)
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if len(buckets) < 16 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return ctx.Err()
}
