package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// BackfillApplicationReadModel streams bounded time slices into the latest-event
// model. The MV captures concurrent inserts, including reclassification of old
// timestamps. FINAL makes replayed slices harmless without relying on merges.
// Progress commits only after a synchronous CH insert; restart resumes safely.
func BackfillApplicationReadModel(ctx context.Context, pgDSN, chDSN string) error {
	db, err := sql.Open("pgx", pgDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: chDSN})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(ctx, `INSERT INTO application_read_model_backfills(name,cursor_at,until_at,status) VALUES('latest-observations-v1',$1,$2,'running') ON CONFLICT DO NOTHING`, now.Add(-7*24*time.Hour), now)
	if err != nil {
		return err
	}
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var from, until time.Time
		var status string
		err = tx.QueryRowContext(ctx, `SELECT cursor_at,until_at,status FROM application_read_model_backfills WHERE name='latest-observations-v1' FOR UPDATE`).Scan(&from, &until, &status)
		if err != nil {
			tx.Rollback()
			return err
		}
		if status == "completed" {
			tx.Rollback()
			if err := BackfillNormalizedEventFeatures(ctx, db, ch); err != nil {
				return err
			}
			model := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
			if err := BackfillActivityChartKeys(ctx, db, ch); err != nil {
				return err
			}
			if err := model.DrainActivityChartReadModel(ctx); err != nil {
				return fmt.Errorf("backfill activity statistics: %w", err)
			}
			if err := BackfillApplicationObservationKeys(ctx, db, ch); err != nil {
				return err
			}
			if err := model.DrainApplicationObservationReadModel(ctx); err != nil {
				return fmt.Errorf("backfill application observation statistics: %w", err)
			}
			if err := model.DrainApplicationConnectionReadModel(ctx); err != nil {
				return fmt.Errorf("backfill application connections: %w", err)
			}
			return nil
		}
		to := minTime(from.Add(5*time.Minute), until)
		query := fmt.Sprintf(`INSERT INTO application_latest_observations(timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,observation_json,classification_revision,batch_id) SELECT timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,observation_json,classification_revision,batch_id FROM application_observations WHERE timestamp>=parseDateTime64BestEffort(%s,9) AND timestamp<parseDateTime64BestEffort(%s,9) SETTINGS max_threads=2,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_execution_time=30,async_insert=0`, chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano)))
		sliceCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		err = ch.exec(sliceCtx, query)
		if err == nil {
			connectionQuery := fmt.Sprintf(`INSERT INTO application_connection_observations(timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,classification_revision,batch_id) SELECT timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,classification_revision,batch_id FROM application_observations WHERE timestamp>=parseDateTime64BestEffort(%s,9) AND timestamp<parseDateTime64BestEffort(%s,9) AND event_type!='dns' AND connection_id!='' SETTINGS max_threads=2,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_execution_time=30,async_insert=0`, chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano)))
			err = ch.exec(sliceCtx, connectionQuery)
		}
		cancel()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("backfill latest observations [%s,%s): %w", from, to, err)
		}
		nextStatus := "running"
		if !to.Before(until) {
			nextStatus = "completed"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE application_read_model_backfills SET cursor_at=$1,status=$2,updated_at=now() WHERE name='latest-observations-v1'`, to, nextStatus); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
}

// The capture view exists before this high-water mark is recorded. New and
// late events are captured concurrently; each historical slice is restartable.
func BackfillNormalizedEventFeatures(ctx context.Context, db *sql.DB, ch *ClickHouseStore) error {
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO application_read_model_backfills(name,cursor_at,until_at,status) VALUES('normalized-event-features-v1',$1,$2,'running') ON CONFLICT DO NOTHING`, now.Add(-7*24*time.Hour), now); err != nil {
		return err
	}
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var from, until time.Time
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT cursor_at,until_at,status FROM application_read_model_backfills WHERE name='normalized-event-features-v1' FOR UPDATE`).Scan(&from, &until, &status); err != nil {
			tx.Rollback()
			return err
		}
		if status == "completed" {
			tx.Rollback()
			return nil
		}
		to := minTime(from.Add(5*time.Minute), until)
		query := fmt.Sprintf(`INSERT INTO normalized_event_features SELECT timestamp,event_id,sensor_id,campus_id,type,proto,subject_ip,dst_ip,dst_port,JSONExtractString(payload_json,'query'),JSONExtractString(payload_json,'host'),JSONExtractString(payload_json,'sni'),JSONExtractString(payload_json,'user_agent'),JSONExtractString(payload_json,'ja3'),JSONExtractString(payload_json,'ja4'),JSONExtractInt(flow_json,'ttl'),JSONExtractString(flow_json,'app_protocol') FROM normalized_events WHERE timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<parseDateTime64BestEffort(%s,6) SETTINGS max_threads=1,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_execution_time=20,async_insert=0`, chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano)))
		if err = ch.exec(ctx, query); err != nil {
			tx.Rollback()
			return fmt.Errorf("backfill normalized features [%s,%s): %w", from, to, err)
		}
		next := "running"
		if !to.Before(until) {
			next = "completed"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE application_read_model_backfills SET cursor_at=$1,status=$2,updated_at=now() WHERE name='normalized-event-features-v1'`, to, next); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
