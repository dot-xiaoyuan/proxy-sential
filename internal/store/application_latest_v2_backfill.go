package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type applicationLatestDigest struct {
	Keys uint64 `json:"keys"`
	Hash uint64 `json:"hash"`
}

// BackfillApplicationLatestV2 is resumable and never switches readers. The
// caller decides when to enable the read flag after every hot slice agrees.
func BackfillApplicationLatestV2(ctx context.Context, pgDSN, chDSN string) error {
	pg, err := sql.Open("pgx", pgDSN)
	if err != nil {
		return err
	}
	defer pg.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: chDSN})
	if err != nil {
		return err
	}
	const name = "application-latest-observations-v2"
	now := time.Now().UTC()
	if _, err = pg.ExecContext(ctx, `INSERT INTO application_read_model_backfills(name,cursor_at,until_at,status) VALUES($1,$2,$3,'running') ON CONFLICT DO NOTHING`, name, now.Add(-7*24*time.Hour), now); err != nil {
		return err
	}
	for ctx.Err() == nil {
		tx, beginErr := pg.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		var from, until time.Time
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT cursor_at,until_at,status FROM application_read_model_backfills WHERE name=$1 FOR UPDATE`, name).Scan(&from, &until, &status); err != nil {
			tx.Rollback()
			return err
		}
		if status == "completed" || !from.Before(until) {
			tx.Rollback()
			return nil
		}
		to := minTime(from.Add(5*time.Minute), until)
		where := fmt.Sprintf(`timestamp>=parseDateTime64BestEffort(%s,9) AND timestamp<parseDateTime64BestEffort(%s,9)`, chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano)))
		query := `INSERT INTO application_latest_observations_v2(timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,classification_revision,batch_id)
SELECT timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,classification_revision,batch_id
FROM application_observations WHERE ` + where + ` SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=25,async_insert=0`
		sliceCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
		err = ch.exec(sliceCtx, query)
		if err == nil {
			err = verifyApplicationLatestV2Slice(sliceCtx, ch, where)
		}
		cancel()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("compact application latest [%s,%s): %w", from, to, err)
		}
		nextStatus := "running"
		if !to.Before(until) {
			nextStatus = "completed"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE application_read_model_backfills SET cursor_at=$2,status=$3,updated_at=now() WHERE name=$1`, name, to, nextStatus); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func verifyApplicationLatestV2Slice(ctx context.Context, ch *ClickHouseStore, where string) error {
	var previous, compact []applicationLatestDigest
	for index, table := range []string{"application_latest_observations", "application_latest_observations_v2"} {
		query := `SELECT count() keys,groupBitXor(cityHash64(timestamp,sensor_id,event_id,classification_revision,batch_id,campus_id,ip,target_id,target_type,name,category)) hash FROM ` + table + ` FINAL WHERE ` + where + ` SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`
		raw, err := ch.query(ctx, query)
		if err != nil {
			return err
		}
		if index == 0 {
			err = decodeJSONEachRow(raw, &previous)
		} else {
			err = decodeJSONEachRow(raw, &compact)
		}
		if err != nil {
			return err
		}
	}
	if len(previous) != 1 || len(compact) != 1 || previous[0] != compact[0] {
		return fmt.Errorf("compact latest slice mismatch: previous=%v compact=%v", previous, compact)
	}
	return nil
}
