package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	activityV3FiveMinuteModel = "activity-5m-v3"
	activityV3HourModel       = "activity-hour-v3"
	activityV3DayModel        = "activity-day-v3"
	activityV3CutoverState    = "activity-v3"
	activityV3DispatchState   = "activity-v3-dispatch"
)

type readModelJob struct {
	Model           string
	BucketStart     time.Time
	SensorID        string
	CampusID        string
	DirtyGeneration int64
	Attempts        int
}

func (s *DBStore) ensureActivityV3Cutover(ctx context.Context) (time.Time, error) {
	requested := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_ACTIVITY_V3_CUTOVER"))
	cutover := time.Now().UTC()
	if requested != "" {
		parsed, err := time.Parse(time.RFC3339Nano, requested)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse PROXY_SENTINEL_ACTIVITY_V3_CUTOVER: %w", err)
		}
		cutover = parsed.UTC()
	}
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state)
VALUES($1,jsonb_build_object('cutover',$2::text,'available_from',$2::text)) ON CONFLICT(name) DO NOTHING`, activityV3CutoverState, cutover.Format(time.RFC3339Nano))
	if err != nil {
		return time.Time{}, err
	}
	var raw string
	if err = s.pg.db.QueryRowContext(ctx, `SELECT state->>'cutover' FROM read_model_runtime_state WHERE name=$1`, activityV3CutoverState).Scan(&raw); err != nil {
		return time.Time{}, err
	}
	return parseReadModelTime(raw)
}

// PostgreSQL renders timestamptz::text with a space separator and may shorten
// UTC offsets to +00. Runtime state predates the canonical formatter below, so
// readers remain compatible while the worker rewrites values as RFC3339.
func parseReadModelTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 10 && raw[10] == ' ' {
		raw = raw[:10] + "T" + raw[11:]
	}
	if len(raw) >= 3 {
		offset := raw[len(raw)-3:]
		if (offset[0] == '+' || offset[0] == '-') && offset[1] >= '0' && offset[1] <= '9' && offset[2] >= '0' && offset[2] <= '9' {
			raw += ":00"
		}
	}
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse read-model timestamp %q: %w", raw, err)
	}
	return value, nil
}

// dispatchActivityV3Jobs advances a cheap receipt cursor independently of all
// ClickHouse aggregation. Repeated receipts collapse into one PostgreSQL job.
func (s *DBStore) dispatchActivityV3Jobs(ctx context.Context) (int, error) {
	cutover, err := s.ensureActivityV3Cutover(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state) VALUES($1,'{}') ON CONFLICT(name) DO NOTHING`, activityV3DispatchState); err != nil {
		return 0, err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT state FROM read_model_runtime_state WHERE name=$1 FOR UPDATE`, activityV3DispatchState).Scan(&raw); err != nil {
		return 0, err
	}
	var cursor activityChartCursor
	if err = json.Unmarshal(raw, &cursor); err != nil {
		return 0, err
	}
	where := "l.written_at>=parseDateTime64BestEffort(" + chQuote(cutover.Format(time.RFC3339Nano)) + ",9)" +
		" AND l.window_start>=toStartOfFiveMinutes(parseDateTimeBestEffort(" + chQuote(cutover.Format(time.RFC3339Nano)) + "))"
	if cursor.WrittenAt != "" {
		where += " AND (l.written_at,l.window_start,l.sensor_id,l.campus_id)>(parseDateTime64BestEffort(" + chQuote(cursor.WrittenAt) + ",9),parseDateTimeBestEffort(" + chQuote(cursor.WindowStart) + ")," + chQuote(cursor.SensorID) + "," + chQuote(cursor.CampusID) + ")"
	}
	// A high-throughput insert stream can emit hundreds of receipts for the same
	// five-minute bucket. Collapse them before they reach PostgreSQL; the job row
	// represents dirty state, not the number of ClickHouse insert blocks.
	data, err := s.ch.query(ctx, `SELECT concat(replaceOne(toString(max(l.written_at)),' ','T'),'Z') written_at,formatDateTime(l.window_start,'%Y-%m-%dT%H:%i:%SZ','UTC') window_start,l.sensor_id sensor_id,l.campus_id campus_id FROM activity_chart_dirty_log l WHERE `+where+` GROUP BY l.window_start,l.sensor_id,l.campus_id ORDER BY max(l.written_at),l.window_start,l.sensor_id,l.campus_id LIMIT 10000 SETTINGS max_threads=1,max_memory_usage=268435456,max_bytes_before_external_group_by=67108864 FORMAT JSONEachRow`)
	if err != nil {
		return 0, err
	}
	rows := []activityChartCursor{}
	if err = decodeJSONEachRow(data, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		_, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET updated_at=now() WHERE name=$1`, activityV3DispatchState)
		if err != nil {
			return 0, err
		}
		return 0, tx.Commit()
	}
	seen := map[[3]string]bool{}
	for _, row := range rows {
		bucket, parseErr := time.Parse(time.RFC3339Nano, row.WindowStart)
		if parseErr != nil {
			return 0, parseErr
		}
		key := [3]string{row.WindowStart, row.SensorID, row.CampusID}
		if seen[key] {
			continue
		}
		seen[key] = true
		now := time.Now().UTC()
		notBefore := now.Add(30 * time.Second)
		historical := bucket.Add(5*time.Minute + 90*time.Second).Before(now)
		if historical {
			// Old buckets are normally produced while ingest catches up. Debounce
			// them until receipts have been quiet for 90 seconds, instead of
			// rebuilding the same immutable bucket after every replay batch.
			notBefore = now.Add(90 * time.Second)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO read_model_jobs(model,bucket_start,sensor_id,campus_id,not_before)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(model,bucket_start,sensor_id,campus_id) DO UPDATE SET
dirty_generation=CASE
 WHEN read_model_jobs.status='running' THEN GREATEST(read_model_jobs.dirty_generation,read_model_jobs.processed_generation+2)
 WHEN read_model_jobs.processed_generation<read_model_jobs.dirty_generation THEN read_model_jobs.dirty_generation
 ELSE read_model_jobs.dirty_generation+1 END,
not_before=CASE WHEN $6 THEN GREATEST(read_model_jobs.not_before,EXCLUDED.not_before) ELSE LEAST(read_model_jobs.not_before,EXCLUDED.not_before) END,
status=CASE WHEN read_model_jobs.status='running' THEN 'running' ELSE 'pending' END,updated_at=now()`, activityV3FiveMinuteModel, bucket, row.SensorID, row.CampusID, notBefore, historical); err != nil {
			return 0, err
		}
	}
	last, _ := json.Marshal(rows[len(rows)-1])
	if _, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=$2,updated_at=now() WHERE name=$1`, activityV3DispatchState, last); err != nil {
		return 0, err
	}
	return len(seen), tx.Commit()
}

func (s *DBStore) claimReadModelJob(ctx context.Context, models []string, worker string) (readModelJob, bool, error) {
	row := s.pg.db.QueryRowContext(ctx, `WITH picked AS (
 SELECT model,bucket_start,sensor_id,campus_id FROM read_model_jobs
 WHERE model=ANY($1::text[]) AND processed_generation<dirty_generation AND not_before<=now()
 AND (status<>'running' OR lease_until<now())
 ORDER BY CASE model WHEN 'activity-5m-v3' THEN 0 WHEN 'activity-hour-v3' THEN 1 ELSE 2 END,
 CASE WHEN model='activity-5m-v3' THEN bucket_start END DESC,
 CASE WHEN model<>'activity-5m-v3' THEN bucket_start END ASC
 FOR UPDATE SKIP LOCKED LIMIT 1)
UPDATE read_model_jobs j SET status='running',lease_owner=$2,lease_until=now()+interval '2 minutes',updated_at=now()
FROM picked p WHERE j.model=p.model AND j.bucket_start=p.bucket_start AND j.sensor_id=p.sensor_id AND j.campus_id=p.campus_id
RETURNING j.model,j.bucket_start,j.sensor_id,j.campus_id,j.dirty_generation,j.attempts`, models, worker)
	var job readModelJob
	if err := row.Scan(&job.Model, &job.BucketStart, &job.SensorID, &job.CampusID, &job.DirtyGeneration, &job.Attempts); err != nil {
		if err == sql.ErrNoRows {
			return readModelJob{}, false, nil
		}
		return readModelJob{}, false, err
	}
	return job, true, nil
}

func (s *DBStore) finishReadModelJob(ctx context.Context, job readModelJob, runErr error) error {
	if runErr == nil {
		nextNotBefore := activitySuccessfulNotBefore(job.Model, time.Now().UTC())
		_, err := s.pg.db.ExecContext(ctx, `UPDATE read_model_jobs SET processed_generation=GREATEST(processed_generation,$5),
status=CASE WHEN dirty_generation>$5 THEN 'pending' ELSE 'completed' END,
attempts=0,lease_owner='',lease_until='-infinity',last_error='',
not_before=GREATEST(not_before,$6),updated_at=now()
WHERE model=$1 AND bucket_start=$2 AND sensor_id=$3 AND campus_id=$4`, job.Model, job.BucketStart, job.SensorID, job.CampusID, job.DirtyGeneration, nextNotBefore)
		return err
	}
	attempts := job.Attempts + 1
	delay := time.Second * time.Duration(1<<min(attempts, 8))
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	_, err := s.pg.db.ExecContext(ctx, `UPDATE read_model_jobs SET status='pending',attempts=$5,lease_owner='',lease_until='-infinity',
last_error=$6,not_before=now()+$7::interval,updated_at=now()
WHERE model=$1 AND bucket_start=$2 AND sensor_id=$3 AND campus_id=$4`, job.Model, job.BucketStart, job.SensorID, job.CampusID, attempts, runErr.Error(), delay.String())
	return err
}

// activitySuccessfulNotBefore rate-limits rebuilds after a successful
// publication. Dirty generations are never discarded; they remain pending and
// are folded into the next complete revision. This is especially important
// during catch-up, where late receipts can otherwise rebuild a million-row hour
// every 90 seconds and starve interactive queries.
func activitySuccessfulNotBefore(model string, now time.Time) time.Time {
	switch model {
	case activityV3FiveMinuteModel:
		return now.Add(30 * time.Second)
	case activityV3HourModel:
		return now.Add(10 * time.Minute)
	case activityV3DayModel:
		return now.Add(30 * time.Minute)
	default:
		return now
	}
}

func (s *DBStore) nextReadModelRevision(ctx context.Context) (uint64, error) {
	var revision uint64
	err := s.pg.db.QueryRowContext(ctx, `SELECT nextval('read_model_revision_v3_seq')`).Scan(&revision)
	return revision, err
}

func activityV3Scope(sensorID, campusID string) string {
	return "sensor_id=" + chQuote(sensorID) + " AND campus_id=" + chQuote(campusID)
}

func activityV3AliasedScope(alias, sensorID, campusID string) string {
	if alias != "" {
		alias += "."
	}
	return alias + "sensor_id=" + chQuote(sensorID) + " AND " + alias + "campus_id=" + chQuote(campusID)
}

func (s *DBStore) publishActivityV3Version(ctx context.Context, granularity string, bucket time.Time, sensorID, campusID string, revision uint64, finalized bool) error {
	final := 0
	if finalized {
		final = 1
	}
	query := fmt.Sprintf(`INSERT INTO activity_chart_bucket_versions_v3(granularity,bucket_start,sensor_id,campus_id,revision,source_as_of,published_at,finalized) VALUES(%s,parseDateTimeBestEffort(%s),%s,%s,toUInt64(%d),now64(9),now64(9),toUInt8(%d))`, chQuote(granularity), chQuote(bucket.UTC().Format(time.RFC3339Nano)), chQuote(sensorID), chQuote(campusID), revision, final)
	return s.ch.exec(ctx, query)
}

func (s *DBStore) materializeActivityV3FiveMinute(ctx context.Context, job readModelJob) error {
	revision, err := s.nextReadModelRevision(ctx)
	if err != nil {
		return err
	}
	from, to := job.BucketStart.UTC(), job.BucketStart.UTC().Add(5*time.Minute)
	sourceFrom := from
	cutover, err := s.ensureActivityV3Cutover(ctx)
	if err != nil {
		return err
	}
	if sourceFrom.Before(cutover) {
		sourceFrom = cutover
	}
	sourceWhere := "timestamp>=parseDateTime64BestEffort(" + chQuote(sourceFrom.Format(time.RFC3339Nano)) + ",6) AND timestamp<parseDateTime64BestEffort(" + chQuote(to.Format(time.RFC3339Nano)) + ",6) AND " + activityV3Scope(job.SensorID, job.CampusID)
	query := fmt.Sprintf(`INSERT INTO activity_chart_facts_5m_v3 SELECT toStartOfFiveMinutes(timestamp) bucket_start,sensor_id,campus_id,toUInt64(%d) revision,t.1 dimension,t.2 value,count() event_count,min(timestamp) first_seen,max(timestamp) last_seen FROM(SELECT timestamp,sensor_id,campus_id,arrayJoin(%s) t FROM normalized_event_features WHERE %s) GROUP BY bucket_start,sensor_id,campus_id,dimension,value SETTINGS max_threads=1,max_memory_usage=536870912,max_bytes_before_external_group_by=134217728,max_execution_time=15`, revision, activityChartArray, sourceWhere)
	if err = s.ch.exec(ctx, query); err != nil {
		return err
	}
	finalized := !time.Now().UTC().Before(to.Add(90 * time.Second))
	if err = s.publishActivityV3Version(ctx, "5m", from, job.SensorID, job.CampusID, revision, finalized); err != nil {
		return err
	}
	if finalized {
		hour := from.Truncate(time.Hour)
		// Late and replayed receipts can finalize several child buckets for the
		// same hour in quick succession. Push the parent job out after every
		// child publication so the hour is rebuilt once after the stream is
		// quiet, rather than once per child generation.
		notBefore := activityParentNotBefore(hour.Add(time.Hour+5*time.Minute), time.Now().UTC(), 90*time.Second)
		_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_jobs(model,bucket_start,sensor_id,campus_id,not_before)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(model,bucket_start,sensor_id,campus_id) DO UPDATE SET
dirty_generation=CASE
 WHEN read_model_jobs.status='running' THEN GREATEST(read_model_jobs.dirty_generation,read_model_jobs.processed_generation+2)
 WHEN read_model_jobs.processed_generation<read_model_jobs.dirty_generation THEN read_model_jobs.dirty_generation
 ELSE read_model_jobs.dirty_generation+1 END,
status=CASE WHEN read_model_jobs.status='running' THEN 'running' ELSE 'pending' END,
not_before=GREATEST(read_model_jobs.not_before,EXCLUDED.not_before),updated_at=now()`, activityV3HourModel, hour, job.SensorID, job.CampusID, notBefore)
		if err != nil {
			return err
		}
	}
	asOf := to
	if now := time.Now().UTC(); asOf.After(now) {
		asOf = now
	}
	return s.updateActivityV3State(ctx, "5m", asOf)
}

func (s *DBStore) materializeActivityV3Coarse(ctx context.Context, job readModelJob) error {
	revision, err := s.nextReadModelRevision(ctx)
	if err != nil {
		return err
	}
	query, granularity, from, err := activityV3CoarseMaterializeSQL(job, revision)
	if err != nil {
		return err
	}
	if err = s.ch.exec(ctx, query); err != nil {
		return err
	}
	if err = s.publishActivityV3Version(ctx, granularity, from, job.SensorID, job.CampusID, revision, true); err != nil {
		return err
	}
	if granularity == "hour" {
		day := from.Truncate(24 * time.Hour)
		notBefore := activityParentNotBefore(day.Add(24*time.Hour+30*time.Minute), time.Now().UTC(), 5*time.Minute)
		_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_jobs(model,bucket_start,sensor_id,campus_id,not_before)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(model,bucket_start,sensor_id,campus_id) DO UPDATE SET
dirty_generation=CASE
 WHEN read_model_jobs.status='running' THEN GREATEST(read_model_jobs.dirty_generation,read_model_jobs.processed_generation+2)
 WHEN read_model_jobs.processed_generation<read_model_jobs.dirty_generation THEN read_model_jobs.dirty_generation
 ELSE read_model_jobs.dirty_generation+1 END,
status=CASE WHEN read_model_jobs.status='running' THEN 'running' ELSE 'pending' END,
not_before=GREATEST(read_model_jobs.not_before,EXCLUDED.not_before),updated_at=now()`, activityV3DayModel, day, job.SensorID, job.CampusID, notBefore)
		if err != nil {
			return err
		}
	}
	return s.updateActivityV3State(ctx, granularity, time.Now().UTC())
}

func activityParentNotBefore(parentReadyAt, now time.Time, settle time.Duration) time.Time {
	quietAt := now.Add(settle)
	if parentReadyAt.After(quietAt) {
		return parentReadyAt
	}
	return quietAt
}

func activityV3CoarseMaterializeSQL(job readModelJob, revision uint64) (string, string, time.Time, error) {
	granularity, childGranularity, targetTable, sourceTable, truncate, width := "hour", "5m", "activity_chart_facts_hour_v3", "activity_chart_facts_5m_v3", "toStartOfHour", time.Hour
	if job.Model == activityV3DayModel {
		granularity, childGranularity, targetTable, sourceTable, truncate, width = "day", "hour", "activity_chart_facts_day_v3", "activity_chart_facts_hour_v3", "toStartOfDay", 24*time.Hour
	} else if job.Model != activityV3HourModel {
		return "", "", time.Time{}, fmt.Errorf("unsupported activity coarse model %q", job.Model)
	}
	from, to := job.BucketStart.UTC(), job.BucketStart.UTC().Add(width)
	fromSQL, toSQL := chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano))
	// Keep the selected revision in a primary-key tuple predicate. A JOIN makes
	// ClickHouse scan every superseded revision before it can apply the match;
	// at campus traffic volume that turns a 2-3 second bucket rebuild into a
	// repeatable 60 second timeout.
	query := fmt.Sprintf(`INSERT INTO %s SELECT %s(f.bucket_start) bucket_start,f.sensor_id,f.campus_id,toUInt64(%d) revision,f.dimension,f.value,sum(f.event_count),min(f.first_seen),max(f.last_seen) FROM %s f PREWHERE f.bucket_start>=parseDateTimeBestEffort(%s) AND f.bucket_start<parseDateTimeBestEffort(%s) AND %s WHERE (f.bucket_start,f.sensor_id,f.campus_id,f.revision) IN(SELECT bucket_start,sensor_id,campus_id,argMax(revision,published_at) revision FROM activity_chart_bucket_versions_v3 WHERE granularity=%s AND bucket_start>=parseDateTimeBestEffort(%s) AND bucket_start<parseDateTimeBestEffort(%s) AND %s GROUP BY bucket_start,sensor_id,campus_id) GROUP BY bucket_start,sensor_id,campus_id,dimension,value SETTINGS max_threads=1,max_memory_usage=1073741824,max_bytes_before_external_group_by=268435456,max_execution_time=30`, targetTable, truncate, revision, sourceTable, fromSQL, toSQL, activityV3AliasedScope("f", job.SensorID, job.CampusID), chQuote(childGranularity), fromSQL, toSQL, activityV3Scope(job.SensorID, job.CampusID))
	return query, granularity, from, nil
}

func (s *DBStore) updateActivityV3State(ctx context.Context, granularity string, asOf time.Time) error {
	name := "activity-v3-" + granularity
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at)
VALUES($1,jsonb_build_object('as_of',$2::text),now()) ON CONFLICT(name) DO UPDATE SET
state=jsonb_build_object('as_of',GREATEST(
 COALESCE((read_model_runtime_state.state->>'as_of')::timestamptz,'-infinity'::timestamptz),
 $2::timestamptz)),updated_at=now()`, name, asOf.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *DBStore) RunActivityV3Realtime(ctx context.Context) {
	worker := fmt.Sprintf("realtime-%d", os.Getpid())
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if _, dispatchErr := s.dispatchActivityV3Jobs(workCtx); dispatchErr != nil {
			fmt.Fprintf(os.Stderr, "activity v3 dispatch failed: %v\n", dispatchErr)
		}
		job, found, err := s.claimReadModelJob(workCtx, []string{activityV3FiveMinuteModel}, worker)
		if err != nil {
			fmt.Fprintf(os.Stderr, "activity v3 realtime claim failed: %v\n", err)
		}
		if err == nil && found {
			err = s.materializeActivityV3FiveMinute(workCtx, job)
			if err != nil {
				fmt.Fprintf(os.Stderr, "activity v3 realtime materialize failed: %v\n", err)
			}
			_ = s.finishReadModelJob(context.WithoutCancel(workCtx), job, err)
		}
		cancel()
		delay := time.Second
		if !found {
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

func (s *DBStore) RunActivityV3Coarse(ctx context.Context) {
	worker := fmt.Sprintf("coarse-%d", os.Getpid())
	healthySince := time.Time{}
	paused := true
	for ctx.Err() == nil {
		// Realtime lag pauses all coarse work without consuming a job lease.
		var lagSeconds float64
		lagErr := s.pg.db.QueryRowContext(ctx, `SELECT EXTRACT(EPOCH FROM now()-(state->>'as_of')::timestamptz)
FROM read_model_runtime_state WHERE name='activity-v3-5m'`).Scan(&lagSeconds)
		if lagErr != nil || lagSeconds > 90 {
			paused = true
			healthySince = time.Time{}
		} else if paused {
			if lagSeconds <= 60 {
				if healthySince.IsZero() {
					healthySince = time.Now()
				} else if time.Since(healthySince) >= 5*time.Minute {
					paused = false
				}
			} else {
				healthySince = time.Time{}
			}
		}
		if !paused {
			workCtx, cancel := context.WithTimeout(ctx, 70*time.Second)
			job, found, err := s.claimReadModelJob(workCtx, []string{activityV3HourModel, activityV3DayModel}, worker)
			if err != nil {
				fmt.Fprintf(os.Stderr, "activity v3 coarse claim failed: %v\n", err)
			}
			if err == nil && found {
				err = s.materializeActivityV3Coarse(workCtx, job)
				if err != nil {
					fmt.Fprintf(os.Stderr, "activity v3 coarse materialize failed: %v\n", err)
				}
				_ = s.finishReadModelJob(context.WithoutCancel(workCtx), job, err)
			}
			cancel()
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *DBStore) ReadModelStatus(ctx context.Context) (map[string]any, error) {
	rows, err := s.pg.db.QueryContext(ctx, `SELECT name,state,updated_at FROM read_model_runtime_state ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := map[string]any{}
	for rows.Next() {
		var name string
		var state []byte
		var updatedAt time.Time
		if err = rows.Scan(&name, &state, &updatedAt); err != nil {
			return nil, err
		}
		var value map[string]any
		if err = json.Unmarshal(state, &value); err != nil {
			return nil, err
		}
		value["updated_at"] = updatedAt.UTC().Format(time.RFC3339Nano)
		states[name] = value
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	jobRows, err := s.pg.db.QueryContext(ctx, `SELECT model,count(*) FILTER(WHERE processed_generation<dirty_generation),
 COALESCE(EXTRACT(EPOCH FROM now()-(min(bucket_start) FILTER(WHERE processed_generation<dirty_generation))),0),
 count(*) FILTER(WHERE attempts>=10),max(updated_at) FROM read_model_jobs GROUP BY model`)
	if err != nil {
		return nil, err
	}
	defer jobRows.Close()
	jobs := map[string]any{}
	for jobRows.Next() {
		var model string
		var pending int64
		var lag float64
		var alerted int64
		var updated sql.NullTime
		if err = jobRows.Scan(&model, &pending, &lag, &alerted, &updated); err != nil {
			return nil, err
		}
		jobs[model] = map[string]any{"pending": pending, "oldest_lag_seconds": int64(lag), "failed_ten_times": alerted, "updated_at": updated.Time.UTC().Format(time.RFC3339Nano)}
	}
	var recognitionPending, recognitionFailures int64
	_ = s.pg.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE processed_generation<dirty_generation),count(*) FILTER(WHERE attempts>=10) FROM endpoint_recognition_jobs`).Scan(&recognitionPending, &recognitionFailures)
	routerState := map[string]any{"processed_events": int64(0)}
	var routerCursor, routerSuccess sql.NullTime
	var routerProcessed int64
	var routerError string
	if stateErr := s.pg.db.QueryRowContext(ctx, `SELECT cursor_timestamp,processed_events,last_success_at,last_error FROM router_recognition_state WHERE singleton`).Scan(&routerCursor, &routerProcessed, &routerSuccess, &routerError); stateErr == nil {
		routerState["processed_events"] = routerProcessed
		routerState["last_error"] = routerError
		if routerCursor.Valid {
			routerState["cursor_at"] = routerCursor.Time.UTC().Format(time.RFC3339Nano)
			routerState["lag_seconds"] = max(0, int64(time.Since(routerCursor.Time).Seconds()))
		}
		if routerSuccess.Valid {
			routerState["last_success_at"] = routerSuccess.Time.UTC().Format(time.RFC3339Nano)
		}
	}
	applicationState := map[string]any{}
	if applicationRows, applicationErr := s.pg.db.QueryContext(ctx, `SELECT lane,job,updated_at FROM application_processing_jobs ORDER BY lane`); applicationErr == nil {
		for applicationRows.Next() {
			var lane string
			var job []byte
			var updatedAt time.Time
			if applicationRows.Scan(&lane, &job, &updatedAt) == nil {
				var value map[string]any
				if json.Unmarshal(job, &value) == nil {
					value["updated_at"] = updatedAt.UTC().Format(time.RFC3339Nano)
					applicationState[lane] = value
				}
			}
		}
		applicationRows.Close()
	}
	return map[string]any{
		"states":                    states,
		"jobs":                      jobs,
		"recognition":               map[string]any{"pending": recognitionPending, "failed_ten_times": recognitionFailures},
		"router_recognition":        routerState,
		"application_processing":    applicationState,
		"event_id_index_cutover":    strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_ID_INDEX_CUTOVER")),
		"event_id_index_v2_cutover": strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_ID_INDEX_V2_CUTOVER")),
	}, nil
}
