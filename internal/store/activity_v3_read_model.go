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
	// activityBucketFinalizeDelay is how long a closed five-minute bucket waits for
	// late receipts before it is published. An open bucket is not written at all:
	// readers only use the newest published revision, so every rebuild before close
	// appended a full copy that the next rebuild immediately superseded.
	activityBucketFinalizeDelay = 90 * time.Second

	// activityCoarseMaxRealtimeLag pauses the hourly and daily rollups while the
	// five-minute lane is behind. activityCoarseClaimInterval spaces successful
	// coarse claims so a long catch-up cannot monopolise the write path.
	activityCoarseMaxRealtimeLag = 90 * time.Second
	activityCoarseClaimInterval  = 30 * time.Second

	// activityFiveMinuteStructuralLag is the coverage lag that close-gated
	// publication always has: the newest published bucket ends at the previous
	// close gate, so as_of trails wall clock by one bucket width plus the finalize
	// delay even when the lane is completely caught up. The coarse gate compares
	// the excess over this window, otherwise it would never open.
	activityFiveMinuteStructuralLag = 5*time.Minute + activityBucketFinalizeDelay

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
	return s.readActivityV3Cutover(ctx)
}

// GET requests only read worker-owned state. Initialization belongs to workers
// and must never turn a statistics read into an INSERT or wait on a writer.
func (s *DBStore) readActivityV3Cutover(ctx context.Context) (time.Time, error) {
	var raw string
	if err := s.pg.db.QueryRowContext(ctx, `SELECT state->>'cutover' FROM read_model_runtime_state WHERE name=$1`, activityV3CutoverState).Scan(&raw); err != nil {
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
	if _, err = s.repairActivityV3Finalization(ctx); err != nil {
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
	// The published revision carries the instant its build began reading, so a receipt that is
	// comfortably older than that is already included: rebuilding would append an identical
	// copy under a new revision, and the read path only ever reads the published one. The five
	// second margin covers the gap between a source row becoming visible and the receipt that
	// timestamps it.
	data, err := s.ch.query(ctx, `SELECT concat(replaceOne(toString(d.written_at),' ','T'),'Z') written_at,formatDateTime(d.window_start,'%Y-%m-%dT%H:%i:%SZ','UTC') window_start,d.sensor_id sensor_id,d.campus_id campus_id,toUInt8(v.source_as_of IS NOT NULL AND v.source_as_of>=d.written_at+INTERVAL 5 SECOND) covered FROM(SELECT max(l.written_at) written_at,l.window_start window_start,l.sensor_id sensor_id,l.campus_id campus_id FROM activity_chart_dirty_log l WHERE `+where+` GROUP BY l.window_start,l.sensor_id,l.campus_id) d LEFT JOIN (SELECT bucket_start,sensor_id,campus_id,argMax(source_as_of,published_at) source_as_of FROM activity_chart_bucket_versions_v3 WHERE granularity='5m' GROUP BY bucket_start,sensor_id,campus_id) v ON v.bucket_start=d.window_start AND v.sensor_id=d.sensor_id AND v.campus_id=d.campus_id ORDER BY d.written_at,d.window_start,d.sensor_id,d.campus_id LIMIT 10000 SETTINGS max_threads=1,max_memory_usage=268435456,max_bytes_before_external_group_by=67108864 FORMAT JSONEachRow`)
	if err != nil {
		return 0, err
	}
	rows := []activityChartCursor{}
	if err = decodeJSONEachRow(data, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		// A "checked, nothing to do" heartbeat: this statement's only effect is its timestamp,
		// which is exactly the shape that carries no information. It runs on every dispatch
		// cycle, and each autocommit pays a WAL fsync (~230 ms on the field). Keep the liveness
		// marker fresh to within ten seconds instead of touching it every cycle.
		_, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET updated_at=now() WHERE name=$1 AND updated_at < now() - interval '10 seconds'`, activityV3DispatchState)
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
		if row.Covered == 1 {
			// Already published: skip the rebuild but keep walking, because the cursor below is
			// taken from the last row of this result set and must still advance past it.
			continue
		}
		if err = enqueueActivityV3FiveMinuteJob(ctx, tx, bucket, time.Now().UTC(), row.SensorID, row.CampusID); err != nil {
			return 0, err
		}
	}
	last, _ := json.Marshal(rows[len(rows)-1])
	if _, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=$2,updated_at=now() WHERE name=$1`, activityV3DispatchState, last); err != nil {
		return 0, err
	}
	return len(seen), tx.Commit()
}

type activityJobWriter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func enqueueActivityV3FiveMinuteJob(ctx context.Context, db activityJobWriter, bucket, now time.Time, sensor, campus string) error {
	// Start one settle window per dirty job. Repeated late receipts fold into
	// that job without postponing its claim or overriding a retry backoff.
	// A receipt during a leased build leaves a further generation to publish.
	_, err := db.ExecContext(ctx, `INSERT INTO read_model_jobs(model,bucket_start,sensor_id,campus_id,not_before)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(model,bucket_start,sensor_id,campus_id) DO UPDATE SET
dirty_generation=read_model_jobs.dirty_generation+1,
not_before=CASE WHEN read_model_jobs.status='running' THEN read_model_jobs.not_before
 ELSE GREATEST(read_model_jobs.not_before,EXCLUDED.not_before) END,
status=CASE WHEN read_model_jobs.status='running' THEN 'running' ELSE 'pending' END,updated_at=now()
WHERE read_model_jobs.processed_generation=read_model_jobs.dirty_generation
   OR read_model_jobs.status='running'`,
		activityV3FiveMinuteModel, bucket, sensor, campus, activityFiveMinuteSchedule(bucket, now))
	return err
}

// claimReadModelJob takes the most recent five-minute bucket first, and the most
// recent hour/day bucket first, so fresh chart data appears before the backlog
// fills in. Hourly catch-up spends up to a couple of minutes per legacy bucket,
// so newest-first is what makes 24h and 7d readable while history is rebuilt.
func (s *DBStore) claimReadModelJob(ctx context.Context, models []string, worker string) (readModelJob, bool, error) {
	row := s.pg.db.QueryRowContext(ctx, `WITH picked AS (
 SELECT model,bucket_start,sensor_id,campus_id FROM read_model_jobs
 WHERE model=ANY($1::text[]) AND processed_generation<dirty_generation AND not_before<=now()
 AND (status<>'running' OR lease_until<now())
 ORDER BY CASE model WHEN 'activity-5m-v3' THEN 0 WHEN 'activity-hour-v3' THEN 1 ELSE 2 END,
 CASE WHEN model='activity-5m-v3' THEN bucket_start END DESC,
 CASE WHEN model<>'activity-5m-v3' THEN bucket_start END DESC
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

// activityFiveMinuteCloseAt is the instant a five-minute bucket stops taking new
// receipts. A single finalize delay covers the publish itself and the settle
// window used for late data.
func activityFiveMinuteCloseAt(bucket time.Time) time.Time {
	return bucket.UTC().Add(5*time.Minute + activityBucketFinalizeDelay)
}

// activityFiveMinuteOpen reports whether the bucket is still open at now.
func activityFiveMinuteOpen(bucket, now time.Time) bool {
	return now.Before(activityFiveMinuteCloseAt(bucket))
}

// activityFiveMinuteSchedule schedules the first claim at the close gate, or
// gives a newly dirtied closed bucket time to collect more late receipts.
func activityFiveMinuteSchedule(bucket, now time.Time) time.Time {
	closeAt := activityFiveMinuteCloseAt(bucket)
	if now.Before(closeAt) {
		return closeAt
	}
	return now.Add(activityBucketFinalizeDelay)
}

// activityCoarseEffectiveLag removes the structural coverage window from the
// reported realtime lag so the gate measures real backlog only.
func activityCoarseEffectiveLag(lagSeconds float64) float64 {
	structural := activityFiveMinuteStructuralLag.Seconds()
	if lagSeconds <= structural {
		return 0
	}
	return lagSeconds - structural
}

// activityCoarseGate decides whether the hourly and daily lanes may claim a job.
// sinceSuccess is negative when no job has succeeded yet. The previous gate also
// required the lag to stay below a lower threshold for five minutes, which the
// five-minute lane can never satisfy because its watermark moves in multi-minute
// steps; the hourly rollups therefore never ran. See docs/current-work.md.
func activityCoarseGate(lagSeconds float64, lagErr error, sinceSuccess time.Duration) (bool, string) {
	switch {
	case lagErr != nil:
		return true, "realtime checkpoint unavailable: " + lagErr.Error()
	case lagSeconds > activityCoarseMaxRealtimeLag.Seconds():
		return true, "realtime lag above limit"
	case sinceSuccess >= 0 && sinceSuccess < activityCoarseClaimInterval:
		return true, "claim rate limited"
	}
	return false, ""
}

// activityCoarseSourceExpired reports whether a rollup job reads a source table
// that no longer holds the bucket. Only the hourly model depends on the retained
// five-minute facts; the day model reads the hour table and the five-minute model
// reads normalized events.
func activityCoarseSourceExpired(model string, bucketStart, fiveMinuteFloor time.Time) bool {
	if model != activityV3HourModel || fiveMinuteFloor.IsZero() {
		return false
	}
	return bucketStart.UTC().Before(fiveMinuteFloor.UTC())
}

// activityFiveMinuteFloor returns the oldest partition still stored for the
// five-minute facts. Partition level is enough: TTL drops whole parts and the
// oldest partition is the only one that can straddle the retention boundary.
// An empty table reports the zero time so the caller keeps the job queued.
func (s *DBStore) activityFiveMinuteFloor(ctx context.Context) (time.Time, error) {
	raw, err := s.ch.query(ctx, `SELECT toString(min(partition)) AS floor_partition FROM system.parts WHERE active AND database=currentDatabase() AND table='activity_chart_facts_5m_v3' FORMAT JSONEachRow`)
	if err != nil {
		return time.Time{}, err
	}
	rows := []struct {
		Partition string `json:"floor_partition"`
	}{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return time.Time{}, err
	}
	if len(rows) != 1 || rows[0].Partition == "" {
		return time.Time{}, nil
	}
	floor, err := time.Parse("2006-01-02", rows[0].Partition)
	if err != nil {
		return time.Time{}, err
	}
	return floor, nil
}

// cancelActivityV3Job records an unbuildable bucket without publishing a revision.
// The generation is consumed so the job leaves the queue, and the reason stays on
// the row: a cancelled bucket is a known gap, never a completed rollup.
func (s *DBStore) cancelActivityV3Job(ctx context.Context, job readModelJob, reason string) error {
	_, err := s.pg.db.ExecContext(ctx, `UPDATE read_model_jobs SET status='cancelled',processed_generation=dirty_generation,last_error=$5,attempts=0,lease_owner='',lease_until='-infinity',updated_at=now()
WHERE model=$1 AND bucket_start=$2 AND sensor_id=$3 AND campus_id=$4`, job.Model, job.BucketStart, job.SensorID, job.CampusID, reason)
	return err
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

// publishActivityV3Version records which revision readers should use. sourceAsOf is the
// moment the build began reading its source: every receipt written before it is necessarily
// part of this revision, which is what lets the dispatch skip rebuilds that would only append
// an identical copy. It used to be the publish time, which is later than the read and
// therefore cannot prove coverage.
func (s *DBStore) publishActivityV3Version(ctx context.Context, granularity string, bucket time.Time, sensorID, campusID string, revision uint64, sourceAsOf time.Time, finalized bool) error {
	final := 0
	if finalized {
		final = 1
	}
	query := fmt.Sprintf(`INSERT INTO activity_chart_bucket_versions_v3(granularity,bucket_start,sensor_id,campus_id,revision,source_as_of,published_at,finalized) VALUES(%s,parseDateTimeBestEffort(%s),%s,%s,toUInt64(%d),parseDateTime64BestEffort(%s,9),now64(9),toUInt8(%d))`, chQuote(granularity), chQuote(bucket.UTC().Format(time.RFC3339Nano)), chQuote(sensorID), chQuote(campusID), revision, chQuote(sourceAsOf.UTC().Format(time.RFC3339Nano)), final)
	return s.ch.exec(ctx, query)
}

func (s *DBStore) materializeActivityV3FiveMinute(ctx context.Context, job readModelJob) error {
	return s.materializeActivityV3FiveMinuteAt(ctx, job, time.Now().UTC())
}

type activityV3FiveMinuteDelta struct {
	Changed   uint64 `json:"changed"`
	Revision  uint64 `json:"revision"`
	Finalized uint8  `json:"stored_finalized"`
	Revisions uint64 `json:"revisions"`
}

// activityV3FiveMinuteDeltaSQL compares the bucket that would be published with
// the revision readers already use. Equality is dimension, value, and count.
func activityV3FiveMinuteDeltaSQL(bucket time.Time, sensorID, campusID, sourceWhere string) string {
	bucketSQL := chQuote(bucket.UTC().Format(time.RFC3339Nano))
	scope := activityV3Scope(sensorID, campusID)
	versionScope := "granularity='5m' AND bucket_start=parseDateTimeBestEffort(" + bucketSQL + ") AND " + scope
	return `WITH next AS (
 SELECT t.1 AS dimension, t.2 AS value, count() AS event_count
 FROM (SELECT arrayJoin(` + activityChartArray + `) AS t FROM normalized_event_features WHERE ` + sourceWhere + `)
 GROUP BY dimension, value
), current AS (
 SELECT dimension, value, event_count FROM activity_chart_facts_5m_v3
 WHERE bucket_start=parseDateTimeBestEffort(` + bucketSQL + `) AND ` + scope + `
  AND revision=(SELECT argMax(revision, published_at) FROM activity_chart_bucket_versions_v3 WHERE ` + versionScope + `)
)
SELECT (SELECT count() FROM (
 SELECT * FROM next EXCEPT SELECT * FROM current
 UNION ALL
 SELECT * FROM current EXCEPT SELECT * FROM next
)) AS changed,
(SELECT argMax(revision, published_at) FROM activity_chart_bucket_versions_v3 WHERE ` + versionScope + `) AS revision,
(SELECT argMax(finalized, published_at) FROM activity_chart_bucket_versions_v3 WHERE ` + versionScope + `) AS stored_finalized,
(SELECT count() FROM activity_chart_bucket_versions_v3 WHERE ` + versionScope + `) AS revisions
FORMAT JSONEachRow SETTINGS max_threads=4,max_memory_usage=536870912,max_bytes_before_external_group_by=134217728,max_execution_time=30`
}

func (s *DBStore) materializeActivityV3FiveMinuteAt(ctx context.Context, job readModelJob, now time.Time) error {
	from, to := job.BucketStart.UTC(), job.BucketStart.UTC().Add(5*time.Minute)
	if activityFiveMinuteOpen(job.BucketStart, now) {
		// Defer the whole build to the close gate: nothing is inserted, no revision
		// is allocated and no version is published. The claimed generation must stay
		// behind, because finishReadModelJob advances processed_generation to the
		// claimed value on a nil error and would otherwise mark the bucket completed
		// without ever writing its facts.
		if _, err := s.pg.db.ExecContext(ctx, `UPDATE read_model_jobs SET dirty_generation=GREATEST(dirty_generation,$5+1),not_before=GREATEST(not_before,$6),updated_at=now()
WHERE model=$1 AND bucket_start=$2 AND sensor_id=$3 AND campus_id=$4`, job.Model, job.BucketStart, job.SensorID, job.CampusID, job.DirtyGeneration, activityFiveMinuteCloseAt(job.BucketStart)); err != nil {
			return err
		}
		return s.updateActivityV3State(ctx, "5m", now)
	}
	sourceFrom := from
	cutover, err := s.ensureActivityV3Cutover(ctx)
	if err != nil {
		return err
	}
	if sourceFrom.Before(cutover) {
		sourceFrom = cutover
	}
	sourceWhere := "timestamp>=parseDateTime64BestEffort(" + chQuote(sourceFrom.Format(time.RFC3339Nano)) + ",6) AND timestamp<parseDateTime64BestEffort(" + chQuote(to.Format(time.RFC3339Nano)) + ",6) AND " + activityV3Scope(job.SensorID, job.CampusID)
	raw, err := s.ch.query(ctx, activityV3FiveMinuteDeltaSQL(from, job.SensorID, job.CampusID, sourceWhere))
	if err != nil {
		return err
	}
	delta := []activityV3FiveMinuteDelta{}
	if err = decodeJSONEachRow(raw, &delta); err != nil {
		return err
	}
	if len(delta) != 1 {
		return fmt.Errorf("activity 5m delta returned %d rows", len(delta))
	}
	finalized := !now.Before(to.Add(90 * time.Second))
	if delta[0].Changed == 0 && delta[0].Revisions > 0 {
		if !finalized {
			_, err = s.pg.db.ExecContext(ctx, `UPDATE read_model_jobs SET dirty_generation=GREATEST(dirty_generation,$5+1),not_before=GREATEST(not_before,$6),updated_at=now()
WHERE model=$1 AND bucket_start=$2 AND sensor_id=$3 AND campus_id=$4`, job.Model, job.BucketStart, job.SensorID, job.CampusID, job.DirtyGeneration, to.Add(90*time.Second))
			if err != nil {
				return err
			}
		} else if delta[0].Finalized == 0 {
			if err = s.publishActivityV3Version(ctx, "5m", from, job.SensorID, job.CampusID, delta[0].Revision, time.Now().UTC(), true); err != nil {
				return err
			}
			if err = s.enqueueActivityV3HourParent(ctx, from, job, now); err != nil {
				return err
			}
		}
		asOf := to
		if asOf.After(now) {
			asOf = now
		}
		return s.updateActivityV3State(ctx, "5m", asOf)
	}
	revision, err := s.nextReadModelRevision(ctx)
	if err != nil {
		return err
	}
	// The read starts here: any receipt written before this instant is in the source table and
	// therefore in the revision this build publishes.
	sourceAsOf := time.Now().UTC()
	query := fmt.Sprintf(`INSERT INTO activity_chart_facts_5m_v3 SELECT toStartOfFiveMinutes(timestamp) bucket_start,sensor_id,campus_id,toUInt64(%d) revision,t.1 dimension,t.2 value,count() event_count,min(timestamp) first_seen,max(timestamp) last_seen FROM(SELECT timestamp,sensor_id,campus_id,arrayJoin(%s) t FROM normalized_event_features WHERE %s) GROUP BY bucket_start,sensor_id,campus_id,dimension,value SETTINGS max_threads=4,max_memory_usage=536870912,max_bytes_before_external_group_by=134217728,max_execution_time=15`, revision, activityChartArray, sourceWhere)
	if err = s.ch.exec(ctx, query); err != nil {
		return err
	}
	if err = s.publishActivityV3Version(ctx, "5m", from, job.SensorID, job.CampusID, revision, sourceAsOf, finalized); err != nil {
		return err
	}
	if !finalized {
		// A quiet bucket receives no more dirty receipts. Keep one pending
		// generation so the final publication and parent job cannot be skipped.
		_, err = s.pg.db.ExecContext(ctx, `UPDATE read_model_jobs SET dirty_generation=GREATEST(dirty_generation,$5+1),not_before=GREATEST(not_before,$6),updated_at=now()
WHERE model=$1 AND bucket_start=$2 AND sensor_id=$3 AND campus_id=$4`, job.Model, job.BucketStart, job.SensorID, job.CampusID, job.DirtyGeneration, to.Add(90*time.Second))
		if err != nil {
			return err
		}
	} else if err = s.enqueueActivityV3HourParent(ctx, from, job, now); err != nil {
		return err
	}
	asOf := to
	if asOf.After(now) {
		asOf = now
	}
	return s.updateActivityV3State(ctx, "5m", asOf)
}

// Finalize legacy completed children once, including partially published
// children whose hour already has a parent from another child. This is a
// one-time bounded PostgreSQL queue operation; the realtime worker still owns
// all ClickHouse publication, leases, retries, and live-first priority.
func (s *DBStore) repairActivityV3Finalization(ctx context.Context) (int, error) {
	const name = "activity-v3-finalization-repair-v1"
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state) VALUES($1,'{}') ON CONFLICT(name) DO NOTHING`, name); err != nil {
		return 0, err
	}
	var done bool
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((state->>'complete')::boolean,false) FROM read_model_runtime_state WHERE name=$1 FOR UPDATE`, name).Scan(&done); err != nil {
		return 0, err
	}
	if done {
		return 0, tx.Commit()
	}
	var count int
	if err = tx.QueryRowContext(ctx, `WITH picked AS (
 SELECT j.model,j.bucket_start,j.sensor_id,j.campus_id FROM read_model_jobs j
 WHERE j.model=$1 AND j.status='completed' AND j.processed_generation>=j.dirty_generation
 AND j.bucket_start+interval '6 minutes 30 seconds'<=now()
 ORDER BY j.bucket_start,j.sensor_id,j.campus_id FOR UPDATE OF j LIMIT 100
), repaired AS (
 UPDATE read_model_jobs j SET dirty_generation=j.processed_generation+1,status='pending',not_before=LEAST(j.not_before,now()),updated_at=now()
 FROM picked p WHERE j.model=p.model AND j.bucket_start=p.bucket_start AND j.sensor_id=p.sensor_id AND j.campus_id=p.campus_id RETURNING j.model
) SELECT count(*) FROM repaired`, activityV3FiveMinuteModel).Scan(&count); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=jsonb_build_object('complete',$2::boolean,'queued',COALESCE((state->>'queued')::int,0)+$3::int),updated_at=now() WHERE name=$1`, name, count < 100, count); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (s *DBStore) enqueueActivityV3HourParent(ctx context.Context, from time.Time, job readModelJob, now time.Time) error {
	hour := from.Truncate(time.Hour)
	// Late and replayed receipts can finalize several child buckets for the
	// same hour in quick succession. Push the parent job out after every
	// child publication so the hour is rebuilt once after the stream is
	// quiet, rather than once per child generation.
	notBefore := activityParentNotBefore(hour.Add(time.Hour+5*time.Minute), now, 90*time.Second)
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO read_model_jobs(model,bucket_start,sensor_id,campus_id,not_before)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(model,bucket_start,sensor_id,campus_id) DO UPDATE SET
dirty_generation=CASE
 WHEN read_model_jobs.status='running' THEN GREATEST(read_model_jobs.dirty_generation,read_model_jobs.processed_generation+2)
 WHEN read_model_jobs.processed_generation<read_model_jobs.dirty_generation THEN read_model_jobs.dirty_generation
 ELSE read_model_jobs.dirty_generation+1 END,
status=CASE WHEN read_model_jobs.status='running' THEN 'running' ELSE 'pending' END,
not_before=GREATEST(read_model_jobs.not_before,EXCLUDED.not_before),updated_at=now()`, activityV3HourModel, hour, job.SensorID, job.CampusID, notBefore)
	return err
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
	sourceAsOf := time.Now().UTC()
	if err = s.ch.exec(ctx, query); err != nil {
		return err
	}
	if err = s.publishActivityV3Version(ctx, granularity, from, job.SensorID, job.CampusID, revision, sourceAsOf, true); err != nil {
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
	query := fmt.Sprintf(`INSERT INTO %s SELECT %s(f.bucket_start) bucket_start,f.sensor_id,f.campus_id,toUInt64(%d) revision,f.dimension,f.value,sum(f.event_count),min(f.first_seen),max(f.last_seen) FROM %s f PREWHERE f.bucket_start>=parseDateTimeBestEffort(%s) AND f.bucket_start<parseDateTimeBestEffort(%s) AND %s WHERE (f.bucket_start,f.sensor_id,f.campus_id,f.revision) IN(SELECT bucket_start,sensor_id,campus_id,argMax(revision,published_at) revision FROM activity_chart_bucket_versions_v3 WHERE granularity=%s AND bucket_start>=parseDateTimeBestEffort(%s) AND bucket_start<parseDateTimeBestEffort(%s) AND %s GROUP BY bucket_start,sensor_id,campus_id) GROUP BY bucket_start,sensor_id,campus_id,dimension,value SETTINGS max_threads=4,max_memory_usage=1073741824,max_bytes_before_external_group_by=268435456,max_execution_time=150`, targetTable, truncate, revision, sourceTable, fromSQL, toSQL, activityV3AliasedScope("f", job.SensorID, job.CampusID), chQuote(childGranularity), fromSQL, toSQL, activityV3Scope(job.SensorID, job.CampusID))
	return query, granularity, from, nil
}

// recordActivityV3CoarseState publishes why the hourly/daily lane is idle. It is
// written on transitions only, so a paused lane is visible in PostgreSQL without
// adding a periodic write.
func (s *DBStore) recordActivityV3CoarseState(ctx context.Context, reason string, lagSeconds float64, materialized bool, lastSuccess time.Time) error {
	state := map[string]any{"reason": reason, "lag_seconds": int(lagSeconds), "paused": reason != ""}
	if materialized {
		state["last_success_at"] = lastSuccess.UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES($1,$2,now())
ON CONFLICT (name) DO UPDATE SET state=read_model_runtime_state.state||EXCLUDED.state,updated_at=EXCLUDED.updated_at`, "activity-v3-coarse", raw)
	return err
}

func (s *DBStore) updateActivityV3State(ctx context.Context, granularity string, asOf time.Time) error {
	name := "activity-v3-" + granularity
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at)
VALUES($1,jsonb_build_object('as_of',$2::text),now()) ON CONFLICT(name) DO UPDATE SET
state=jsonb_build_object('as_of',GREATEST(
 COALESCE((read_model_runtime_state.state->>'as_of')::timestamptz,'-infinity'::timestamptz),
 $2::timestamptz)),updated_at=now()
-- The watermark is monotonic (GREATEST keeps the maximum), so suppressing intermediate writes
-- loses nothing: the next write past the throttle carries the newer value. Without this the
-- lane rewrote the row every few seconds even when only the timestamp moved.
WHERE read_model_runtime_state.updated_at < now() - interval '10 seconds'`, name, asOf.UTC().Format(time.RFC3339Nano))
	return err
}

// A successful loop proves that receipt dispatch and the ready job queue were
// checked even if no packet arrived. This checkpoint never advances event as_of.
func (s *DBStore) recordActivityV3RealtimeHealth(ctx context.Context, runErr error, at time.Time) error {
	state := map[string]any{"status": "ready", "last_error": ""}
	if runErr != nil {
		state["status"] = "failed"
		state["last_error"] = runErr.Error()
	} else {
		state["last_success_at"] = at.UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('activity-v3-realtime-health',$1,$2) ON CONFLICT(name) DO UPDATE SET state=read_model_runtime_state.state||EXCLUDED.state,updated_at=EXCLUDED.updated_at`, raw, at)
	return err
}

func (s *DBStore) RunActivityV3Realtime(ctx context.Context) {
	worker := fmt.Sprintf("realtime-%d", os.Getpid())
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, dispatchErr := s.dispatchActivityV3Jobs(workCtx)
		if dispatchErr != nil {
			fmt.Fprintf(os.Stderr, "activity v3 dispatch failed: %v\n", dispatchErr)
		}
		job, found, claimErr := s.claimReadModelJob(workCtx, []string{activityV3FiveMinuteModel}, worker)
		if claimErr != nil {
			fmt.Fprintf(os.Stderr, "activity v3 realtime claim failed: %v\n", claimErr)
		}
		runErr := dispatchErr
		if runErr == nil {
			runErr = claimErr
		}
		if claimErr == nil && found {
			materializeErr := s.materializeActivityV3FiveMinute(workCtx, job)
			if materializeErr != nil {
				fmt.Fprintf(os.Stderr, "activity v3 realtime materialize failed: %v\n", materializeErr)
			}
			finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(workCtx), 5*time.Second)
			finishErr := s.finishReadModelJob(finishCtx, job, materializeErr)
			finishCancel()
			if finishErr != nil {
				fmt.Fprintf(os.Stderr, "activity v3 realtime finish failed: %v\n", finishErr)
			}
			if runErr == nil {
				runErr = materializeErr
			}
			if runErr == nil {
				runErr = finishErr
			}
		}
		cancel()
		if ctx.Err() == nil {
			healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
			if err := s.recordActivityV3RealtimeHealth(healthCtx, runErr, time.Now().UTC()); err != nil {
				fmt.Fprintf(os.Stderr, "activity v3 realtime checkpoint failed: %v\n", err)
			}
			healthCancel()
		}
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

// Fresh source data keeps the existing lag thresholds. A verified quiet worker
// may process coarser windows only while there is no actionable five-minute
// backlog. Missing heartbeat state falls back to the pre-upgrade lag guard.
func (s *DBStore) activityV3RealtimeLag(ctx context.Context, now time.Time) (float64, error) {
	var lag float64
	var heartbeat sql.NullTime
	var status, lastError, asOfRaw, dispatchWindow string
	var backlog bool
	err := s.pg.db.QueryRowContext(ctx, `SELECT EXTRACT(EPOCH FROM $1::timestamptz-(live.state->>'as_of')::timestamptz),health.updated_at,COALESCE(health.state->>'status',''),COALESCE(health.state->>'last_error',''),
 EXISTS(SELECT 1 FROM read_model_jobs j WHERE j.model='activity-5m-v3' AND j.processed_generation<j.dirty_generation
 AND (j.not_before<=$1::timestamptz OR j.attempts>0 OR j.bucket_start+interval '6 minutes 30 seconds'<=$1::timestamptz)),
 COALESCE(live.state->>'as_of',''),COALESCE(dispatch.state->>'window_start','')
 FROM read_model_runtime_state live
 LEFT JOIN read_model_runtime_state health ON health.name='activity-v3-realtime-health'
 LEFT JOIN read_model_runtime_state dispatch ON dispatch.name='activity-v3-dispatch'
 WHERE live.name='activity-v3-5m'`, now).Scan(&lag, &heartbeat, &status, &lastError, &backlog, &asOfRaw, &dispatchWindow)
	if err != nil {
		return 0, err
	}
	if heartbeat.Valid {
		age := now.Sub(heartbeat.Time)
		if age > 30*time.Second || age < -time.Second {
			return lag, fmt.Errorf("activity v3 realtime checkpoint is not current")
		}
		if status != "ready" || lastError != "" {
			return lag, fmt.Errorf("activity v3 realtime checkpoint failed: %s", lastError)
		}
		if !backlog {
			return 0, nil
		}
		// A pending rebuild of a bucket that the published coverage already
		// includes is late-data cleanup, not a wall-clock backlog. The input
		// itself can be quiet while a historical bucket is rebuilt.
		if asOf, asErr := parseReadModelTime(asOfRaw); asErr == nil {
			if window, wErr := parseReadModelTime(dispatchWindow); wErr == nil && !asOf.Before(window.Add(5*time.Minute)) {
				return 0, nil
			}
		}
	}
	return max(0, lag), nil
}

func (s *DBStore) RunActivityV3Coarse(ctx context.Context) {
	worker := fmt.Sprintf("coarse-%d", os.Getpid())
	lastSuccess := time.Time{}
	lastReason := ""
	for ctx.Err() == nil {
		// Realtime lag pauses all coarse work without consuming a job lease. The
		// five-minute lane advances its watermark in multi-minute steps, so the old
		// dwell requirement could never be met and the rollups never ran.
		now := time.Now().UTC()
		lagSeconds, lagErr := s.activityV3RealtimeLag(ctx, now)
		effectiveLag := activityCoarseEffectiveLag(lagSeconds)
		sinceSuccess := time.Duration(-1)
		if !lastSuccess.IsZero() {
			sinceSuccess = now.Sub(lastSuccess)
		}
		paused, reason := activityCoarseGate(effectiveLag, lagErr, sinceSuccess)
		if paused {
			if reason != lastReason {
				lastReason = reason
				fmt.Fprintf(os.Stderr, "activity v3 coarse paused: %s (realtime lag %.0fs, %.0fs over the coverage window)\n", reason, lagSeconds, effectiveLag)
				_ = s.recordActivityV3CoarseState(ctx, reason, effectiveLag, false, time.Time{})
			}
		} else {
			lastReason = ""
			workCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
			job, found, err := s.claimReadModelJob(workCtx, []string{activityV3HourModel, activityV3DayModel}, worker)
			if err != nil {
				fmt.Fprintf(os.Stderr, "activity v3 coarse claim failed: %v\n", err)
			}
			if err == nil && found {
				if expired, floorErr := s.activityFiveMinuteFloor(workCtx); floorErr == nil && activityCoarseSourceExpired(job.Model, job.BucketStart, expired) {
					reason := fmt.Sprintf("five-minute facts for this hour expired before catch-up (retained from %s)", expired.UTC().Format(time.RFC3339))
					fmt.Fprintf(os.Stderr, "activity v3 coarse cancelled %s/%s %s: %s\n", job.Model, job.SensorID, job.BucketStart.UTC().Format(time.RFC3339), reason)
					_ = s.cancelActivityV3Job(context.WithoutCancel(workCtx), job, reason)
					cancel()
					continue
				}
				err = s.materializeActivityV3Coarse(workCtx, job)
				if err != nil {
					fmt.Fprintf(os.Stderr, "activity v3 coarse materialize failed: %v\n", err)
				} else {
					lastSuccess = time.Now().UTC()
				}
				_ = s.finishReadModelJob(context.WithoutCancel(workCtx), job, err)
				_ = s.recordActivityV3CoarseState(ctx, "", effectiveLag, err == nil, lastSuccess)
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
	return map[string]any{
		"states":                    states,
		"jobs":                      jobs,
		"recognition":               map[string]any{"pending": recognitionPending, "failed_ten_times": recognitionFailures},
		"router_recognition":        routerState,
		"event_id_index_cutover":    strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_ID_INDEX_CUTOVER")),
		"event_id_index_v2_cutover": strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_ID_INDEX_V2_CUTOVER")),
	}, nil
}
