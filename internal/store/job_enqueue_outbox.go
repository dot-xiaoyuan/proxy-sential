package store

import (
	"context"
	"fmt"
	"os"
	"time"
)

// The trigger functions only append to these logs; one dispatcher per job table
// folds the log into the shared job rows in a single ordered statement. That
// keeps every writer's transaction free of shared-row locks while the job rows
// still receive the same dirty generations.
const (
	dirtyLogFlushBatch     = 500
	dirtyLogFlushInterval  = 500 * time.Millisecond
	dirtyLogCleanupPeriod  = 10 * time.Minute
	dirtyLogFlushTimeout   = 10 * time.Second
	dirtyLogCleanupTimeout = 30 * time.Second
)

func (s *DBStore) flushRecognitionDirtyLog(ctx context.Context) (int64, error) {
	var consumed, updated int64
	err := s.pg.db.QueryRowContext(ctx, `
WITH batch AS (
 SELECT id FROM endpoint_recognition_dirty_log ORDER BY id LIMIT $1
), last AS (
 SELECT max(id) AS max_id FROM batch
), agg AS (
 SELECT DISTINCT ON (endpoint_id) endpoint_id
 FROM endpoint_recognition_dirty_log
 WHERE id<=(SELECT max_id FROM last)
 ORDER BY endpoint_id,id DESC
), del AS (
 DELETE FROM endpoint_recognition_dirty_log WHERE id<=(SELECT max_id FROM last) RETURNING id
), ins AS (
 INSERT INTO endpoint_recognition_jobs(endpoint_id)
 SELECT endpoint_id FROM agg ORDER BY endpoint_id
 ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  lane=0,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=CASE WHEN endpoint_recognition_jobs.processed_generation<endpoint_recognition_jobs.dirty_generation THEN endpoint_recognition_jobs.updated_at ELSE now() END
 WHERE endpoint_recognition_jobs.processed_generation>=endpoint_recognition_jobs.dirty_generation
    OR endpoint_recognition_jobs.lease_until>clock_timestamp() OR endpoint_recognition_jobs.lane=1
 RETURNING 1
)
SELECT (SELECT count(*) FROM agg),(SELECT count(*) FROM ins)`, dirtyLogFlushBatch).Scan(&consumed, &updated)
	return consumed, err
}

func (s *DBStore) flushSharedProfileDirtyLog(ctx context.Context) (int64, error) {
	var consumed, updated int64
	err := s.pg.db.QueryRowContext(ctx, `
WITH batch AS (
 SELECT id FROM shared_device_profile_dirty_log ORDER BY id LIMIT $1
), last AS (
 SELECT max(id) AS max_id FROM batch
), agg AS (
 SELECT DISTINCT ON (subject_key) subject_key,sensor_id,campus_id,endpoint_id,mac,ip,vlan,observed_at
 FROM shared_device_profile_dirty_log
 WHERE id<=(SELECT max_id FROM last)
 ORDER BY subject_key,id DESC
), del AS (
 DELETE FROM shared_device_profile_dirty_log WHERE id<=(SELECT max_id FROM last) RETURNING id
), ins AS (
 INSERT INTO shared_device_profile_jobs(subject_key,sensor_id,campus_id,endpoint_id,mac,ip,vlan,observed_at)
 SELECT subject_key,sensor_id,campus_id,endpoint_id,mac,ip,vlan,observed_at FROM agg ORDER BY subject_key
 ON CONFLICT(subject_key) DO UPDATE SET
  sensor_id=CASE WHEN EXCLUDED.sensor_id<>'' THEN EXCLUDED.sensor_id ELSE shared_device_profile_jobs.sensor_id END,
  campus_id=CASE WHEN EXCLUDED.campus_id<>'' THEN EXCLUDED.campus_id ELSE shared_device_profile_jobs.campus_id END,
  endpoint_id=CASE WHEN EXCLUDED.endpoint_id<>'' THEN EXCLUDED.endpoint_id ELSE shared_device_profile_jobs.endpoint_id END,
  mac=CASE WHEN EXCLUDED.mac<>'' THEN EXCLUDED.mac ELSE shared_device_profile_jobs.mac END,
  ip=coalesce(EXCLUDED.ip,shared_device_profile_jobs.ip),
  vlan=CASE WHEN EXCLUDED.vlan<>'' THEN EXCLUDED.vlan ELSE shared_device_profile_jobs.vlan END,
  observed_at=greatest(shared_device_profile_jobs.observed_at,EXCLUDED.observed_at),
  dirty_since=CASE WHEN shared_device_profile_jobs.processed_generation>=shared_device_profile_jobs.dirty_generation THEN now() ELSE shared_device_profile_jobs.dirty_since END,
  dirty_generation=shared_device_profile_jobs.dirty_generation+1,
  not_before=least(shared_device_profile_jobs.not_before,now()),updated_at=now()
 RETURNING 1
)
SELECT (SELECT count(*) FROM agg),(SELECT count(*) FROM ins)`, dirtyLogFlushBatch).Scan(&consumed, &updated)
	return consumed, err
}

// pruneJobEnqueueLogs drops marks a dispatcher never consumed, for example
// after a long outage. The job rows already carry the last known state, and the
// next observation re-marks the endpoint, so stale marks need no replay.
func (s *DBStore) pruneJobEnqueueLogs(ctx context.Context) error {
	_, err := s.pg.db.ExecContext(ctx, `DELETE FROM endpoint_recognition_dirty_log WHERE created_at<now()-interval '1 hour';
DELETE FROM shared_device_profile_dirty_log WHERE created_at<now()-interval '1 hour'`)
	return err
}

func (s *DBStore) runJobEnqueueDispatchers(ctx context.Context) {
	flush := time.NewTicker(dirtyLogFlushInterval)
	cleanup := time.NewTicker(dirtyLogCleanupPeriod)
	defer flush.Stop()
	defer cleanup.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			work, cancel := context.WithTimeout(ctx, dirtyLogFlushTimeout)
			consumed, err := s.flushRecognitionDirtyLog(work)
			cancel()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "recognition dirty dispatcher: %v\n", err)
			}
			_ = consumed
			work, cancel = context.WithTimeout(ctx, dirtyLogFlushTimeout)
			_, err = s.flushSharedProfileDirtyLog(work)
			cancel()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "shared profile dirty dispatcher: %v\n", err)
			}
		case <-cleanup.C:
			work, cancel := context.WithTimeout(ctx, dirtyLogCleanupTimeout)
			err := s.pruneJobEnqueueLogs(work)
			cancel()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "job enqueue log retention: %v\n", err)
			}
		}
	}
}
