package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/store"
	"strings"
	"time"
)

// Completed jobs without newer dependencies can only lose older evidence from
// their last evaluated window. In-flight/new work and missing bounds remain
// conservative; per-IP changes are never filtered by this coverage-only check.
func sharedSnapshotCoverageRelevant(covered sql.NullTime, from time.Time, interval int, registered, force, busy bool) bool {
	if !covered.Valid || from.IsZero() || !registered || interval <= 0 || force || busy {
		return true
	}
	return !covered.Time.Before(from.Add(-time.Duration(3*interval) * time.Second))
}

// A wake is expanded in bounded keyset batches. The wake row and the selected job
// rows are locked only while this PostgreSQL transaction is open.
func (s *Server) processSharedObservationWake(ctx context.Context) (bool, error) {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id int64
	var cursor, producerMode, kind string
	var originXID int64
	err = tx.QueryRowContext(ctx, `SELECT wake_id,cursor_job_id,producer_mode,kind,origin_xid FROM shared_observation_wakes
 WHERE processed_at IS NULL ORDER BY wake_id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id, &cursor, &producerMode, &kind, &originXID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var covered sql.NullTime
	var force, registered bool
	var interval int
	if kind == "snapshot_scope" {
		var scope store.IdentityScope
		if err = tx.QueryRowContext(ctx, `SELECT source,sensor_id,campus_id,access_domain,covered_to,force_all FROM shared_observation_wakes WHERE wake_id=$1`, id).Scan(&scope.Source, &scope.SensorID, &scope.CampusID, &scope.AccessDomain, &covered, &force); err != nil {
			return true, err
		}
		if covered.Valid && !force {
			authority, e := newIdentityAuthorityResolver(s).resolve(ctx, scope)
			if e != nil {
				return true, e
			}
			interval, registered = authority.interval, authority.registered
		}
	}
	if kind == "snapshot_ip" {
		// Snapshot rows may be rewritten for provenance even when almost none
		// of their IPs have a current shared observation. Match 1,000 changed
		// IPs at a time, wake only the intersecting jobs, then confirm exactly
		// those durable records in the same short transaction.
		var confirmed int64
		err = tx.QueryRowContext(ctx, `WITH picked AS (
 SELECT ip.wake_id,ip.source,ip.sensor_id,ip.campus_id,ip.access_domain,ip.ip,
 GREATEST(ip.received_at,COALESCE(scope.received_at,ip.received_at)) AS received_at
 FROM shared_observation_wakes ip LEFT JOIN shared_observation_wakes scope
  ON scope.origin_xid=ip.origin_xid AND scope.kind='snapshot_scope' AND scope.source=ip.source
  AND scope.sensor_id=ip.sensor_id AND scope.campus_id=ip.campus_id AND scope.access_domain=ip.access_domain
 WHERE ip.kind='snapshot_ip' AND ip.origin_xid=$1 AND ip.processed_at IS NULL
 ORDER BY ip.wake_id LIMIT 1000 FOR UPDATE OF ip SKIP LOCKED
), matched AS (
 SELECT p.wake_id,j.job_id,p.received_at FROM picked p JOIN shared_observation_jobs j ON j.ip=p.ip
 WHERE NOT j.expired AND j.last_event_at+($3::integer*interval '1 second')>now()
 AND EXISTS (SELECT 1 FROM shared_observation_mappings m WHERE m.active
  AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
  AND m.identity_source=p.source AND m.identity_sensor_id=p.sensor_id AND m.identity_campus_id=p.campus_id
  AND m.identity_access_domain=p.access_domain AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at)
), impacted AS (
 SELECT job_id,max(received_at) AS received_at FROM matched GROUP BY job_id
), applied AS (
 UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),
 last_dependency_at=GREATEST(j.last_dependency_at,i.received_at),
 dirty_since=CASE WHEN j.revision=j.completed_revision THEN i.received_at ELSE j.dirty_since END,
 lease_token='',lease_until=NULL
 FROM impacted i WHERE $2='async' AND j.job_id=i.job_id RETURNING j.job_id
), confirmed AS (
 UPDATE shared_observation_wakes w SET processed_at=clock_timestamp(),
 matched_jobs=(SELECT count(*) FROM matched m WHERE m.wake_id=w.wake_id),
 applied_jobs=CASE WHEN $2='async' THEN (SELECT count(*) FROM matched m WHERE m.wake_id=w.wake_id) ELSE 0 END
 FROM picked p WHERE w.wake_id=p.wake_id RETURNING w.wake_id
)
 SELECT count(*) FROM confirmed`, originXID, producerMode, s.sharedConfig.FreshnessSeconds).Scan(&confirmed)
		if err != nil {
			return true, err
		}
		if confirmed > 0 {
			return true, tx.Commit()
		}
	}
	jobSQL := `SELECT j.job_id FROM shared_observation_jobs j
 JOIN shared_observation_wakes w ON w.wake_id=$1
 WHERE j.job_id>$2 AND NOT j.expired AND j.last_event_at+($3::integer*interval '1 second')>now()
 AND (
  (w.kind='capture_scope' AND j.sensor_id=w.sensor_id AND j.campus_id=w.campus_id AND j.access_domain=w.access_domain
   AND (w.force_all OR (j.coverage_state<>'verified' AND j.last_event_at>w.previous_covered_to
    AND j.last_event_at<=w.covered_to)))
  OR (w.kind='health_scope' AND EXISTS (SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.health_bridge_id=w.bridge_id
    AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at))
  OR (w.kind IN ('identity_ip','snapshot_ip','snapshot_scope')
	   AND ((w.kind='snapshot_scope' AND (w.force_all OR j.last_result<>'matched' OR j.attribution_state<>'resolved')
	    AND (j.revision=j.completed_revision OR j.lease_token<>''))
    OR (w.kind<>'snapshot_scope' AND j.ip=w.ip))
   AND EXISTS (SELECT 1 FROM shared_observation_mappings m WHERE m.active
    AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
    AND m.identity_source=w.source AND m.identity_sensor_id=w.sensor_id AND m.identity_campus_id=w.campus_id
    AND m.identity_access_domain=w.access_domain AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at))
  ) ORDER BY j.job_id LIMIT 100`
	if kind == "snapshot_scope" {
		jobSQL = strings.Replace(jobSQL, "SELECT j.job_id FROM", "SELECT j.job_id,j.last_document->'window'->>'from',(j.revision<>j.completed_revision OR j.lease_token<>'') FROM", 1)
	}
	rows, err := tx.QueryContext(ctx, jobSQL, id, cursor, s.sharedConfig.FreshnessSeconds)
	if err != nil {
		return true, err
	}
	ids := make([]string, 0, 100)
	lastScanned := ""
	for rows.Next() {
		var jobID string
		var fromRaw sql.NullString
		var busy bool
		if kind == "snapshot_scope" {
			err = rows.Scan(&jobID, &fromRaw, &busy)
		} else {
			err = rows.Scan(&jobID)
		}
		if err != nil {
			rows.Close()
			return true, err
		}
		lastScanned = jobID
		if kind == "snapshot_scope" {
			from, _ := time.Parse(time.RFC3339Nano, fromRaw.String)
			if !sharedSnapshotCoverageRelevant(covered, from, interval, registered, force, busy) {
				continue
			}
		}
		ids = append(ids, jobID)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return true, err
	}
	apply := producerMode == "async"
	if apply && len(ids) > 0 {
		_, err = tx.ExecContext(ctx, `UPDATE shared_observation_jobs j SET revision=revision+1,
 next_attempt_at=now(),last_dependency_at=GREATEST(j.last_dependency_at,w.received_at),
 dirty_since=CASE WHEN j.revision=j.completed_revision THEN w.received_at ELSE j.dirty_since END,
 lease_token='',lease_until=NULL
 FROM shared_observation_wakes w WHERE w.wake_id=$1 AND j.job_id=ANY($2::text[])`, id, ids)
		if err != nil {
			return true, err
		}
	}
	if lastScanned == "" {
		_, err = tx.ExecContext(ctx, `UPDATE shared_observation_wakes SET processed_at=clock_timestamp() WHERE wake_id=$1`, id)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE shared_observation_wakes SET cursor_job_id=$2,matched_jobs=matched_jobs+$3,
 applied_jobs=applied_jobs+$4 WHERE wake_id=$1`, id, lastScanned, len(ids), map[bool]int{true: len(ids), false: 0}[apply])
	}
	if err != nil {
		return true, err
	}
	return true, tx.Commit()
}

func (s *Server) maintainSharedObservationWakes(ctx context.Context) error {
	// Confirmation-based retention. Pending wakes remain durable through outages.
	_, err := s.operations.db.ExecContext(ctx, `DELETE FROM shared_observation_wakes
 WHERE wake_id IN (SELECT wake_id FROM shared_observation_wakes
 WHERE processed_at<now()-interval '30 days' ORDER BY wake_id LIMIT 500)`)
	return err
}

func (s *Server) reconcileSharedObservationGaps(ctx context.Context) error {
	// Bounded safety sweep for a missed dependency notification. It runs at most
	// once a minute, and only for current, unresolved evidence.
	_, err := s.operations.db.ExecContext(ctx, `WITH candidates AS (
 SELECT job_id FROM shared_observation_jobs
 WHERE NOT expired AND revision=completed_revision AND last_result='insufficient'
 AND completed_at<now()-interval '1 minute' AND next_attempt_at>now()
 AND last_event_at+($1::integer*interval '1 second')>now()
 ORDER BY completed_at,job_id LIMIT 100 FOR UPDATE SKIP LOCKED)
 UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),dirty_since=now(),
 lease_token='',lease_until=NULL
 FROM candidates WHERE j.job_id=candidates.job_id`, s.sharedConfig.FreshnessSeconds)
	return err
}

func (s *Server) logSharedObservationMetrics(ctx context.Context) error {
	var current, expiry, timedOut, pendingWakes, recentDecisions, lockWaiters int64
	var oldestCurrent, oldestExpiry, oldestWake, p99, maxLockWait sql.NullFloat64
	scopes, _ := json.Marshal(s.sharedConfig.Sources)
	err := s.operations.db.QueryRowContext(ctx, `WITH eligible AS (
 SELECT j.*,m.mode,
 (j.revision>j.completed_revision OR (m.mode<>'async' AND j.last_event_at+($1::integer*interval '1 second')>now())) AS realtime_lane,
 (j.revision=j.completed_revision AND (m.mode='async' OR j.last_event_at+($1::integer*interval '1 second')<=now())) AS expiry_lane
 FROM shared_observation_jobs j CROSS JOIN shared_observation_wake_mode m
 WHERE m.singleton AND NOT j.expired
 AND (j.sensor_id,j.campus_id,j.access_domain) IN
 (SELECT sensor_id,campus_id,access_domain FROM jsonb_to_recordset($2::jsonb) r(sensor_id text,campus_id text,access_domain text))
 ) SELECT
 count(*) FILTER(WHERE next_attempt_at<=now() AND realtime_lane),
 count(*) FILTER(WHERE next_attempt_at<=now() AND expiry_lane),
 count(*) FILTER(WHERE lease_until<now() AND lease_token<>''),
 max(extract(epoch FROM now()-CASE WHEN revision>completed_revision THEN dirty_since ELSE next_attempt_at END)) FILTER(WHERE next_attempt_at<=now() AND realtime_lane),
 max(extract(epoch FROM now()-next_attempt_at)) FILTER(WHERE next_attempt_at<=now() AND expiry_lane)
 FROM eligible`, s.sharedConfig.FreshnessSeconds, scopes).Scan(&current, &expiry, &timedOut, &oldestCurrent, &oldestExpiry)
	if err != nil {
		return err
	}
	err = s.operations.db.QueryRowContext(ctx, `SELECT count(*),max(extract(epoch FROM now()-received_at)) FROM shared_observation_wakes WHERE processed_at IS NULL`).Scan(&pendingWakes, &oldestWake)
	if err != nil {
		return err
	}
	recentDecisions, p99.Float64 = sharedDecisionLatencies.snapshot(time.Now())
	p99.Valid = recentDecisions > 0 && p99.Float64 >= 0

	err = s.operations.db.QueryRowContext(ctx, `SELECT count(*),max(extract(epoch FROM clock_timestamp()-query_start))
 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%shared_observation_jobs%'`).Scan(&lockWaiters, &maxLockWait)
	if err != nil {
		return err
	}
	// Keep a stable, parseable line for field inspection without changing public APIs.
	sharedObservationMetricLog(current, expiry, timedOut, pendingWakes, recentDecisions, lockWaiters, oldestCurrent, oldestExpiry, oldestWake, p99, maxLockWait)
	return nil
}

func sharedObservationMetricLog(current, expiry, timedOut, wakes, decisions, lockWaiters int64, currentAge, expiryAge, wakeAge, p99, lockAge sql.NullFloat64) {
	fmt.Printf("shared_observation_metrics realtime=%d expiry=%d lease_timeout=%d wake_pending=%d realtime_oldest_s=%.3f expiry_oldest_s=%.3f wake_oldest_s=%.3f async_decisions=%d async_p99_ms=%.3f enqueue_lock_waiters=%d enqueue_lock_wait_oldest_s=%.3f claims=%d empty_claims=%d failures=%d version_conflicts=%d latency_window_s=900 latency_samples_complete=%t at=%s\n",
		current, expiry, timedOut, wakes, currentAge.Float64, expiryAge.Float64, wakeAge.Float64, decisions, p99.Float64, lockWaiters, lockAge.Float64, sharedObservationClaimAttempts.Swap(0), sharedObservationEmptyClaims.Swap(0), sharedObservationFailures.Swap(0), sharedObservationVersionConflicts.Swap(0), p99.Valid, time.Now().UTC().Format(time.RFC3339))
}
