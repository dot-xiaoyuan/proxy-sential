package store

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"
)

var errIdentityDeltaPressure = errors.New("identity calibration paused for realtime pressure")

func (s *PostgresStore) identityDeltaLoad(ctx context.Context) (time.Duration, bool, error) {
	var age float64
	var blocked bool
	err := s.db.QueryRowContext(ctx, IdentityScopeStatusSQL(`SELECT COALESCE((SELECT max(extract(epoch FROM now()-oldest_pending_at)) FROM identity_pipeline_scopes WHERE enabled AND pending_records>0),0),EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query_start<now()-interval '1 second' AND (query LIKE '%identity_%' OR query LIKE '%shared_observation_jobs%'))`)).Scan(&age, &blocked)
	return time.Duration(age * float64(time.Second)), blocked, err
}

func (s *DBStore) runIdentityDeltaMaterializer(ctx context.Context) {
	db, err := sql.Open("pgx", s.pg.dsn)
	if err != nil {
		log.Printf("identity delta pool: %v", err)
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	worker := &PostgresStore{db: db, dsn: s.pg.dsn, sensorID: s.pg.sensorID, identityDeltaEnabled: true}
	notifyDone := make(chan struct{})
	notifyCtx, notifyStop := context.WithCancel(ctx)
	defer func() { notifyStop(); <-notifyDone }()
	go func() { defer close(notifyDone); worker.runIdentityDeltaNotifications(notifyCtx) }()
	nextCleanup := time.Now().Add(time.Minute)
	var pressure identityDeltaPressure
	for ctx.Err() == nil {
		began := time.Now()
		check, cancel := context.WithTimeout(ctx, 2*time.Second)
		age, blocked, e := worker.identityDeltaLoad(check)
		cancel()
		wasPaused := pressure.paused
		allowed := pressure.allow(age, blocked || e != nil)
		if wasPaused != pressure.paused {
			log.Printf("identity_delta_pressure paused=%t realtime_oldest_ms=%d database_blocked=%t", pressure.paused, age.Milliseconds(), blocked || e != nil)
		}
		did := false
		if allowed {
			work, stop := context.WithTimeout(ctx, 2*time.Minute)
			did, err = worker.processIdentityDelta(work)
			stop()
			if err != nil && !errors.Is(err, errIdentityDeltaPressure) {
				log.Printf("identity delta step failed: %v", err)
			}
			if !did && err == nil && time.Now().After(nextCleanup) {
				cleanup, c := context.WithTimeout(ctx, 10*time.Second)
				err = worker.cleanupIdentityDelta(cleanup)
				c()
				nextCleanup = time.Now().Add(10 * time.Second)
			}
			// Legacy scopes remain supported, but cannot claim a configured delta scope.
			if !did && err == nil {
				work, stop = context.WithTimeout(ctx, 2*time.Minute)
				err = worker.projectPendingIdentitySnapshots(work, 1)
				stop()
			}

		}
		delay := time.Second
		if did && err == nil {
			delay = 100 * time.Millisecond
		}
		if err != nil {
			delay = 2 * time.Second
		}
		logSlow := time.Since(began) > 10*time.Second
		if logSlow {
			log.Printf("identity_delta_cycle elapsed_ms=%d paused=%t", time.Since(began).Milliseconds(), pressure.paused)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (s *PostgresStore) runIdentityDeltaNotifications(ctx context.Context) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 10*time.Second)
		did, err := s.consumeIdentityDeltaNotification(work)
		cancel()
		delay := time.Second
		if did && err == nil {
			delay = 100 * time.Millisecond
		}
		if err != nil {
			log.Printf("identity delta notification failed: %v", err)
			delay = 2 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// Only completed staging data is temporary. Runs/capture intervals and identity
// evidence remain available; incomplete runs and undelivered notifications are
// never age-deleted. Each cleanup transaction has a bounded row count.
func (s *PostgresStore) cleanupIdentityDelta(ctx context.Context) error {
	tx, err := deltaBegin(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT run_id FROM identity_delta_runs WHERE state='completed' AND cleaned_at IS NULL AND completed_at<now()-interval '24 hours' ORDER BY completed_at,run_id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM identity_delta_members WHERE (run_id,member_key) IN (SELECT run_id,member_key FROM identity_delta_members WHERE run_id=$1 ORDER BY member_key LIMIT 500)`,
		`DELETE FROM identity_delta_changes WHERE (run_id,member_key) IN (SELECT run_id,member_key FROM identity_delta_changes WHERE run_id=$1 AND applied_at IS NOT NULL ORDER BY member_key LIMIT 500)`,
		`DELETE FROM identity_delta_notifications WHERE notification_id IN (SELECT notification_id FROM identity_delta_notifications WHERE run_id=$1 AND processed_at IS NOT NULL ORDER BY notification_id LIMIT 500)`,
		`UPDATE identity_delta_runs SET cleaned_at=now() WHERE run_id=$1 AND NOT EXISTS(SELECT 1 FROM identity_delta_members WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM identity_delta_changes WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM identity_delta_notifications WHERE run_id=$1)`,
	} {
		if _, err = tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
