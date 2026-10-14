package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"proxy-sentinel/internal/normalized"
)

// Build a private generation without locking the current identity writer. Replay
// all committed deltas after the snapshot boundary, then publish at a checked
// processing checkpoint. A failed or expired builder never replaces current.
func (s *PostgresStore) calibrateIdentitySnapshot(ctx context.Context, snapshot IdentitySnapshot) (err error) {
	key := IdentityScopeKey(snapshot.IdentityScope)
	_, err = s.db.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, key, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain)
	if err != nil {
		return err
	}
	var epoch int64
	err = s.db.QueryRowContext(ctx, `UPDATE identity_pipeline_scopes SET calibration_epoch=calibration_epoch+1,calibration_lease_until=now()+interval '30 seconds',calibration_state='building',calibration_error='' WHERE scope_key=$1 AND (snapshot_at IS NULL OR snapshot_at<$2) AND (calibration_lease_until IS NULL OR calibration_lease_until<now()) RETURNING calibration_epoch`, key, snapshot.ObservedAt).Scan(&epoch)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	generation := fmt.Sprintf("snapshot-%s-%d", snapshot.SnapshotID, epoch)
	defer func() {
		if err != nil {
			report, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _ = s.db.ExecContext(report, `INSERT INTO identity_projection_cleanup(scope_key,generation,calibration_epoch) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, key, generation, epoch)
			_, _ = s.db.ExecContext(report, `UPDATE identity_pipeline_scopes SET calibration_state='failed',calibration_error='calibration_failed',calibration_lease_until=NULL WHERE scope_key=$1 AND calibration_epoch=$2`, key, epoch)
		}
	}()
	renew := func() error {
		result, e := s.db.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET calibration_lease_until=now()+interval '30 seconds' WHERE scope_key=$1 AND calibration_epoch=$2 AND calibration_lease_until>now()`, key, epoch)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrIdentityLeaseExpired
		}
		return nil
	}
	for start := 0; start < len(snapshot.Events); start += 500 {
		if err = renew(); err != nil {
			return err
		}
		rows := []map[string]any{}
		for _, event := range snapshot.Events[start:min(start+500, len(snapshot.Events))] {
			sessions := BuildIdentityState([]normalized.Event{event}).Sessions
			if len(sessions) != 1 {
				return fmt.Errorf("invalid snapshot session")
			}
			session := sessions[0]
			address, parseErr := netip.ParseAddr(session.IP)
			if parseErr != nil {
				return parseErr
			}
			session.IP = address.Unmap().String()
			if seconds, e := strconv.ParseInt(stringFromMap(event.Payload, "source_login_generation"), 10, 64); e == nil && seconds > 0 && !time.Unix(seconds, 0).After(snapshot.ObservedAt) {
				session.StartedAt = time.Unix(seconds, 0).UTC().Format(time.RFC3339Nano)
			}
			rows = append(rows, map[string]any{"session_id": session.SessionID, "ip": session.IP, "account_id": session.AccountID, "document": session})
		}
		raw, _ := json.Marshal(rows)
		_, err = s.db.ExecContext(ctx, `INSERT INTO identity_current_addresses(scope_key,generation,session_id,ip,account_id,observed_at,active,document) SELECT $1,$2,r.session_id,r.ip,r.account_id,$3,true,r.document FROM jsonb_to_recordset($4::jsonb) r(session_id text,ip text,account_id text,document jsonb)`, key, generation, snapshot.ObservedAt, raw)
		if err != nil {
			return err
		}
	}
	// These aggregates only run once per private snapshot generation, never on GET.
	_, err = s.db.ExecContext(ctx, `INSERT INTO identity_session_refs SELECT scope_key,generation,session_id,min(account_id),count(*) FROM identity_current_addresses WHERE scope_key=$1 AND generation=$2 GROUP BY scope_key,generation,session_id HAVING count(DISTINCT account_id)=1`, key, generation)
	if err != nil {
		return err
	}
	// Conflicting account ownership is a failed calibration, not a dropped row.
	var conflict bool
	// Inspect the candidate once. A join against freshly inserted reference rows
	// can choose a quadratic nested loop while generation statistics are stale.
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_current_addresses WHERE scope_key=$1 AND generation=$2 GROUP BY session_id HAVING count(DISTINCT account_id)>1)`, key, generation).Scan(&conflict)
	if err != nil {
		return err
	}
	if conflict {
		return fmt.Errorf("snapshot session account conflict")
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO identity_account_refs SELECT scope_key,generation,account_id,count(*) FROM identity_session_refs WHERE scope_key=$1 AND generation=$2 AND addresses>0 GROUP BY scope_key,generation,account_id`, key, generation)
	if err != nil {
		return err
	}
	sequence, ordinal := int64(0), -1
	for {
		if err = renew(); err != nil {
			return err
		}
		var checkpointSequence int64
		var checkpointOffset int
		err = s.db.QueryRowContext(ctx, `SELECT processed_sequence,COALESCE((SELECT processed_offset FROM identity_ingest_batches b WHERE b.scope_key=p.scope_key AND b.sequence=p.processed_sequence+1),0) FROM identity_pipeline_scopes p WHERE scope_key=$1`, key).Scan(&checkpointSequence, &checkpointOffset)
		if err != nil {
			return err
		}
		for {
			rows, e := s.db.QueryContext(ctx, `SELECT batch_sequence,ordinal,document FROM identity_applied_events WHERE scope_key=$1 AND (batch_sequence,ordinal)>($2,$3) AND (batch_sequence<$4 OR (batch_sequence=$4 AND ordinal<$5)) AND observed_at>$6 ORDER BY batch_sequence,ordinal LIMIT 100`, key, sequence, ordinal, checkpointSequence+1, checkpointOffset, snapshot.ObservedAt)
			if e != nil {
				err = e
				return err
			}
			events := []normalized.Event{}
			for rows.Next() {
				var raw []byte
				var event normalized.Event
				if e = rows.Scan(&sequence, &ordinal, &raw); e == nil {
					e = json.Unmarshal(raw, &event)
				}
				if e != nil {
					break
				}
				events = append(events, event)
			}
			if e == nil {
				e = rows.Err()
			}
			rows.Close()
			if e != nil {
				err = e
				return err
			}
			if len(events) == 0 {
				break
			}
			work, cancel := context.WithTimeout(ctx, 2*time.Second)
			tx, e := s.db.BeginTx(work, nil)
			if e == nil {
				_, _, e = applyCurrentIdentityEvents(work, tx, key, generation, events, sql.NullTime{})
				if e == nil {
					e = tx.Commit()
				}
				tx.Rollback()
			}
			cancel()
			if e != nil {
				err = e
				return err
			}
		}
		var accounts, sessions int64
		err = s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity_account_refs WHERE scope_key=$1 AND generation=$2 AND sessions>0),(SELECT count(*) FROM identity_session_refs WHERE scope_key=$1 AND generation=$2 AND addresses>0)`, key, generation).Scan(&accounts, &sessions)
		if err != nil {
			return err
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		tx, e := s.db.BeginTx(work, nil)
		if e != nil {
			cancel()
			err = e
			return err
		}
		var liveSequence int64
		var liveOffset int
		var valid bool
		e = tx.QueryRowContext(work, `SELECT processed_sequence,COALESCE(calibration_epoch=$2 AND calibration_lease_until>now(),false) FROM identity_pipeline_scopes WHERE scope_key=$1 FOR UPDATE`, key, epoch).Scan(&liveSequence, &valid)
		if e == nil {
			e = tx.QueryRowContext(work, `SELECT COALESCE((SELECT processed_offset FROM identity_ingest_batches WHERE scope_key=$1 AND sequence=$2),0)`, key, liveSequence+1).Scan(&liveOffset)
		}
		if e == nil && !valid {
			e = ErrIdentityLeaseExpired
		}
		published := e == nil && liveSequence == checkpointSequence && liveOffset == checkpointOffset
		if published {
			_, e = tx.ExecContext(work, `INSERT INTO identity_projection_cleanup(scope_key,generation,calibration_epoch) SELECT scope_key,current_generation,calibration_epoch-1 FROM identity_pipeline_scopes WHERE scope_key=$1 ON CONFLICT DO NOTHING`, key)
			if e != nil {
				tx.Rollback()
				cancel()
				return e
			}
			_, e = tx.ExecContext(work, `UPDATE identity_pipeline_scopes SET current_generation=$2,accounts=$3,sessions=$4,statistics_at=now(),snapshot_id=$5,snapshot_at=$6,calibration_state='completed',calibration_error='',calibration_lease_until=NULL,lease_epoch=lease_epoch+1,lease_until=NULL WHERE scope_key=$1`, key, generation, accounts, sessions, snapshot.SnapshotID, snapshot.ObservedAt)
			if e == nil {
				e = tx.Commit()
			}
		}
		tx.Rollback()
		cancel()
		if e != nil {
			err = e
			return err
		}
		if published {
			return nil
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			return err
		}
	}
}
func (s *DBStore) runIdentityCalibration(ctx context.Context) {
	for ctx.Err() == nil {
		// Latest complete snapshot per scope; no partial uploads can enter this table.
		work, cancel := context.WithTimeout(ctx, 3*time.Minute)
		rows, err := s.pg.db.QueryContext(work, `SELECT f.document FROM (SELECT DISTINCT ON(source,sensor_id,campus_id,access_domain) * FROM identity_full_snapshots WHERE sensor_id=$1 ORDER BY source,sensor_id,campus_id,access_domain,observed_at DESC) f LEFT JOIN identity_pipeline_scopes p USING(source,sensor_id,campus_id,access_domain) WHERE p.snapshot_at IS NULL OR p.snapshot_at<f.observed_at`, s.pg.sensorID)
		snapshots := []IdentitySnapshot{}
		if err == nil {
			for rows.Next() {
				var raw []byte
				var snap IdentitySnapshot
				if err = rows.Scan(&raw); err == nil {
					err = json.Unmarshal(raw, &snap)
				}
				if err != nil {
					break
				}
				snapshots = append(snapshots, snap)
			}
			rows.Close()
		}
		if err == nil {
			for _, snap := range snapshots {
				if err = s.pg.calibrateIdentitySnapshot(work, snap); err != nil {
					break
				}
			}
		}
		cancel()
		cleanup, stop := context.WithTimeout(ctx, time.Second)
		_ = s.pg.cleanIdentityProjectionGeneration(cleanup, s.pg.sensorID)
		stop()
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// The small queue indexes exact obsolete generations; it never scans current
// sessions to discover work, and never deletes a still-current/building version.
func (s *PostgresStore) cleanIdentityProjectionGeneration(ctx context.Context, sensor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var key, generation string
	err = tx.QueryRowContext(ctx, `SELECT j.scope_key,j.generation FROM identity_projection_cleanup j JOIN identity_pipeline_scopes p USING(scope_key) WHERE p.sensor_id=$1 AND j.generation<>p.current_generation AND (j.calibration_epoch<p.calibration_epoch OR p.calibration_state='failed') ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1`, sensor).Scan(&key, &generation)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	var deleted int64
	for _, table := range []string{"identity_current_addresses", "identity_session_refs", "identity_account_refs"} {
		result, e := tx.ExecContext(ctx, `WITH batch AS (SELECT ctid FROM `+table+` WHERE scope_key=$1 AND generation=$2 LIMIT 1000 FOR UPDATE SKIP LOCKED) DELETE FROM `+table+` WHERE ctid IN (SELECT ctid FROM batch)`, key, generation)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		deleted += n
	}
	if deleted == 0 {
		_, err = tx.ExecContext(ctx, `DELETE FROM identity_projection_cleanup WHERE scope_key=$1 AND generation=$2 AND NOT EXISTS(SELECT 1 FROM identity_current_addresses WHERE scope_key=$1 AND generation=$2) AND NOT EXISTS(SELECT 1 FROM identity_session_refs WHERE scope_key=$1 AND generation=$2) AND NOT EXISTS(SELECT 1 FROM identity_account_refs WHERE scope_key=$1 AND generation=$2)`, key, generation)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
