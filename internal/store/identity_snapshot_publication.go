package store

import (
	"context"
	"database/sql"
	"os"
	"time"

	"proxy-sentinel/internal/policy"
)

// snapshotMetadataRetention keeps the snapshot log for a year after each snapshot. The log is the
// durable record of which snapshots existed; documents are not kept beyond the newest one per scope.
const snapshotMetadataRetention = 365 * 24 * time.Hour

// snapshotPruneBatch bounds how many old snapshots one commit deletes, so steady state is one in,
// one out and a commit never carries a large delete.
const snapshotPruneBatch = 2

// snapshotPublishSQL publishes a complete snapshot as the scope's current state in the commit
// transaction. It only moves forward, and it never changes the generation or the inbox lease: the
// old background calibration rebuilt three tables per snapshot and fenced in-flight applies.
const snapshotPublishSQL = `UPDATE identity_pipeline_scopes SET snapshot_id=$3,snapshot_at=$2,accounts=$4,sessions=$5,statistics_at=now(),calibration_state='completed',calibration_error='' WHERE scope_key=$1 AND (snapshot_at IS NULL OR snapshot_at<$2)`

// snapshotPublishFailedSQL records a snapshot that cannot be published and keeps the published one.
const snapshotPublishFailedSQL = `UPDATE identity_pipeline_scopes SET calibration_state='failed',calibration_error=$3 WHERE scope_key=$1 AND (snapshot_at IS NULL OR snapshot_at<$2)`

// snapshotPruneSQL deletes older documents of the scope once the projection no longer needs them: a
// document is read only by its pending projection job, and the newest one by managed polling.
const snapshotPruneSQL = `DELETE FROM identity_full_snapshots WHERE ctid IN (SELECT f.ctid FROM identity_full_snapshots f
 WHERE f.source=$1 AND f.sensor_id=$2 AND f.campus_id=$3 AND f.access_domain=$4 AND f.observed_at<$5
 AND NOT EXISTS (SELECT 1 FROM identity_snapshot_projection_jobs j WHERE j.source=f.source AND j.sensor_id=f.sensor_id AND j.campus_id=f.campus_id AND j.access_domain=f.access_domain AND j.snapshot_id=f.snapshot_id)
 ORDER BY f.observed_at LIMIT $6)`

const snapshotLogPruneSQL = `DELETE FROM identity_snapshot_log WHERE ctid IN (SELECT ctid FROM identity_snapshot_log
 WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND observed_at<$5 ORDER BY observed_at LIMIT $6)`

// snapshotPublication counts distinct sessions and accounts in a complete snapshot and reports a
// session that belongs to more than one account.
func snapshotPublication(sessions []policy.Session) (accounts, count int, conflict bool) {
	owner := make(map[string]string, len(sessions))
	accountSet := map[string]struct{}{}
	for _, session := range sessions {
		if existing, seen := owner[session.ID]; seen && existing != session.AccountID {
			conflict = true
		}
		owner[session.ID] = session.AccountID
		accountSet[session.AccountID] = struct{}{}
	}
	return len(accountSet), len(owner), conflict
}

// publishSnapshotTx writes the scope publication last in the commit transaction, so the scope-row
// lock is held only until commit.
func publishSnapshotTx(ctx context.Context, tx *sql.Tx, snapshot IdentitySnapshot, accounts, sessions int, conflict bool) error {
	key := IdentityScopeKey(snapshot.IdentityScope)
	if _, err := tx.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, key, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain); err != nil {
		return err
	}
	if conflict {
		_, err := tx.ExecContext(ctx, snapshotPublishFailedSQL, key, snapshot.ObservedAt, "session_account_conflict")
		return err
	}
	if os.Getenv("PROXY_SENTINEL_IDENTITY_DELTA_ENABLED") == "true" {
		var delta bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_delta_settings WHERE scope_key=$1 AND mode IN ('shadow','delta'))`, key).Scan(&delta); err != nil {
			return err
		}
		if delta {
			_, err := tx.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET calibration_state='building',calibration_error='' WHERE scope_key=$1`, key)
			return err
		}
	}
	_, err := tx.ExecContext(ctx, snapshotPublishSQL, key, snapshot.ObservedAt, snapshot.SnapshotID, accounts, sessions)
	return err
}

// pruneSnapshotsTx deletes a bounded number of superseded documents and expired log rows.
func pruneSnapshotsTx(ctx context.Context, tx *sql.Tx, snapshot IdentitySnapshot) error {
	if _, err := tx.ExecContext(ctx, snapshotPruneSQL, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.ObservedAt, snapshotPruneBatch); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, snapshotLogPruneSQL, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.ObservedAt.Add(-snapshotMetadataRetention), snapshotPruneBatch)
	return err
}
