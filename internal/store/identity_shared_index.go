package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	// sharedIndexMembers bounds the member rows per statement.
	sharedIndexMembers = 1000
	sharedIndexIdle    = 10 * time.Second
	// sharedPruneBatch bounds the member rows one pass deletes.
	sharedPruneBatch = 5000
)

// sharedIndexSelectSQL picks the newest unindexed snapshot of this process's sensor inside the
// retention window, one document per pass. History is never indexed: shared-observation windows only
// look back about three reconcile intervals.
const sharedIndexSelectSQL = `SELECT f.source,f.sensor_id,f.campus_id,f.access_domain,f.snapshot_id,f.observed_at,f.document
FROM identity_full_snapshots f
WHERE f.sensor_id=$1 AND f.observed_at>$2 AND NOT EXISTS (SELECT 1 FROM shared_identity_snapshot_indexes i WHERE i.source=f.source AND i.sensor_id=f.sensor_id AND i.campus_id=f.campus_id AND i.access_domain=f.access_domain AND i.snapshot_id=f.snapshot_id)
ORDER BY f.observed_at DESC, f.snapshot_id DESC LIMIT 1`

// Members and index rows outside the retention window are deleted in bounded, index-ordered batches.
const sharedMembersPruneSQL = `DELETE FROM shared_identity_snapshot_members WHERE ctid IN (SELECT ctid FROM shared_identity_snapshot_members WHERE received_at<$1 ORDER BY received_at LIMIT $2)`
const sharedIndexesPruneSQL = `DELETE FROM shared_identity_snapshot_indexes WHERE observed_at<$1`

// indexPendingSharedSnapshots indexes the newest unindexed snapshot, outside the snapshot commit, then
// prunes expired member and index rows. The index row is written last, so its presence means every
// member is stored. Until then readers report identity_snapshot_index_pending, which is the honest
// state for a snapshot that is still being indexed.
func (s *DBStore) indexPendingSharedSnapshots(ctx context.Context) (int, error) {
	cutoff := time.Now().UTC().Add(-snapshotRetention)
	rows, err := s.pg.db.QueryContext(ctx, sharedIndexSelectSQL, s.pg.sensorID, cutoff)
	if err != nil {
		return 0, err
	}
	var work []IdentitySnapshot
	for rows.Next() {
		var snapshot IdentitySnapshot
		var raw []byte
		if err = rows.Scan(&snapshot.Source, &snapshot.SensorID, &snapshot.CampusID, &snapshot.AccessDomain, &snapshot.SnapshotID, &snapshot.ObservedAt, &raw); err != nil {
			rows.Close()
			return 0, err
		}
		if err = json.Unmarshal(raw, &snapshot); err != nil {
			rows.Close()
			return 0, fmt.Errorf("decode snapshot %s: %w", snapshot.SnapshotID, err)
		}
		work = append(work, snapshot)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	indexed := 0
	for _, snapshot := range work {
		snapshot.Sessions = policyRows(snapshot.Events)
		if err = indexSharedSnapshot(ctx, s.pg.db, snapshot); err != nil {
			return indexed, fmt.Errorf("index snapshot %s: %w", snapshot.SnapshotID, err)
		}
		indexed++
	}
	if _, err = s.pg.db.ExecContext(ctx, sharedMembersPruneSQL, cutoff, sharedPruneBatch); err != nil {
		return indexed, fmt.Errorf("prune shared members: %w", err)
	}
	if _, err = s.pg.db.ExecContext(ctx, sharedIndexesPruneSQL, cutoff); err != nil {
		return indexed, fmt.Errorf("prune shared indexes: %w", err)
	}
	return indexed, nil
}

// indexSharedSnapshot stores every member, then the index row, in one transaction.
func indexSharedSnapshot(ctx context.Context, db *sql.DB, snapshot IdentitySnapshot) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for start := 0; start < len(snapshot.Sessions); start += sharedIndexMembers {
		end := min(start+sharedIndexMembers, len(snapshot.Sessions))
		if err = insertSharedSnapshotMembers(ctx, tx, snapshot, snapshot.Sessions[start:end]); err != nil {
			return err
		}
	}
	if err = insertSharedSnapshotIndex(ctx, tx, snapshot); err != nil {
		return err
	}
	return tx.Commit()
}

// runSharedSnapshotIndexer keeps draining the pending queue. It sleeps only when a pass finds nothing
// or fails, so a backlog is worked off without pause.
func (s *DBStore) runSharedSnapshotIndexer(ctx context.Context) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 2*time.Minute)
		indexed, err := s.indexPendingSharedSnapshots(work)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "shared snapshot indexer: %v\n", err)
		}
		if err != nil || indexed == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(sharedIndexIdle):
			}
		}
	}
}
