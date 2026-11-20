package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

var ErrSharedStreamBinding = errors.New("shared stream binding is missing or stale")

func SharedStreamRequired() bool { return os.Getenv("PROXY_SENTINEL_STREAM_SHARED_REQUIRED") == "true" }

// Hold the current binding rows until the decision and its durable ACK commit.
func LockSharedStreamEpochs(ctx context.Context, tx *sql.Tx, sensor, generation string, expected map[string]string) error {
	rows, err := tx.QueryContext(ctx, `SELECT s.source_owner,s.epoch,s.cancel_id FROM stream_shared_source_cutovers s
 JOIN stream_source_cutovers f USING(epoch,source_kind,source_path)
 WHERE s.sensor_id=$1 AND s.state='active' AND f.state='active' AND f.sensor_id=$1 ORDER BY s.source_owner FOR SHARE OF s`, sensor)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var owner, epoch, actualGeneration string
		if err := rows.Scan(&owner, &epoch, &actualGeneration); err != nil {
			return err
		}
		if actualGeneration != generation || expected[owner] != epoch {
			return ErrSharedStreamBinding
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if seen != 2 || len(expected) != 2 {
		return ErrSharedStreamBinding
	}
	return nil
}

func VerifyRequiredSharedStream(ctx context.Context, db *sql.DB, sensor, scope, owner, path, epoch string) error {
	var ready bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM stream_shared_source_cutovers s JOIN stream_source_cutovers f USING(epoch,source_kind,source_path)
 WHERE s.sensor_id=$1 AND f.sensor_id=$1 AND s.scope_id=$2 AND s.source_owner=$3
 AND s.source_path=$4 AND s.epoch=$5 AND s.state='active' AND f.state='active')
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='stream_shared_segment_receipts'::regclass
 AND conname='stream_shared_segment_receipts_event_count_check' AND pg_get_constraintdef(oid) LIKE '%2000%')
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='stream_projection_segments'::regclass
 AND conname='stream_projection_device_stream4_shape' AND pg_get_constraintdef(oid) LIKE '%2000%')`, sensor, scope, owner, path, epoch).Scan(&ready)
	if err != nil {
		return fmt.Errorf("verify required shared stream: %w", err)
	}
	if !ready {
		return ErrSharedStreamBinding
	}
	return nil
}

type StreamSharedCutover struct {
	Epoch      string
	Cutoff     time.Time
	SourcePath string
	ScopeID    string
}

// The reader selects one owner generation before fetching any signal rows.
// A missing row means that owner still uses the legacy bounded reader.
func (s *DBStore) activeStreamSharedCutover(ctx context.Context, sensor, owner string) (StreamSharedCutover, bool, error) {
	if s == nil || s.pg == nil || sensor == "" || (owner != "handshake-sidecar" && owner != "packet-sidecar") {
		return StreamSharedCutover{}, false, errors.New("invalid shared source cutover lookup")
	}
	var item StreamSharedCutover
	query := `SELECT epoch,source_cutoff_at,source_path,scope_id FROM stream_shared_source_cutovers
 WHERE sensor_id=$1 AND source_owner=$2 AND state='active'`
	if SharedStreamRequired() {
		query += ` AND EXISTS(SELECT 1 FROM stream_source_cutovers f WHERE f.epoch=stream_shared_source_cutovers.epoch
 AND f.source_kind=stream_shared_source_cutovers.source_kind AND f.source_path=stream_shared_source_cutovers.source_path
 AND f.sensor_id=$1 AND f.state='active')`
	}
	err := s.pg.db.QueryRowContext(ctx, query, sensor, owner).Scan(&item.Epoch, &item.Cutoff, &item.SourcePath, &item.ScopeID)
	if errors.Is(err, sql.ErrNoRows) {
		if SharedStreamRequired() {
			return StreamSharedCutover{}, false, fmt.Errorf("%s: %w", owner, ErrSharedStreamBinding)
		}
		return StreamSharedCutover{}, false, nil
	}
	if err != nil {
		return StreamSharedCutover{}, false, err
	}
	if item.Epoch == "" || item.Cutoff.IsZero() || item.SourcePath == "" || item.ScopeID == "" {
		return StreamSharedCutover{}, false, errors.New("shared source cutover is incomplete")
	}
	return item, true, nil
}
