package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/ingest"
)

// AcquireIngestSourceLease holds a session-scoped advisory lock for the life
// of one source reader. It prevents two ingest processes from racing between
// the idempotency lookup and the ClickHouse insert for the same file.
func (s *PostgresStore) AcquireIngestSourceLease(ctx context.Context, sourceKind, sourcePath string) (func(), error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	key := ingestSourceLeaseKey(s.sensorID, sourceKind, sourcePath)
	var locked bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, key).Scan(&locked); err != nil {
		conn.Close()
		return nil, err
	}
	if !locked {
		conn.Close()
		return nil, fmt.Errorf("ingest source is already leased: %s", sourceKind)
	}
	return func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key)
		_ = conn.Close()
	}, nil
}

func ingestSourceLeaseKey(sensorID, sourceKind, sourcePath string) string {
	return fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(sensorID), sensorID, len(sourceKind), sourceKind, len(sourcePath), sourcePath)
}

func (s *PostgresStore) LoadIngestCheckpoint(ctx context.Context, sourceKind, sourcePath string) (ingest.Checkpoint, bool, error) {
	var item ingest.Checkpoint
	var lastEvent sql.NullTime
	var updated time.Time
	err := s.db.QueryRowContext(ctx, `SELECT sensor_id,source_kind,source_path,file_id,committed_offset,last_event_at,updated_at FROM ingest_checkpoints WHERE sensor_id=$1 AND source_kind=$2 AND source_path=$3`, s.sensorID, sourceKind, sourcePath).Scan(&item.SensorID, &item.SourceKind, &item.SourcePath, &item.FileID, &item.Offset, &lastEvent, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return ingest.Checkpoint{}, false, nil
	}
	if err != nil {
		return ingest.Checkpoint{}, false, err
	}
	if lastEvent.Valid {
		item.LastEventAt = lastEvent.Time.UTC().Format(time.RFC3339Nano)
	}
	item.UpdatedAt = updated.UTC().Format(time.RFC3339Nano)
	return item, true, nil
}

func (s *PostgresStore) BeginIngestBatch(ctx context.Context, item ingest.Batch) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ingest_batches(batch_id,sensor_id,source_kind,source_path,file_id,start_offset,end_offset,checksum,status,event_count,malformed_count,last_error,started_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'started',0,0,NULL,$9) ON CONFLICT(batch_id) DO UPDATE SET status='started',last_error=NULL,started_at=EXCLUDED.started_at`, item.BatchID, item.SensorID, item.SourceKind, item.SourcePath, item.FileID, item.StartOffset, item.EndOffset, item.Checksum, item.StartedAt)
	return err
}

func (s *PostgresStore) CommitIngestBatch(ctx context.Context, item ingest.Batch, lastEventAt string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE ingest_batches SET status='committed',event_count=$2,malformed_count=$3,last_error=NULL,committed_at=$4 WHERE batch_id=$1`, item.BatchID, item.EventCount, item.Malformed, item.CommittedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ingest_checkpoints(sensor_id,source_kind,source_path,file_id,committed_offset,last_event_at,updated_at) VALUES($1,$2,$3,$4,$5,NULLIF($6,'')::timestamptz,now()) ON CONFLICT(sensor_id,source_kind,source_path) DO UPDATE SET file_id=EXCLUDED.file_id,committed_offset=EXCLUDED.committed_offset,last_event_at=COALESCE(EXCLUDED.last_event_at,ingest_checkpoints.last_event_at),updated_at=now()`, item.SensorID, item.SourceKind, item.SourcePath, item.FileID, item.EndOffset, lastEventAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) FailIngestBatch(ctx context.Context, batchID string, cause error) error {
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE ingest_batches SET status='failed',last_error=$2 WHERE batch_id=$1`, batchID, message)
	return err
}

func (s *DBStore) LoadIngestCheckpoint(ctx context.Context, sourceKind, sourcePath string) (ingest.Checkpoint, bool, error) {
	return s.pg.LoadIngestCheckpoint(ctx, sourceKind, sourcePath)
}

func (s *DBStore) AcquireIngestSourceLease(ctx context.Context, sourceKind, sourcePath string) (func(), error) {
	return s.pg.AcquireIngestSourceLease(ctx, sourceKind, sourcePath)
}

func (s *DBStore) BeginIngestBatch(ctx context.Context, item ingest.Batch) error {
	return s.pg.BeginIngestBatch(ctx, item)
}

func (s *DBStore) CommitIngestBatch(ctx context.Context, item ingest.Batch, lastEventAt string) error {
	return s.pg.CommitIngestBatch(ctx, item, lastEventAt)
}

func (s *DBStore) FailIngestBatch(ctx context.Context, batchID string, cause error) error {
	return s.pg.FailIngestBatch(ctx, batchID, cause)
}

func (s *DBStore) Close() error {
	s.domainOnce.Do(func() {})
	if s.domainCancel != nil {
		s.domainCancel()
		<-s.domainDone
	}
	return s.pg.Close()
}
