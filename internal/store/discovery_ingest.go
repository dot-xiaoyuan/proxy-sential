package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
)

// StageDiscoveryBatch links work to the original file batch before export.
// A pending task is not eligible until that same ledger batch is committed.
func (s *DBStore) StageDiscoveryBatch(ctx context.Context, batch ingest.Batch, events []normalized.Event) error {
	if os.Getenv("PROXY_SENTINEL_DISCOVERY_V2") != "true" {
		return nil
	}
	config, err := discovery.LoadCollectionConfig(os.Getenv("PROXY_SENTINEL_DISCOVERY_CONFIG"))
	if err != nil {
		return err
	}
	selected := config.SelectEvents(events)
	if len(selected) == 0 {
		return nil
	}
	_, err = discovery.EncodeDiscoveryBatch(selected)
	if err != nil {
		return err
	}
	segments, err := discovery.EncodeDiscoverySegments(selected)
	if err != nil {
		return err
	}
	hash := discovery.DiscoveryBatchHash(selected)
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO discovery_batch_work(batch_id,events,selected_event_count,payload_sha256)
 VALUES($1,'[]'::jsonb,$2,$3) ON CONFLICT DO NOTHING`, batch.BatchID, len(selected), hash)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		if err = discovery.InsertDiscoverySegments(ctx, tx, batch.BatchID, segments); err != nil {
			return err
		}
	} else {
		var existing sql.NullString
		if err = tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM discovery_batch_work WHERE batch_id=$1`, batch.BatchID).Scan(&existing); err != nil {
			return err
		}
		if existing.Valid && existing.String != hash {
			return fmt.Errorf("discovery batch selection changed for %s", batch.BatchID)
		}
	}
	return tx.Commit()
}
