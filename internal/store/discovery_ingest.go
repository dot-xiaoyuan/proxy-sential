package store

import (
	"context"
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
	raw, err := discovery.EncodeDiscoveryBatch(selected)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO discovery_batch_work(batch_id,events) VALUES($1,$2) ON CONFLICT DO NOTHING`, batch.BatchID, raw)
	return err
}
