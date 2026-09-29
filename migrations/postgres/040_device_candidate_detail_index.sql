CREATE INDEX IF NOT EXISTS idx_device_inventory_candidate_ids
 ON device_inventory_snapshots USING gin((inventory->'devices') jsonb_path_ops);
