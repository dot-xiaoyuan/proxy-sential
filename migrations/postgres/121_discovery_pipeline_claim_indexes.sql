-- Current freshness never scans retained ingest history. The two timestamps
-- below are a compact rollup; pending gaps remain in discovery_batch_work.
CREATE TABLE discovery_pipeline_watermark (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 ingested_at timestamptz,
 processed_at timestamptz
);
INSERT INTO discovery_pipeline_watermark(singleton,ingested_at,processed_at)
SELECT true,max(b.committed_at),max(w.completed_at)
FROM discovery_batch_work w JOIN ingest_batches b USING(batch_id);

CREATE FUNCTION sentinel_discovery_watermark() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='ingest_batches' THEN
  IF NEW.committed_at IS NOT NULL AND EXISTS(SELECT 1 FROM discovery_batch_work WHERE batch_id=NEW.batch_id) THEN
   UPDATE discovery_pipeline_watermark SET ingested_at=greatest(ingested_at,NEW.committed_at) WHERE singleton;
  END IF;
 ELSE
  IF NEW.completed_at IS NOT NULL THEN
   UPDATE discovery_pipeline_watermark SET processed_at=greatest(processed_at,NEW.completed_at) WHERE singleton;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER discovery_ingest_watermark AFTER UPDATE OF committed_at ON ingest_batches
 FOR EACH ROW EXECUTE FUNCTION sentinel_discovery_watermark();
CREATE TRIGGER discovery_processed_watermark AFTER UPDATE OF completed_at ON discovery_batch_work
 FOR EACH ROW EXECUTE FUNCTION sentinel_discovery_watermark();
-- One extra narrow partial index per failed task; no JSON/GiN write amplification.
CREATE INDEX discovery_batch_pending_error ON discovery_batch_work(created_at)
 WHERE NOT completed AND error<>'';

-- Preserve every interrupted task, offset, error and original timestamp. Old
-- work is recovered by the bounded background lane; new realtime events need
-- not wait behind pre-cutover multi-thousand-event device-signals batches.
-- Freshness continues to include these gaps and cannot report ready early.
UPDATE discovery_batch_work SET lane='backfill'
 WHERE NOT completed AND lane='realtime';
