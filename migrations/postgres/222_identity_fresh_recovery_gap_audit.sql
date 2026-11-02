SET LOCAL lock_timeout = '5s';

-- A fresh NCU inbox may start after an older scope counter whose batch bodies
-- are no longer present. This ledger keeps that discrepancy visible. It never
-- describes the old responsibility as processed or the Redis source as canceled.
CREATE TABLE identity_fresh_recovery_gaps (
 new_epoch text PRIMARY KEY,
 old_epoch text NOT NULL,
 scope_key text NOT NULL,
 old_start_offset bigint NOT NULL CHECK(old_start_offset>=0),
 accepted_sequence bigint NOT NULL CHECK(accepted_sequence>=0),
 processed_sequence bigint NOT NULL CHECK(processed_sequence>=0),
 legacy_pending_records bigint NOT NULL CHECK(legacy_pending_records>=0),
 legacy_export_pending_records bigint NOT NULL CHECK(legacy_export_pending_records>=0),
 retained_batch_count bigint NOT NULL CHECK(retained_batch_count=0),
 retained_fragment_count bigint NOT NULL CHECK(retained_fragment_count=0),
 retained_ready_count bigint NOT NULL CHECK(retained_ready_count=0),
 retained_pending_ip_count bigint NOT NULL CHECK(retained_pending_ip_count=0),
 old_legacy_cancel_id text NOT NULL,
 old_cancel_manifest_sha256 text NOT NULL,
 redis_event_list text NOT NULL CHECK(redis_event_list<>''),
 redis_processing_list text NOT NULL CHECK(redis_processing_list<>''),
 redis_source_length bigint NOT NULL CHECK(redis_source_length>=0),
 redis_processing_length bigint NOT NULL CHECK(redis_processing_length>=0),
 redis_sample_at timestamptz NOT NULL,
 redis_boundary jsonb NOT NULL CHECK(jsonb_typeof(redis_boundary)='object'),
 redis_audit_sha256 text NOT NULL CHECK(length(redis_audit_sha256)=64),
 audit_sha256 text NOT NULL CHECK(length(audit_sha256)=64),
 state text NOT NULL DEFAULT 'unverifiable_gap' CHECK(state='unverifiable_gap'),
 reason text NOT NULL CHECK(reason<>''),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 CHECK(processed_sequence<=accepted_sequence),
 UNIQUE(scope_key,old_epoch)
);
CREATE INDEX identity_fresh_recovery_gaps_scope_time
 ON identity_fresh_recovery_gaps(scope_key,recorded_at DESC);

CREATE FUNCTION identity_fresh_recovery_gap_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'identity fresh recovery gap audit is immutable';
END $$;
CREATE TRIGGER identity_fresh_recovery_gaps_immutable
 BEFORE UPDATE OR DELETE ON identity_fresh_recovery_gaps
 FOR EACH ROW EXECUTE FUNCTION identity_fresh_recovery_gap_immutable();

-- The migration 164 bootstrap UPSERT would otherwise replace the new zero
-- baseline with the retained old summary, resurrecting unavailable batches.
-- Likewise, reversing split progress would overwrite the immutable old gap.
CREATE OR REPLACE FUNCTION identity_initialize_split_progress() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 PERFORM scope_key FROM identity_pipeline_scopes ORDER BY scope_key FOR UPDATE;
 IF EXISTS(SELECT 1 FROM identity_fresh_recovery_gaps) THEN
  RAISE EXCEPTION 'identity split bootstrap is forbidden after audited fresh recovery';
 END IF;
 INSERT INTO identity_receive_progress SELECT scope_key,accepted_sequence,greatest(pending_records,export_pending_records),NULL,accepted_sequence FROM identity_pipeline_scopes
 ON CONFLICT(scope_key) DO UPDATE SET accepted_sequence=EXCLUDED.accepted_sequence,total_records=EXCLUDED.total_records,ip_tracking_after_sequence=EXCLUDED.ip_tracking_after_sequence;
 INSERT INTO identity_consume_progress SELECT scope_key,processed_sequence,greatest(pending_records,export_pending_records)-pending_records,current_generation,lease_epoch+1,NULL,oldest_pending_at,processed_at,heartbeat_at,last_error FROM identity_pipeline_scopes
 ON CONFLICT(scope_key) DO UPDATE SET processed_sequence=EXCLUDED.processed_sequence,processed_records=EXCLUDED.processed_records,current_generation=EXCLUDED.current_generation,lease_epoch=EXCLUDED.lease_epoch,lease_until=NULL,oldest_pending_at=EXCLUDED.oldest_pending_at,processed_at=EXCLUDED.processed_at,heartbeat_at=EXCLUDED.heartbeat_at,last_error=EXCLUDED.last_error;
 INSERT INTO identity_export_progress SELECT scope_key,greatest(pending_records,export_pending_records)-export_pending_records,export_last_error,export_heartbeat_at,export_completed_at FROM identity_pipeline_scopes
 ON CONFLICT(scope_key) DO UPDATE SET exported_records=EXCLUDED.exported_records,export_last_error=EXCLUDED.export_last_error,export_heartbeat_at=EXCLUDED.export_heartbeat_at,export_completed_at=EXCLUDED.export_completed_at;
END $$;

CREATE OR REPLACE FUNCTION identity_restore_legacy_progress() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 PERFORM scope_key FROM identity_pipeline_scopes ORDER BY scope_key FOR UPDATE;
 IF EXISTS(SELECT 1 FROM identity_fresh_recovery_gaps) THEN
  RAISE EXCEPTION 'legacy identity progress restore is forbidden after audited fresh recovery';
 END IF;
 UPDATE identity_pipeline_scopes s SET accepted_sequence=v.accepted_sequence,processed_sequence=v.processed_sequence,
 pending_records=v.pending_records,export_pending_records=v.export_pending_records,lease_epoch=v.lease_epoch+1,lease_until=NULL,
 oldest_pending_at=v.oldest_pending_at,processed_at=v.processed_at,heartbeat_at=v.heartbeat_at,last_error=v.last_error,
 export_last_error=v.export_last_error,export_heartbeat_at=v.export_heartbeat_at,export_completed_at=v.export_completed_at
 FROM identity_pipeline_scope_status v WHERE s.scope_key=v.scope_key;
END $$;
