SET LOCAL lock_timeout = '5s';
CREATE TABLE identity_receive_progress (
 scope_key text PRIMARY KEY,accepted_sequence bigint NOT NULL,total_records bigint NOT NULL,
 accepted_at timestamptz,ip_tracking_after_sequence bigint NOT NULL
);
CREATE TABLE identity_consume_progress (
 scope_key text PRIMARY KEY,processed_sequence bigint NOT NULL,processed_records bigint NOT NULL,
 current_generation text NOT NULL,lease_epoch bigint NOT NULL,lease_until timestamptz,
 oldest_pending_at timestamptz,processed_at timestamptz,heartbeat_at timestamptz,last_error text NOT NULL DEFAULT ''
);
CREATE TABLE identity_export_progress (
 scope_key text PRIMARY KEY,exported_records bigint NOT NULL,
 export_last_error text NOT NULL DEFAULT '',export_heartbeat_at timestamptz,export_completed_at timestamptz
);
-- Bootstrap is repeated while old writers are stopped immediately before
-- enabling the compatible application's split-progress flag. Migration alone
-- never switches producers/consumers.
CREATE FUNCTION identity_initialize_split_progress() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 PERFORM scope_key FROM identity_pipeline_scopes ORDER BY scope_key FOR UPDATE;
 INSERT INTO identity_receive_progress SELECT scope_key,accepted_sequence,greatest(pending_records,export_pending_records),NULL,accepted_sequence FROM identity_pipeline_scopes
 ON CONFLICT(scope_key) DO UPDATE SET accepted_sequence=EXCLUDED.accepted_sequence,total_records=EXCLUDED.total_records,ip_tracking_after_sequence=EXCLUDED.ip_tracking_after_sequence;
 INSERT INTO identity_consume_progress SELECT scope_key,processed_sequence,greatest(pending_records,export_pending_records)-pending_records,current_generation,lease_epoch+1,NULL,oldest_pending_at,processed_at,heartbeat_at,last_error FROM identity_pipeline_scopes
 ON CONFLICT(scope_key) DO UPDATE SET processed_sequence=EXCLUDED.processed_sequence,processed_records=EXCLUDED.processed_records,current_generation=EXCLUDED.current_generation,lease_epoch=EXCLUDED.lease_epoch,lease_until=NULL,oldest_pending_at=EXCLUDED.oldest_pending_at,processed_at=EXCLUDED.processed_at,heartbeat_at=EXCLUDED.heartbeat_at,last_error=EXCLUDED.last_error;
 INSERT INTO identity_export_progress SELECT scope_key,greatest(pending_records,export_pending_records)-export_pending_records,export_last_error,export_heartbeat_at,export_completed_at FROM identity_pipeline_scopes
 ON CONFLICT(scope_key) DO UPDATE SET exported_records=EXCLUDED.exported_records,export_last_error=EXCLUDED.export_last_error,export_heartbeat_at=EXCLUDED.export_heartbeat_at,export_completed_at=EXCLUDED.export_completed_at;
END $$;
CREATE VIEW identity_pipeline_scope_status AS
SELECT (jsonb_populate_record(NULL::identity_pipeline_scopes,to_jsonb(s)||
 CASE WHEN r.scope_key IS NULL OR c.scope_key IS NULL OR e.scope_key IS NULL THEN '{}'::jsonb ELSE
 jsonb_build_object('accepted_sequence',r.accepted_sequence,'processed_sequence',c.processed_sequence,
 'pending_records',r.total_records-c.processed_records,'export_pending_records',r.total_records-e.exported_records,
 'lease_epoch',c.lease_epoch,'lease_until',c.lease_until,'oldest_pending_at',CASE WHEN r.total_records>c.processed_records THEN (SELECT b.accepted_at FROM identity_ingest_batches b WHERE b.protocol_version=2 AND b.scope_key=c.scope_key AND b.sequence=c.processed_sequence+1) END,'processed_at',c.processed_at,
 'heartbeat_at',c.heartbeat_at,'last_error',c.last_error,'export_last_error',e.export_last_error,
 'export_heartbeat_at',e.export_heartbeat_at,'export_completed_at',e.export_completed_at) END)).*
FROM identity_pipeline_scopes s LEFT JOIN identity_receive_progress r USING(scope_key)
LEFT JOIN identity_consume_progress c USING(scope_key) LEFT JOIN identity_export_progress e USING(scope_key);
CREATE FUNCTION identity_restore_legacy_progress() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 UPDATE identity_pipeline_scopes s SET accepted_sequence=v.accepted_sequence,processed_sequence=v.processed_sequence,
 pending_records=v.pending_records,export_pending_records=v.export_pending_records,lease_epoch=v.lease_epoch+1,lease_until=NULL,
 oldest_pending_at=v.oldest_pending_at,processed_at=v.processed_at,heartbeat_at=v.heartbeat_at,last_error=v.last_error,
 export_last_error=v.export_last_error,export_heartbeat_at=v.export_heartbeat_at,export_completed_at=v.export_completed_at
 FROM identity_pipeline_scope_status v WHERE s.scope_key=v.scope_key;
END $$;
