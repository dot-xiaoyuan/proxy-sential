-- Forward-only support for correcting individual facts without rebuilding a device.
ALTER TABLE endpoint_inventory_projection_deltas ADD COLUMN old_payload jsonb;
CREATE TABLE endpoint_inventory_contributions (
 endpoint_id text NOT NULL, origin_key jsonb NOT NULL,
 kind text NOT NULL, value text NOT NULL, source text NOT NULL,
 first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
 confidence double precision NOT NULL, event_id text NOT NULL DEFAULT '',
 is_session boolean NOT NULL DEFAULT false,
 PRIMARY KEY(endpoint_id,origin_key,kind,value,source)
);
CREATE INDEX inventory_contribution_first ON endpoint_inventory_contributions(endpoint_id,kind,value,source,first_seen);
CREATE INDEX inventory_contribution_latest ON endpoint_inventory_contributions(endpoint_id,kind,value,source,last_seen DESC,event_id DESC);
CREATE INDEX inventory_contribution_confidence ON endpoint_inventory_contributions(endpoint_id,kind,value,source,confidence DESC);
CREATE INDEX inventory_contribution_ip ON endpoint_inventory_contributions(endpoint_id,value,source,last_seen DESC) WHERE kind='ip' AND NOT is_session;
CREATE TABLE endpoint_inventory_projection_timers (
 endpoint_id text NOT NULL, origin_key jsonb NOT NULL, due_at timestamptz NOT NULL,
 PRIMARY KEY(endpoint_id,origin_key)
);
CREATE INDEX inventory_projection_timer_due ON endpoint_inventory_projection_timers(due_at,endpoint_id);
CREATE INDEX inventory_snapshot_fact_event ON endpoint_inventory_snapshot_facts(endpoint_id,source,event_id);
CREATE INDEX inventory_snapshot_session_key ON account_identity_session_projection((document->>'endpoint_id'),source,session_id);
CREATE INDEX inventory_association_latest ON endpoint_inventory_associations(endpoint_id,kind,last_seen DESC,value);
ALTER TABLE endpoint_inventory_projection_jobs ADD COLUMN contributions_ready boolean NOT NULL DEFAULT false;
ALTER TABLE endpoint_inventory_projection_jobs ADD COLUMN pending_since timestamptz;
UPDATE endpoint_inventory_projection_jobs SET pending_since=updated_at WHERE processed_generation<dirty_generation;
CREATE INDEX inventory_projection_pending_since ON endpoint_inventory_projection_jobs(pending_since) WHERE processed_generation<dirty_generation;
CREATE OR REPLACE FUNCTION enqueue_inventory_projection_id(id text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF coalesce(id,'')='' THEN RETURN; END IF;
 INSERT INTO endpoint_inventory_projection_jobs(endpoint_id,pending_since) VALUES(id,clock_timestamp())
 ON CONFLICT(endpoint_id) DO UPDATE SET dirty_generation=endpoint_inventory_projection_jobs.dirty_generation+1,
 not_before=now(),updated_at=now(),pending_since=coalesce(endpoint_inventory_projection_jobs.pending_since,clock_timestamp());
END $$;
CREATE OR REPLACE FUNCTION record_inventory_projection_delta() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE body jsonb; previous jsonb; endpoint text; old_endpoint text; event text;
BEGIN
 IF TG_OP<>'INSERT' THEN previous:=to_jsonb(OLD); END IF;
 body:=CASE WHEN TG_OP='DELETE' THEN previous ELSE to_jsonb(NEW) END;
 endpoint:=CASE WHEN TG_TABLE_NAME='account_identity_session_projection' THEN body->'document'->>'endpoint_id' ELSE body->>'endpoint_id' END;
 old_endpoint:=CASE WHEN TG_TABLE_NAME='account_identity_session_projection' THEN previous->'document'->>'endpoint_id' ELSE previous->>'endpoint_id' END;
 event:=coalesce(body->>'event_id',body->>'session_id',body->>'snapshot_id','');
 IF coalesce(endpoint,'')<>'' THEN
  INSERT INTO endpoint_inventory_projection_deltas(endpoint_id,source_table,operation,event_id,payload,old_payload)
  VALUES(endpoint,TG_TABLE_NAME,substr(TG_OP,1,1),event,body,previous);
 END IF;
 IF coalesce(old_endpoint,'')<>'' AND old_endpoint IS DISTINCT FROM endpoint THEN
  INSERT INTO endpoint_inventory_projection_deltas(endpoint_id,source_table,operation,event_id,payload,old_payload)
  VALUES(old_endpoint,TG_TABLE_NAME,'D',coalesce(previous->>'event_id',previous->>'session_id',''),previous,previous);
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER inventory_projection_change AFTER INSERT OR UPDATE OR DELETE ON endpoint_inventory_snapshot_facts
 FOR EACH ROW EXECUTE FUNCTION enqueue_inventory_projection();
CREATE TRIGGER inventory_projection_delta_snapshot AFTER INSERT OR UPDATE OR DELETE ON endpoint_inventory_snapshot_facts
 FOR EACH ROW EXECUTE FUNCTION record_inventory_projection_delta();
