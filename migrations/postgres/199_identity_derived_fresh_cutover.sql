-- Audit an explicitly requested test-environment fresh start. Widening the
-- state check is separate from its online validation in migration 200.
LOCK TABLE identity_ingest_batches,identity_ingest_fragments IN ACCESS EXCLUSIVE MODE NOWAIT;
ALTER TABLE identity_ingest_fragments DROP CONSTRAINT identity_ingest_fragments_derived_state_check;
ALTER TABLE identity_ingest_fragments ADD CONSTRAINT identity_ingest_fragments_derived_state_check
 CHECK (derived_state IN ('pending','attempted','completed','failed','cancelled')) NOT VALID;

CREATE TABLE identity_derived_fresh_starts (
 cancel_id text PRIMARY KEY,
 sensor_id text NOT NULL,
 accepted_after timestamptz NOT NULL,
 reason text NOT NULL CHECK(reason<>''),
 legacy_cursors jsonb NOT NULL DEFAULT '[]',
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(sensor_id,accepted_after)
);
CREATE TABLE identity_derived_cancelled_fragments (
 cancel_id text NOT NULL REFERENCES identity_derived_fresh_starts,
 batch_id text NOT NULL,
 first_ordinal integer NOT NULL,
 record_count integer NOT NULL CHECK(record_count BETWEEN 1 AND 50),
 content_sha256 text NOT NULL,
 accepted_at timestamptz NOT NULL,
 previous_state text NOT NULL CHECK(previous_state IN ('pending','attempted','failed')),
 previous_error text NOT NULL,
 previous_lease_epoch bigint NOT NULL,
 cancelled_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cancel_id,batch_id,first_ordinal),
 FOREIGN KEY(batch_id,first_ordinal) REFERENCES identity_ingest_fragments
);
CREATE TABLE identity_derived_cancel_progress (
 cancel_id text PRIMARY KEY REFERENCES identity_derived_fresh_starts,
 cursor_batch text NOT NULL DEFAULT '',
 cursor_ordinal integer NOT NULL DEFAULT -1,
 scanned_fragments bigint NOT NULL DEFAULT 0,
 cancelled_fragments bigint NOT NULL DEFAULT 0,
 cancelled_events bigint NOT NULL DEFAULT 0,
 done boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION prevent_identity_derived_cancel_audit_change() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'identity derived cancellation audit is immutable';
END $$;
CREATE TRIGGER identity_derived_fresh_start_immutable BEFORE UPDATE OR DELETE ON identity_derived_fresh_starts
 FOR EACH ROW EXECUTE FUNCTION prevent_identity_derived_cancel_audit_change();
CREATE TRIGGER identity_derived_cancelled_fragment_immutable BEFORE UPDATE OR DELETE ON identity_derived_cancelled_fragments
 FOR EACH ROW EXECUTE FUNCTION prevent_identity_derived_cancel_audit_change();

-- Once legacy polling is explicitly retired, a producer configuration error
-- must fail visibly before receipt, rather than accept new unconsumed JSON.
CREATE FUNCTION identity_derived_fresh_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.protocol_version<>2 OR NEW.payload_format<>'fragments') AND EXISTS(
  SELECT 1 FROM identity_derived_fresh_starts c WHERE c.sensor_id=NEW.sensor_id
   AND COALESCE(NEW.accepted_at,NEW.received_at)>=c.accepted_after
 ) THEN
  RAISE EXCEPTION 'fresh identity derivation requires durable fragments' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_derived_fresh_source_guard BEFORE INSERT ON identity_ingest_batches
 FOR EACH ROW EXECUTE FUNCTION identity_derived_fresh_source_guard();

CREATE OR REPLACE FUNCTION identity_derived_ready_on_terminal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.derived_state IN ('completed','failed','cancelled') THEN
  DELETE FROM identity_derived_ready WHERE batch_id=NEW.batch_id AND first_ordinal=NEW.first_ordinal;
 ELSIF OLD.derived_state='failed' AND NEW.derived_state IN ('pending','attempted') THEN
  INSERT INTO identity_derived_ready(batch_id,first_ordinal,sensor_id,accepted_at,priority)
  SELECT b.batch_id,NEW.first_ordinal,b.sensor_id,COALESCE(b.accepted_at,b.received_at),1
  FROM identity_ingest_batches b
  WHERE b.batch_id=NEW.batch_id AND b.protocol_version=2 AND b.payload_format='fragments'
  ON CONFLICT(batch_id,first_ordinal) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;

-- One call is one transaction: at most 128 fragment keys (6400 event
-- positions) and 128 KiB metadata. No event body, authority fact, or session
-- result is read or rebuilt. A lock conflict rolls the whole page back;
-- unlike SKIP LOCKED, it cannot advance the cursor over an unaudited gap.
CREATE FUNCTION cancel_identity_derived_page(p_cancel_id text,p_limit integer DEFAULT 128)
RETURNS TABLE(scanned integer,cancelled integer,events bigint,finished boolean)
LANGUAGE plpgsql AS $$
DECLARE
 policy identity_derived_fresh_starts;
 progress identity_derived_cancel_progress;
 page jsonb;
 next_batch text;
 next_ordinal integer;
BEGIN
 IF p_limit<1 OR p_limit>128 THEN RAISE EXCEPTION 'invalid cancellation page limit'; END IF;
 SELECT * INTO STRICT policy FROM identity_derived_fresh_starts WHERE cancel_id=p_cancel_id;
 INSERT INTO identity_derived_cancel_progress(cancel_id) VALUES(p_cancel_id) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT progress FROM identity_derived_cancel_progress WHERE cancel_id=p_cancel_id FOR UPDATE;
 IF progress.done THEN RETURN QUERY SELECT 0,0,0::bigint,true; RETURN; END IF;
 WITH keys AS MATERIALIZED (
  SELECT f.batch_id,f.first_ordinal FROM identity_ingest_fragments f
  WHERE f.derived_state<>'completed' AND (f.batch_id,f.first_ordinal)>(progress.cursor_batch,progress.cursor_ordinal)
  ORDER BY f.batch_id,f.first_ordinal LIMIT p_limit
 ) SELECT COALESCE(jsonb_agg(jsonb_build_object('batch_id',k.batch_id,'first_ordinal',k.first_ordinal)
  ORDER BY k.batch_id,k.first_ordinal),'[]'::jsonb) INTO page FROM keys k;
 IF octet_length(page::text)>131072 THEN RAISE EXCEPTION 'cancellation key page exceeds byte limit'; END IF;
 scanned:=jsonb_array_length(page);
 IF scanned=0 THEN
  UPDATE identity_derived_cancel_progress SET done=true,updated_at=now() WHERE cancel_id=p_cancel_id;
  RETURN QUERY SELECT 0,0,0::bigint,true; RETURN;
 END IF;
 PERFORM f.batch_id FROM jsonb_to_recordset(page) k(batch_id text,first_ordinal integer)
 JOIN identity_ingest_fragments f USING(batch_id,first_ordinal) JOIN identity_ingest_batches b USING(batch_id)
 WHERE b.sensor_id=policy.sensor_id AND COALESCE(b.accepted_at,b.received_at)<policy.accepted_after
 ORDER BY f.batch_id,f.first_ordinal FOR NO KEY UPDATE OF f NOWAIT;
 WITH audited AS (
  INSERT INTO identity_derived_cancelled_fragments(cancel_id,batch_id,first_ordinal,record_count,content_sha256,accepted_at,previous_state,previous_error,previous_lease_epoch)
  SELECT p_cancel_id,f.batch_id,f.first_ordinal,f.record_count,f.content_sha256,COALESCE(b.accepted_at,b.received_at),f.derived_state,f.derived_error,f.derived_lease_epoch
  FROM jsonb_to_recordset(page) k(batch_id text,first_ordinal integer)
  JOIN identity_ingest_fragments f USING(batch_id,first_ordinal) JOIN identity_ingest_batches b USING(batch_id)
  WHERE b.sensor_id=policy.sensor_id AND COALESCE(b.accepted_at,b.received_at)<policy.accepted_after
   AND f.derived_state IN ('pending','attempted','failed')
  ON CONFLICT DO NOTHING RETURNING record_count
 ) SELECT count(*)::integer,COALESCE(sum(record_count),0)::bigint INTO cancelled,events FROM audited;
 UPDATE identity_ingest_fragments f
 SET derived_state='cancelled',derived_error='cancelled_unprocessed:'||p_cancel_id,
  derived_lease_epoch=f.derived_lease_epoch+1,derived_lease_until=NULL
 FROM jsonb_to_recordset(page) k(batch_id text,first_ordinal integer)
 WHERE f.batch_id=k.batch_id AND f.first_ordinal=k.first_ordinal AND f.derived_state IN ('pending','attempted','failed')
  AND EXISTS(SELECT 1 FROM identity_derived_cancelled_fragments a
   WHERE a.cancel_id=p_cancel_id AND a.batch_id=f.batch_id AND a.first_ordinal=f.first_ordinal);
 SELECT k.batch_id,k.first_ordinal INTO next_batch,next_ordinal
 FROM jsonb_to_recordset(page) k(batch_id text,first_ordinal integer)
 ORDER BY k.batch_id DESC,k.first_ordinal DESC LIMIT 1;
 UPDATE identity_derived_cancel_progress SET cursor_batch=next_batch,cursor_ordinal=next_ordinal,
  scanned_fragments=scanned_fragments+scanned,cancelled_fragments=cancelled_fragments+cancelled,
  cancelled_events=cancelled_events+events,updated_at=now() WHERE cancel_id=p_cancel_id;
 finished:=false;
 RETURN NEXT;
END $$;
