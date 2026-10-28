-- Candidate only: not part of the migration sequence until concurrency and
-- rollback behavior have been verified against an isolated PostgreSQL server.
CREATE TABLE identity_derived_ready (
 batch_id text NOT NULL,
 first_ordinal integer NOT NULL,
 sensor_id text NOT NULL,
 accepted_at timestamptz NOT NULL,
 priority smallint NOT NULL CHECK(priority IN (0,1)),
 available_at timestamptz NOT NULL DEFAULT '-infinity',
 PRIMARY KEY(batch_id,first_ordinal),
 FOREIGN KEY(batch_id,first_ordinal) REFERENCES identity_ingest_fragments(batch_id,first_ordinal)
);
CREATE INDEX identity_derived_ready_claim ON identity_derived_ready(sensor_id,priority,available_at,accepted_at,batch_id,first_ordinal);
CREATE TABLE identity_derived_ready_scan (
 id boolean PRIMARY KEY DEFAULT true CHECK(id),
 cursor_batch text NOT NULL DEFAULT '',
 cursor_ordinal integer NOT NULL DEFAULT -1,
 done boolean NOT NULL DEFAULT false
);
INSERT INTO identity_derived_ready_scan(id) VALUES(true);

CREATE FUNCTION identity_derived_ready_on_progress() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.protocol_version=2 AND NEW.payload_format='fragments' AND NEW.processed_offset>OLD.processed_offset THEN
  INSERT INTO identity_derived_ready(batch_id,first_ordinal,sensor_id,accepted_at,priority)
  SELECT NEW.batch_id,f.first_ordinal,NEW.sensor_id,COALESCE(NEW.accepted_at,NEW.received_at),0
  FROM identity_ingest_fragments f
  WHERE f.batch_id=NEW.batch_id
    AND f.first_ordinal>=greatest(0,OLD.processed_offset-49)
    AND f.first_ordinal<NEW.processed_offset
    AND f.first_ordinal+f.record_count>OLD.processed_offset
    AND f.first_ordinal+f.record_count<=NEW.processed_offset
    AND f.derived_state IN ('pending','attempted')
  ON CONFLICT(batch_id,first_ordinal) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_derived_ready_on_progress AFTER UPDATE OF processed_offset ON identity_ingest_batches
 FOR EACH ROW EXECUTE FUNCTION identity_derived_ready_on_progress();

CREATE FUNCTION identity_derived_ready_on_terminal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.derived_state IN ('completed','failed') THEN
  DELETE FROM identity_derived_ready WHERE batch_id=NEW.batch_id AND first_ordinal=NEW.first_ordinal;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_derived_ready_on_terminal AFTER UPDATE OF derived_state ON identity_ingest_fragments
 FOR EACH ROW EXECUTE FUNCTION identity_derived_ready_on_terminal();
