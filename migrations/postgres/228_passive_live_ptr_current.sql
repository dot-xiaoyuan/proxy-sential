-- A small current-only lane lets trusted multicast PTR names reach endpoint
-- recognition while the full passive history cursor keeps consuming in order.
-- The receive-position cursor never advances the historical cursor. The raw
-- standard event remains authoritative in ClickHouse and its archive.
CREATE TABLE passive_live_ptr_state (
 sensor_id text PRIMARY KEY,
 start_received_at timestamptz NOT NULL,
 cursor_received_at timestamptz NOT NULL,
 cursor_event_id text NOT NULL DEFAULT '',
 lease_owner text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 processed_events bigint NOT NULL DEFAULT 0,
 candidate_facts bigint NOT NULL DEFAULT 0,
 rejected_events bigint NOT NULL DEFAULT 0,
 last_success_at timestamptz,
 last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE passive_live_ptr_current (
 sensor_id text NOT NULL,
 site text NOT NULL,
 interface_name text NOT NULL,
 responder_ip text NOT NULL,
 endpoint_id text NOT NULL,
 record_name text NOT NULL,
 instance text NOT NULL,
 name text NOT NULL,
 event_id text NOT NULL,
 observed_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 withdrawn boolean NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,site,interface_name,responder_ip,endpoint_id,record_name,instance)
);
CREATE INDEX passive_live_ptr_by_endpoint
 ON passive_live_ptr_current(endpoint_id,valid_until DESC) WHERE NOT withdrawn;
CREATE INDEX passive_live_ptr_expiry
 ON passive_live_ptr_current(valid_until) WHERE NOT withdrawn;
CREATE INDEX passive_live_ptr_retirement
 ON passive_live_ptr_current(valid_until) WHERE withdrawn;

CREATE FUNCTION enqueue_passive_live_ptr_recognition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  PERFORM mark_endpoint_recognition_dirty(OLD.endpoint_id);
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND OLD.endpoint_id=NEW.endpoint_id
    AND OLD.name=NEW.name AND OLD.withdrawn=NEW.withdrawn
    AND NOT (OLD.valid_until<=now() AND NEW.valid_until>now())
    AND (date_bin('5 minutes',OLD.observed_at,'1970-01-01'::timestamptz)=date_bin('5 minutes',NEW.observed_at,'1970-01-01'::timestamptz)
         OR NEW.valid_until<=now()) THEN
  RETURN NEW;
 END IF;
 PERFORM mark_endpoint_recognition_dirty(NEW.endpoint_id);
 IF TG_OP='UPDATE' AND OLD.endpoint_id<>NEW.endpoint_id THEN
  PERFORM mark_endpoint_recognition_dirty(OLD.endpoint_id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER passive_live_ptr_recognition_dirty
AFTER INSERT OR UPDATE OR DELETE ON passive_live_ptr_current
FOR EACH ROW EXECUTE FUNCTION enqueue_passive_live_ptr_recognition();
