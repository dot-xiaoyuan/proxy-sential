SET LOCAL lock_timeout = '5s';

-- An explicitly abandoned snapshot remains unprocessed. Keep the job, its
-- unique full document, original hash and metadata until a separately audited
-- retirement; new snapshots continue through the ordinary projector.
CREATE TABLE identity_snapshot_projection_cancellations (
 source text NOT NULL,
 sensor_id text NOT NULL,
 campus_id text NOT NULL,
 access_domain text NOT NULL,
 snapshot_id text NOT NULL,
 new_epoch text NOT NULL REFERENCES identity_fresh_recovery_gaps(new_epoch),
 cutover_at timestamptz NOT NULL,
 observed_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL CHECK(received_at<cutover_at),
 content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[0-9a-f]{64}$'),
 state text NOT NULL DEFAULT 'cancelled_unprocessed' CHECK(state='cancelled_unprocessed'),
 reason text NOT NULL CHECK(reason<>''),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,snapshot_id),
 FOREIGN KEY(source,sensor_id,campus_id,access_domain,snapshot_id)
  REFERENCES identity_snapshot_projection_jobs(source,sensor_id,campus_id,access_domain,snapshot_id),
 FOREIGN KEY(source,sensor_id,campus_id,access_domain,snapshot_id)
  REFERENCES identity_full_snapshots(source,sensor_id,campus_id,access_domain,snapshot_id),
 FOREIGN KEY(source,sensor_id,campus_id,access_domain,snapshot_id)
  REFERENCES identity_snapshot_log(source,sensor_id,campus_id,access_domain,snapshot_id)
);
CREATE INDEX identity_snapshot_projection_cancellations_scope_time
 ON identity_snapshot_projection_cancellations(sensor_id,received_at);

CREATE FUNCTION identity_snapshot_projection_cancellation_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'identity snapshot cancellation audit is immutable';
END $$;
CREATE TRIGGER identity_snapshot_projection_cancellations_immutable
 BEFORE UPDATE OR DELETE ON identity_snapshot_projection_cancellations
 FOR EACH ROW EXECUTE FUNCTION identity_snapshot_projection_cancellation_immutable();

-- The FKs reject deletion too. Guard mutable values as well: a later hash,
-- document or projected-flag edit must not rewrite cancelled evidence.
CREATE FUNCTION retain_cancelled_identity_snapshot_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM identity_snapshot_projection_cancellations c
           WHERE c.source=OLD.source AND c.sensor_id=OLD.sensor_id
             AND c.campus_id=OLD.campus_id AND c.access_domain=OLD.access_domain
             AND c.snapshot_id=OLD.snapshot_id) THEN
  RAISE EXCEPTION 'cancelled identity snapshot evidence must remain unchanged';
 END IF;
 IF TG_OP='UPDATE' THEN RETURN NEW; END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER identity_snapshot_projection_job_cancel_guard
 BEFORE UPDATE OR DELETE ON identity_snapshot_projection_jobs
 FOR EACH ROW EXECUTE FUNCTION retain_cancelled_identity_snapshot_evidence();
CREATE TRIGGER identity_full_snapshot_cancel_guard
 BEFORE UPDATE OR DELETE ON identity_full_snapshots
 FOR EACH ROW EXECUTE FUNCTION retain_cancelled_identity_snapshot_evidence();
CREATE TRIGGER identity_snapshot_log_cancel_guard
 BEFORE UPDATE OR DELETE ON identity_snapshot_log
 FOR EACH ROW EXECUTE FUNCTION retain_cancelled_identity_snapshot_evidence();
