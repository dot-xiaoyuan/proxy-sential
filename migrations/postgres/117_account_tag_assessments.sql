CREATE TABLE IF NOT EXISTS account_tag_projection_jobs (
  account_id TEXT PRIMARY KEY,
  dirty_generation BIGINT NOT NULL DEFAULT 1,
  processed_generation BIGINT NOT NULL DEFAULT 0,
  not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS account_tag_projection_jobs_claim
ON account_tag_projection_jobs(not_before, updated_at, account_id)
WHERE dirty_generation > processed_generation;

CREATE TABLE IF NOT EXISTS account_tag_assessments (
  account_id TEXT NOT NULL,
  tag_type TEXT NOT NULL CHECK (tag_type IN ('proxy','router','mobile','pc')),
  assessment_version TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('current','historical')),
  evidence_level TEXT NOT NULL CHECK (evidence_level IN ('confirmed','likely','clue')),
  source_type TEXT NOT NULL,
  reason TEXT NOT NULL,
  endpoint_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  rule_version TEXT NOT NULL DEFAULT '',
  raw_score DOUBLE PRECISION NOT NULL DEFAULT 0,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  valid_until TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(account_id, tag_type)
);

CREATE INDEX IF NOT EXISTS account_tag_assessments_list
ON account_tag_assessments(state, tag_type, last_seen DESC, account_id);

CREATE TABLE IF NOT EXISTS account_tag_assessment_history (
  history_id BIGSERIAL PRIMARY KEY,
  account_id TEXT NOT NULL,
  tag_type TEXT NOT NULL CHECK (tag_type IN ('proxy','router','mobile','pc')),
  assessment_version TEXT NOT NULL,
  state TEXT NOT NULL,
  evidence_level TEXT NOT NULL,
  source_type TEXT NOT NULL,
  reason TEXT NOT NULL,
  endpoint_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  rule_version TEXT NOT NULL DEFAULT '',
  raw_score DOUBLE PRECISION NOT NULL DEFAULT 0,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  valid_until TIMESTAMPTZ NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS account_tag_assessment_history_account
ON account_tag_assessment_history(account_id, recorded_at DESC, history_id DESC);

CREATE UNIQUE INDEX IF NOT EXISTS account_tag_assessment_history_version
ON account_tag_assessment_history(account_id, tag_type, assessment_version);

CREATE TABLE IF NOT EXISTS account_tag_reviews (
  review_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  tag_type TEXT NOT NULL CHECK (tag_type IN ('proxy','router','mobile','pc')),
  assessment_version TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('confirm','reject')),
  reason TEXT NOT NULL,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS account_tag_reviews_version
ON account_tag_reviews(account_id, tag_type, assessment_version);

CREATE TABLE IF NOT EXISTS account_tag_projection_runtime (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
  last_success_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  processed_jobs BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO account_tag_projection_runtime(singleton) VALUES(true) ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION enqueue_account_tag_projection(value TEXT) RETURNS void AS $$
BEGIN
  IF value IS NULL OR btrim(value) = '' THEN RETURN; END IF;
  INSERT INTO account_tag_projection_jobs(account_id) VALUES(value)
  ON CONFLICT(account_id) DO UPDATE SET dirty_generation=account_tag_projection_jobs.dirty_generation+1,not_before=now(),updated_at=now();
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION queue_account_tag_from_session() RETURNS trigger AS $$
BEGIN
  PERFORM enqueue_account_tag_projection(CASE WHEN TG_OP='DELETE' THEN OLD.account_id ELSE NEW.account_id END);
  IF TG_OP='UPDATE' AND OLD.account_id IS DISTINCT FROM NEW.account_id THEN PERFORM enqueue_account_tag_projection(OLD.account_id); END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS account_tag_session_queue ON account_sessions;
CREATE TRIGGER account_tag_session_queue AFTER INSERT OR UPDATE OR DELETE ON account_sessions FOR EACH ROW EXECUTE FUNCTION queue_account_tag_from_session();

CREATE OR REPLACE FUNCTION queue_account_tag_from_endpoint() RETURNS trigger AS $$
DECLARE row RECORD;
BEGIN
  FOR row IN SELECT DISTINCT account_id FROM account_sessions
    WHERE endpoint_id=(CASE WHEN TG_OP='DELETE' THEN OLD.endpoint_id ELSE NEW.endpoint_id END) AND account_id<>'' LOOP
    PERFORM enqueue_account_tag_projection(row.account_id);
  END LOOP;
  IF TG_OP='UPDATE' AND OLD.endpoint_id IS DISTINCT FROM NEW.endpoint_id THEN
    FOR row IN SELECT DISTINCT account_id FROM account_sessions WHERE endpoint_id=OLD.endpoint_id AND account_id<>'' LOOP
      PERFORM enqueue_account_tag_projection(row.account_id);
    END LOOP;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS account_tag_endpoint_queue ON endpoint_device_profiles;
CREATE TRIGGER account_tag_endpoint_queue AFTER INSERT OR UPDATE OR DELETE ON endpoint_device_profiles FOR EACH ROW EXECUTE FUNCTION queue_account_tag_from_endpoint();

CREATE OR REPLACE FUNCTION queue_account_tag_from_risk() RETURNS trigger AS $$
BEGIN
  PERFORM enqueue_account_tag_projection(CASE WHEN TG_OP='DELETE' THEN OLD.account_id ELSE NEW.account_id END);
  IF TG_OP='UPDATE' AND OLD.account_id IS DISTINCT FROM NEW.account_id THEN PERFORM enqueue_account_tag_projection(OLD.account_id); END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS account_tag_risk_queue ON subject_risk_snapshots;
CREATE TRIGGER account_tag_risk_queue AFTER INSERT OR UPDATE OR DELETE ON subject_risk_snapshots FOR EACH ROW EXECUTE FUNCTION queue_account_tag_from_risk();

CREATE OR REPLACE FUNCTION queue_account_tag_from_router() RETURNS trigger AS $$
DECLARE binding JSONB;
BEGIN
  FOR binding IN SELECT value FROM jsonb_array_elements(COALESCE((CASE WHEN TG_OP='DELETE' THEN OLD.assessment ELSE NEW.assessment END)->'auth_bindings','[]'::jsonb)) LOOP
    IF COALESCE((binding->>'ambiguous')::boolean,false)=false AND binding->>'match_basis' IN('exact_endpoint','exact_mac') THEN
      PERFORM enqueue_account_tag_projection(binding->>'account_id');
    END IF;
  END LOOP;
  IF TG_OP='UPDATE' AND OLD.assessment IS DISTINCT FROM NEW.assessment THEN
    FOR binding IN SELECT value FROM jsonb_array_elements(COALESCE(OLD.assessment->'auth_bindings','[]'::jsonb)) LOOP
      IF COALESCE((binding->>'ambiguous')::boolean,false)=false AND binding->>'match_basis' IN('exact_endpoint','exact_mac') THEN
        PERFORM enqueue_account_tag_projection(binding->>'account_id');
      END IF;
    END LOOP;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS account_tag_router_queue ON router_assessments;
CREATE TRIGGER account_tag_router_queue AFTER INSERT OR UPDATE OR DELETE ON router_assessments FOR EACH ROW EXECUTE FUNCTION queue_account_tag_from_router();

INSERT INTO account_tag_projection_jobs(account_id)
SELECT DISTINCT account_id FROM account_sessions WHERE account_id<>''
ON CONFLICT DO NOTHING;
