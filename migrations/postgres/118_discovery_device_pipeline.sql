-- Discovery payloads/tasks extend the existing ingest batch ledger. No second
-- source checkpoint is advanced; batch confirmation and task progress stay linked.
CREATE TABLE discovery_batch_work (
 batch_id text PRIMARY KEY REFERENCES ingest_batches(batch_id),
 events jsonb NOT NULL,
 lane text NOT NULL DEFAULT 'realtime' CHECK(lane IN ('realtime','backfill','rules')),
 processed_offset integer NOT NULL DEFAULT 0,
 archived boolean NOT NULL DEFAULT false,
 completed boolean NOT NULL DEFAULT false,
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 attempts integer NOT NULL DEFAULT 0,
 error text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 completed_at timestamptz
);
CREATE INDEX discovery_batch_oldest ON discovery_batch_work(created_at) WHERE NOT completed;
CREATE INDEX discovery_batch_completed ON discovery_batch_work(completed_at DESC) WHERE completed;
CREATE INDEX discovery_batch_pending ON discovery_batch_work(lane,next_attempt_at,created_at) WHERE NOT completed;
CREATE SEQUENCE discovery_result_version;
CREATE TABLE discovery_event_receipts (
 sensor_id text NOT NULL, source_id text NOT NULL,
 event_id text NOT NULL, revision bigint NOT NULL DEFAULT 0,
 content_hash text NOT NULL, batch_id text NOT NULL REFERENCES ingest_batches(batch_id),
 accepted_at timestamptz NOT NULL, applied_at timestamptz NOT NULL DEFAULT now(),
 result text NOT NULL, PRIMARY KEY(sensor_id,source_id,event_id,revision)
);
CREATE TABLE discovery_service_facts_v2 (
 device_key text NOT NULL, fact_key text NOT NULL,
 sensor_id text NOT NULL, domain text NOT NULL, vlan text NOT NULL, interface_name text NOT NULL,
 source_id text NOT NULL, protocol text NOT NULL, service_instance text NOT NULL,
 ip text NOT NULL, mac text NOT NULL,
 event_id text NOT NULL, revision bigint NOT NULL DEFAULT 0,
 observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL, withdrawn boolean NOT NULL,
 observation jsonb NOT NULL, content_hash text NOT NULL,
 PRIMARY KEY(device_key,fact_key)
);
CREATE INDEX discovery_facts_expiry ON discovery_service_facts_v2(valid_until,device_key) WHERE NOT withdrawn;
CREATE INDEX discovery_facts_ip ON discovery_service_facts_v2(ip,device_key);
CREATE INDEX discovery_facts_mac ON discovery_service_facts_v2(mac,device_key) WHERE mac<>'';
CREATE TABLE discovery_device_state_v2 (
 device_key text PRIMARY KEY, sensor_id text NOT NULL, domain text NOT NULL, vlan text NOT NULL,
 interface_name text NOT NULL, name text NOT NULL DEFAULT '', manufacturer text NOT NULL DEFAULT '', model_name text NOT NULL DEFAULT '',
 device_type text NOT NULL DEFAULT '', category text NOT NULL DEFAULT '',
 last_device_type text NOT NULL DEFAULT '', last_category text NOT NULL DEFAULT '',
 classification_status text NOT NULL DEFAULT 'candidate',
 first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
 expires_at timestamptz, result_version bigint NOT NULL DEFAULT nextval('discovery_result_version'),
 document jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX discovery_state_version ON discovery_device_state_v2(result_version DESC);
CREATE INDEX discovery_state_page ON discovery_device_state_v2(last_seen DESC,device_key);
CREATE INDEX discovery_state_iot_page ON discovery_device_state_v2(last_seen DESC,device_key) WHERE classification_status IN ('identified','expired','conflict');
CREATE INDEX discovery_state_category_page ON discovery_device_state_v2(last_category,last_seen DESC,device_key);
CREATE INDEX discovery_state_expiry ON discovery_device_state_v2(expires_at,device_key) WHERE expires_at IS NOT NULL;
CREATE INDEX discovery_state_name ON discovery_device_state_v2 USING gin (lower(name) gin_trgm_ops);
CREATE INDEX discovery_state_model ON discovery_device_state_v2 USING gin (lower(model_name) gin_trgm_ops);
CREATE INDEX discovery_state_manufacturer ON discovery_device_state_v2 USING gin (lower(manufacturer) gin_trgm_ops);
CREATE TABLE discovery_device_changes_v2 (
 change_id bigserial, device_key text NOT NULL, event_id text NOT NULL,
 ingested_at timestamptz NOT NULL, observed_at timestamptz NOT NULL,
 change_kind text NOT NULL, document jsonb NOT NULL,
 archive_verified_at timestamptz, protected boolean NOT NULL DEFAULT false,
 PRIMARY KEY(ingested_at,change_id)
) PARTITION BY RANGE(ingested_at);
DO $$ DECLARE start_at timestamptz; end_at timestamptz; part text; BEGIN
 FOR month_offset IN -2..2 LOOP
  start_at:=date_trunc('month',now())+make_interval(months=>month_offset);end_at:=start_at+interval '1 month';part:='discovery_changes_'||to_char(start_at,'YYYYMM');
  EXECUTE format('CREATE TABLE %I PARTITION OF discovery_device_changes_v2 FOR VALUES FROM (%L) TO (%L)',part,start_at,end_at);
 END LOOP;
END $$;
CREATE TABLE discovery_changes_default PARTITION OF discovery_device_changes_v2 DEFAULT;
CREATE INDEX discovery_changes_device_page ON discovery_device_changes_v2(device_key,change_id DESC);
CREATE INDEX discovery_changes_archive ON discovery_device_changes_v2(ingested_at,change_id) WHERE archive_verified_at IS NULL;
CREATE TABLE discovery_protocol_runtime (
 sensor_id text NOT NULL, protocol text NOT NULL, owner text NOT NULL DEFAULT 'discovery-worker',enabled boolean NOT NULL DEFAULT false,
 received bigint NOT NULL DEFAULT 0, parsed bigint NOT NULL DEFAULT 0, rejected bigint NOT NULL DEFAULT 0,
 admitted bigint NOT NULL DEFAULT 0, last_seen timestamptz, last_success timestamptz,
 error text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,protocol)
);
CREATE TABLE discovery_enrichment_work (
 device_key text NOT NULL, protocol text NOT NULL, fingerprint text NOT NULL, observation jsonb NOT NULL,
 lease_id text NOT NULL DEFAULT '', lease_until timestamptz NOT NULL DEFAULT '-infinity',
 next_attempt_at timestamptz NOT NULL DEFAULT now(), attempts integer NOT NULL DEFAULT 0,
 last_success timestamptz, error text NOT NULL DEFAULT '', PRIMARY KEY(device_key,protocol)
);
CREATE INDEX discovery_enrichment_pending ON discovery_enrichment_work(next_attempt_at,lease_until);

-- Cases own immutable copies, independent of hot/ordinary archive expiry.
CREATE TABLE discovery_case_evidence_v2 (
 case_id text NOT NULL REFERENCES risk_cases(case_id), event_id text NOT NULL,
 sensor_id text NOT NULL, source_id text NOT NULL, revision bigint NOT NULL,
 document jsonb NOT NULL, captured_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(case_id,sensor_id,source_id,event_id,revision)
);
CREATE FUNCTION sentinel_protect_discovery_case_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ref jsonb; receipt discovery_event_receipts%ROWTYPE; original jsonb;
BEGIN
 IF NEW.evidence ? 'discovery_evidence_refs' THEN
  IF jsonb_typeof(NEW.evidence->'discovery_evidence_refs') <> 'array' OR jsonb_array_length(NEW.evidence->'discovery_evidence_refs')>100 THEN RAISE EXCEPTION 'invalid discovery evidence references'; END IF;
  FOR ref IN SELECT value FROM jsonb_array_elements(NEW.evidence->'discovery_evidence_refs') LOOP
   SELECT * INTO STRICT receipt FROM discovery_event_receipts WHERE sensor_id=ref->>'sensor_id' AND source_id=ref->>'source_id' AND event_id=ref->>'event_id' AND revision=(ref->>'revision')::bigint;
   SELECT item INTO original FROM discovery_batch_work w CROSS JOIN LATERAL jsonb_array_elements(w.events) item WHERE w.batch_id=receipt.batch_id AND item->>'event_id'=receipt.event_id AND coalesce((item->'payload'->>'revision')::bigint,0)=receipt.revision AND item->'observer'->>'sensor_id'=receipt.sensor_id AND coalesce(item->'observer'->>'source_id',item->>'source')=receipt.source_id LIMIT 1;
   IF original IS NULL THEN RAISE EXCEPTION 'discovery original evidence unavailable'; END IF;
   INSERT INTO discovery_case_evidence_v2(case_id,event_id,sensor_id,source_id,revision,document) VALUES(NEW.case_id,receipt.event_id,receipt.sensor_id,receipt.source_id,receipt.revision,original) ON CONFLICT DO NOTHING;
   UPDATE discovery_device_changes_v2 SET protected=true WHERE event_id=receipt.event_id AND document->'evidence'->'observer'->>'sensor_id'=receipt.sensor_id AND coalesce(document->'evidence'->'observer'->>'source_id',document->'evidence'->>'source')=receipt.source_id;
  END LOOP;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER protect_discovery_case_evidence AFTER INSERT OR UPDATE OF evidence ON risk_case_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION sentinel_protect_discovery_case_evidence();
CREATE TABLE discovery_state_counts(device_type text NOT NULL,state text NOT NULL,count bigint NOT NULL CHECK(count>=0),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(device_type,state));
CREATE TABLE discovery_count_deltas(id bigserial PRIMARY KEY,device_type text NOT NULL,state text NOT NULL,delta integer NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE FUNCTION sentinel_discovery_count_delta() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.last_device_type=NEW.last_device_type AND OLD.classification_status=NEW.classification_status THEN RETURN NEW; END IF;
 IF TG_OP IN ('UPDATE','DELETE') THEN INSERT INTO discovery_count_deltas(device_type,state,delta) VALUES(OLD.last_device_type,OLD.classification_status,-1); END IF;
 IF TG_OP IN ('INSERT','UPDATE') THEN INSERT INTO discovery_count_deltas(device_type,state,delta) VALUES(NEW.last_device_type,NEW.classification_status,1); END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER discovery_count_delta AFTER INSERT OR UPDATE OR DELETE ON discovery_device_state_v2 FOR EACH ROW EXECUTE FUNCTION sentinel_discovery_count_delta();
CREATE TABLE discovery_rebuild_progress(job text PRIMARY KEY, last_key text NOT NULL DEFAULT '', completed boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(),error text NOT NULL DEFAULT '');
