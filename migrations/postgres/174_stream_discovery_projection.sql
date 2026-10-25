-- Fresh stream projection is isolated from legacy discovery work. These rows
-- contain narrow facts and locators; event bodies remain authoritative in CH.
CREATE TABLE stream_projection_segments (
 segment_id text PRIMARY KEY,
 epoch text NOT NULL,
 source_kind text NOT NULL,
 source_path text NOT NULL,
 content_sha256 text NOT NULL,
 accepted_at timestamptz NOT NULL,
 event_count integer NOT NULL CHECK(event_count>=0),
 projected_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX stream_projection_segments_epoch ON stream_projection_segments(epoch,projected_at DESC);

-- Compact global key ledger prevents a fixed source event from being applied
-- twice when an unknown outcome is retried after a month boundary.
CREATE TABLE stream_discovery_event_keys (
 epoch text NOT NULL,
 scope_id text NOT NULL,
 event_key text NOT NULL,
 content_sha256 text NOT NULL,
 accepted_month date NOT NULL,
 first_accepted_at timestamptz NOT NULL,
 PRIMARY KEY(epoch,scope_id,event_key)
);
CREATE INDEX stream_discovery_event_keys_retention ON stream_discovery_event_keys(first_accepted_at);

CREATE TABLE stream_discovery_receipts (
 accepted_month date NOT NULL,
 epoch text NOT NULL,
 scope_id text NOT NULL,
 event_key text NOT NULL,
 content_sha256 text NOT NULL,
 accepted_at timestamptz NOT NULL,
 projected_at timestamptz NOT NULL DEFAULT now(),
 result text NOT NULL,
 body_ref jsonb NOT NULL,
 archive_state text NOT NULL DEFAULT 'pending' CHECK(archive_state IN ('pending','confirmed','verified','failed')),
 archive_confirmed_at timestamptz,
 PRIMARY KEY(accepted_month,epoch,scope_id,event_key)
) PARTITION BY RANGE(accepted_month);
DO $$
DECLARE month_start date; month_end date; part text;
BEGIN
 FOR month_offset IN -2..2 LOOP
  month_start:=(date_trunc('month',now())+make_interval(months=>month_offset))::date;
  month_end:=(month_start+interval '1 month')::date;
  part:='stream_discovery_receipts_'||to_char(month_start,'YYYYMM');
  EXECUTE format('CREATE TABLE %I PARTITION OF stream_discovery_receipts FOR VALUES FROM (%L) TO (%L)',part,month_start,month_end);
 END LOOP;
END $$;
CREATE TABLE stream_discovery_receipts_default PARTITION OF stream_discovery_receipts DEFAULT;
CREATE INDEX stream_discovery_receipts_pending_by_epoch ON stream_discovery_receipts(epoch,accepted_at) WHERE archive_state='pending';

CREATE TABLE stream_discovery_facts (
 epoch text NOT NULL,
 device_key text NOT NULL,
 fact_key text NOT NULL,
 scope_id text NOT NULL,
 source_id text NOT NULL,
 protocol text NOT NULL,
 service_instance text NOT NULL,
 event_key text NOT NULL,
 visible_event_key text NOT NULL,
 revision bigint NOT NULL,
 first_observed_at timestamptz NOT NULL,
 observed_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 withdrawn boolean NOT NULL,
 semantic_hash text NOT NULL,
 ip text NOT NULL,
 mac text NOT NULL,
 name text NOT NULL,
 manufacturer text NOT NULL,
 model_name text NOT NULL,
 device_type text NOT NULL,
 candidate_type text NOT NULL,
 candidate_reason text NOT NULL,
 excluded boolean NOT NULL,
 capabilities text[] NOT NULL DEFAULT '{}',
 address_binding boolean NOT NULL DEFAULT false,
 sensor_id text NOT NULL,
 site text NOT NULL,
 domain text NOT NULL,
 vlan text NOT NULL,
 vrf text NOT NULL,
 interface_name text NOT NULL,
 PRIMARY KEY(epoch,device_key,fact_key)
);
CREATE INDEX stream_discovery_facts_active ON stream_discovery_facts(epoch,device_key,valid_until DESC) WHERE NOT withdrawn;
CREATE INDEX stream_discovery_facts_recent ON stream_discovery_facts(epoch,device_key,observed_at DESC,event_key);
CREATE INDEX stream_discovery_facts_expiry ON stream_discovery_facts(valid_until,epoch,device_key) WHERE NOT withdrawn;
CREATE INDEX stream_discovery_facts_protocol ON stream_discovery_facts(epoch,protocol,device_key);
CREATE INDEX stream_discovery_facts_ip ON stream_discovery_facts(epoch,ip,device_key) WHERE ip<>'';
CREATE INDEX stream_discovery_facts_mac ON stream_discovery_facts(epoch,mac,device_key) WHERE mac<>'';

CREATE SEQUENCE stream_discovery_result_version;
CREATE TABLE stream_discovery_device_state (
 epoch text NOT NULL,
 device_key text NOT NULL,
 scope_id text NOT NULL,
 sensor_id text NOT NULL,
 site text NOT NULL,
 domain text NOT NULL,
 vlan text NOT NULL,
 interface_name text NOT NULL,
 name text NOT NULL DEFAULT '',
 manufacturer text NOT NULL DEFAULT '',
 model_name text NOT NULL DEFAULT '',
 device_type text NOT NULL DEFAULT '',
 category text NOT NULL DEFAULT '',
 last_device_type text NOT NULL DEFAULT '',
 last_category text NOT NULL DEFAULT '',
 classification_status text NOT NULL DEFAULT 'candidate',
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 expires_at timestamptz,
 result_version bigint NOT NULL DEFAULT nextval('stream_discovery_result_version'),
 document jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(epoch,device_key)
);
CREATE INDEX stream_discovery_state_page ON stream_discovery_device_state(scope_id,last_seen DESC,device_key);
CREATE INDEX stream_discovery_state_iot_page ON stream_discovery_device_state(scope_id,last_seen DESC,device_key) WHERE classification_status IN ('identified','expired','conflict');
CREATE INDEX stream_discovery_state_expiry ON stream_discovery_device_state(expires_at,epoch,device_key) WHERE expires_at IS NOT NULL;
CREATE INDEX stream_discovery_state_legacy_match ON stream_discovery_device_state(device_key,epoch);
CREATE INDEX stream_discovery_state_epoch_version ON stream_discovery_device_state(epoch,result_version DESC);

-- Compatibility A can read B's isolated fresh states. A legacy conclusion is
-- visible but stale after the first active cutover until that device is seen
-- again; the new generation takes precedence for the same scoped device key.
CREATE VIEW discovery_device_state_read AS
 SELECT s.device_key,s.last_seen,s.result_version,s.name,s.manufacturer,s.model_name,
  s.last_device_type,s.last_category,s.classification_status,s.domain,s.vlan,
  s.epoch,'fresh'::text AS generation,
  s.document||jsonb_build_object('generation','fresh','freshness','new') AS document
 FROM stream_discovery_device_state s
 WHERE EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.epoch=s.epoch AND c.state='active')
 UNION ALL
 SELECT l.device_key,l.last_seen,l.result_version,l.name,l.manufacturer,l.model_name,
  l.last_device_type,l.last_category,l.classification_status,l.domain,l.vlan,
  ''::text AS epoch,'legacy'::text AS generation,
  l.document||jsonb_build_object('generation','legacy','freshness',
   CASE WHEN EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.state='active') THEN 'stale' ELSE 'legacy' END) AS document
 FROM discovery_device_state_v2 l
 WHERE NOT EXISTS(SELECT 1 FROM stream_discovery_device_state s
  WHERE s.device_key=l.device_key AND EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.epoch=s.epoch AND c.state='active'));

CREATE TABLE stream_discovery_changes (
 change_id bigserial PRIMARY KEY,
 epoch text NOT NULL,
 device_key text NOT NULL,
 event_key text NOT NULL,
 accepted_at timestamptz NOT NULL,
 observed_at timestamptz NOT NULL,
 change_kind text NOT NULL,
 before_hash text NOT NULL,
 after_hash text NOT NULL,
 body_ref jsonb NOT NULL,
 protected boolean NOT NULL DEFAULT false
);
CREATE INDEX stream_discovery_changes_device_page ON stream_discovery_changes(epoch,device_key,change_id DESC);
CREATE INDEX stream_discovery_changes_retention ON stream_discovery_changes(accepted_at) WHERE NOT protected;
