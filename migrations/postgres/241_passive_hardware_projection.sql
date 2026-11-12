-- Additive 204 asset classification contract. No trigger or default reader is
-- changed; 184 continues using its existing risk/recognition projections.
CREATE TABLE IF NOT EXISTS passive_hardware_facts (
 identity_key text NOT NULL, fact_key text NOT NULL,
 sensor_id text NOT NULL, campus_id text NOT NULL, access_domain text NOT NULL,
 vlan text NOT NULL DEFAULT '', vrf text NOT NULL DEFAULT '', mac text NOT NULL,
 device_key text NOT NULL, source text NOT NULL,
 first_seen timestamptz NOT NULL, observed_at timestamptz NOT NULL,
 active_until timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 evidence_id text NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(identity_key,fact_key), CHECK(pg_column_size(data)<=65536)
);
CREATE INDEX IF NOT EXISTS passive_hardware_facts_device ON passive_hardware_facts(device_key);
CREATE TABLE IF NOT EXISTS passive_hardware_current (
 identity_key text PRIMARY KEY, scope_key text NOT NULL, device_key text NOT NULL,
 sensor_id text NOT NULL, campus_id text NOT NULL, access_domain text NOT NULL,
 vlan text NOT NULL DEFAULT '', vrf text NOT NULL DEFAULT '', mac text NOT NULL,
 hardware_type text NOT NULL DEFAULT '', hardware_type_status text NOT NULL,
 hardware_model text NOT NULL DEFAULT '', hardware_model_status text NOT NULL DEFAULT '',
 first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
 active_until timestamptz NOT NULL, type_evidence_at timestamptz,
 type_changed_at timestamptz, address_only_since timestamptz,
 rule_version text NOT NULL DEFAULT '', result_version bigint NOT NULL DEFAULT 1,
 data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS passive_hardware_current_scope ON passive_hardware_current(sensor_id,campus_id,access_domain,vlan,vrf,last_seen DESC,identity_key);
CREATE INDEX IF NOT EXISTS passive_hardware_current_type ON passive_hardware_current(hardware_type_status,hardware_type,last_seen DESC,identity_key);
CREATE TABLE IF NOT EXISTS passive_hardware_dirty (
 identity_key text PRIMARY KEY, sensor_id text NOT NULL,
 generation bigint NOT NULL DEFAULT 1, reason text NOT NULL,
 first_enqueued_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(),
 last_error text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS passive_hardware_dirty_ready ON passive_hardware_dirty(sensor_id,next_attempt_at,first_enqueued_at,identity_key);
CREATE TABLE IF NOT EXISTS passive_hardware_rule_dependencies (
 rule_id text NOT NULL, rule_version text NOT NULL, identity_key text NOT NULL,
 PRIMARY KEY(rule_id,rule_version,identity_key)
);
CREATE INDEX IF NOT EXISTS passive_hardware_dependencies_identity ON passive_hardware_rule_dependencies(identity_key);
-- Compact state changes survive evidence expiry/archival; immutable event IDs
-- continue referencing the single authoritative source. Never retain raw XML.
CREATE TABLE IF NOT EXISTS passive_hardware_changes (
 id bigserial PRIMARY KEY, identity_key text NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT now(), reason text NOT NULL,
 before_type text NOT NULL, after_type text NOT NULL,
 before_status text NOT NULL, after_status text NOT NULL,
 rule_version text NOT NULL, sources jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS passive_hardware_changes_identity ON passive_hardware_changes(identity_key,id DESC);
