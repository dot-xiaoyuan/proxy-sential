CREATE TABLE identity_ingest_batches(batch_id text PRIMARY KEY,sensor_id text NOT NULL,accepted_at timestamptz,received_at timestamptz NOT NULL,protocol_version integer NOT NULL DEFAULT 2,payload_format text NOT NULL DEFAULT 'fragments',processed_offset integer NOT NULL DEFAULT 1);
CREATE TABLE identity_ingest_fragments(batch_id text REFERENCES identity_ingest_batches,first_ordinal integer NOT NULL DEFAULT 0,record_count integer NOT NULL DEFAULT 1,content_sha256 text NOT NULL DEFAULT repeat('a',64),normalized_events jsonb NOT NULL DEFAULT '[{"original":"keep"}]',derived_state text NOT NULL DEFAULT 'pending',derived_error text NOT NULL DEFAULT '',derived_lease_epoch bigint NOT NULL DEFAULT 0,derived_lease_until timestamptz,PRIMARY KEY(batch_id,first_ordinal),CONSTRAINT identity_ingest_fragments_derived_state_check CHECK(derived_state IN ('pending','attempted','completed','failed')));
CREATE TABLE identity_derived_ready(batch_id text,first_ordinal integer,sensor_id text,accepted_at timestamptz,priority integer NOT NULL DEFAULT 0,available_at timestamptz NOT NULL DEFAULT '-infinity',last_error text NOT NULL DEFAULT '',PRIMARY KEY(batch_id,first_ordinal));
INSERT INTO identity_ingest_batches(batch_id,sensor_id,accepted_at,received_at) VALUES
 ('a-old','ncu','2026-10-26T00:00:00Z','2026-10-26T00:00:00Z'),
 ('b-leased','ncu','2026-10-27T00:00:00Z','2026-10-27T00:00:00Z'),
 ('c-completed','ncu','2026-10-27T00:00:00Z','2026-10-27T00:00:00Z'),
 ('d-other','other','2026-10-27T00:00:00Z','2026-10-27T00:00:00Z'),
 ('e-boundary','ncu','2026-10-29T05:11:29Z','2026-10-29T05:11:29Z'),
 ('f-new','ncu','2026-10-29T05:11:30Z','2026-10-29T05:11:30Z');
INSERT INTO identity_ingest_fragments(batch_id) SELECT batch_id FROM identity_ingest_batches;
UPDATE identity_ingest_fragments SET derived_state='attempted',derived_lease_epoch=4,derived_lease_until=now()+interval '70 seconds' WHERE batch_id='b-leased';
UPDATE identity_ingest_fragments SET derived_state='completed' WHERE batch_id='c-completed';
INSERT INTO identity_derived_ready(batch_id,first_ordinal,sensor_id,accepted_at)
 SELECT b.batch_id,0,b.sensor_id,b.accepted_at FROM identity_ingest_batches b JOIN identity_ingest_fragments f USING(batch_id) WHERE f.derived_state<>'completed';
