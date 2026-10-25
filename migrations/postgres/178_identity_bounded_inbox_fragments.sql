-- New batches keep only a compact receipt in the header. The old JSONB batch
-- remains readable so a compatibility application can precede the writer cutover.
ALTER TABLE identity_ingest_batches ADD COLUMN payload_format text NOT NULL DEFAULT 'legacy_json';
ALTER TABLE identity_ingest_batches ADD COLUMN stream_epoch text NOT NULL DEFAULT '';

CREATE TABLE identity_ingest_fragments (
 batch_id text NOT NULL REFERENCES identity_ingest_batches(batch_id),
 first_ordinal integer NOT NULL CHECK (first_ordinal>=0),
 record_count integer NOT NULL CHECK (record_count BETWEEN 1 AND 50),
 normalized_events jsonb NOT NULL CHECK (jsonb_typeof(normalized_events)='array'),
 content_sha256 text NOT NULL CHECK (length(content_sha256)=64),
 archive_month text NOT NULL CHECK (archive_month ~ '^[0-9]{6}$'),
 body_state text NOT NULL DEFAULT 'pending' CHECK (body_state IN ('pending','attempted','completed','failed')),
 search_state text NOT NULL DEFAULT 'pending' CHECK (search_state IN ('pending','attempted','completed','failed')),
 derived_state text NOT NULL DEFAULT 'pending' CHECK (derived_state IN ('pending','attempted','completed','failed')),
 lease_epoch bigint NOT NULL DEFAULT 0,
 lease_until timestamptz,
 derived_lease_epoch bigint NOT NULL DEFAULT 0,
 derived_lease_until timestamptz,
 derived_error text NOT NULL DEFAULT '',
 last_attempt_at timestamptz,
 last_error text NOT NULL DEFAULT '',
 archived_at timestamptz,
 searched_at timestamptz,
 released_at timestamptz,
 PRIMARY KEY (batch_id,first_ordinal),
 CHECK ((released_at IS NULL AND jsonb_array_length(normalized_events)=record_count) OR
        (released_at IS NOT NULL AND normalized_events='[]'::jsonb)),
 CHECK (octet_length(normalized_events::text)<=262144)
);
CREATE INDEX identity_ingest_fragments_pending ON identity_ingest_fragments(batch_id,first_ordinal)
 WHERE body_state<>'completed' OR search_state<>'completed';
CREATE INDEX identity_ingest_fragments_derived_pending ON identity_ingest_fragments(batch_id,first_ordinal)
 WHERE derived_state<>'completed';
