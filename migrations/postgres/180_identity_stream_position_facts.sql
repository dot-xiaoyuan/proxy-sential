-- Fresh identity facts are append-only by source position. The bounded inbox
-- header/offset is the projection receipt; authoritative event bodies stay in
-- ClickHouse. Avoid another global event-ID index on this hot path.
CREATE TABLE identity_stream_policy_facts (
 scope_key text NOT NULL,
 batch_sequence bigint NOT NULL CHECK (batch_sequence>0),
 ordinal integer NOT NULL CHECK (ordinal>=0),
 variant smallint NOT NULL CHECK (variant>=0),
 event_id text NOT NULL,
 campus_id text NOT NULL,
 access_domain text NOT NULL,
 observed_at timestamptz NOT NULL,
 accepted_at timestamptz NOT NULL,
 session_data jsonb NOT NULL,
 content_sha256 text NOT NULL CHECK (length(content_sha256)=64),
 applied_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(scope_key,batch_sequence,ordinal,variant)
);
CREATE INDEX identity_stream_policy_scope_time ON identity_stream_policy_facts(campus_id,access_domain,observed_at);
CREATE INDEX identity_stream_policy_retention ON identity_stream_policy_facts USING brin(accepted_at);
