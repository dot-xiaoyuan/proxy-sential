-- A replay cutover preserves a closed journal and its unfinished work while
-- re-reading the same protected source bytes under a non-colliding birth ID.
-- It is separate from fresh-input cancellation: zero source bytes are skipped.
SET LOCAL lock_timeout = '5s';

ALTER TABLE stream_source_cutovers
 ADD COLUMN cutover_mode text NOT NULL DEFAULT 'fresh'
 CHECK (cutover_mode IN ('fresh','verified_replay'));

CREATE TABLE stream_source_replays (
 new_epoch text NOT NULL,
 source_kind text NOT NULL,
 source_path text NOT NULL,
 old_epoch text NOT NULL,
 old_journal_dir text NOT NULL,
 new_journal_dir text NOT NULL,
 recovery_file text NOT NULL,
 old_file_id text NOT NULL,
 old_cursor_offset bigint NOT NULL CHECK (old_cursor_offset > 0),
 replay_file_id text NOT NULL,
 replay_start_offset bigint NOT NULL CHECK (replay_start_offset >= 0),
 replay_file_end_offset bigint NOT NULL CHECK (replay_file_end_offset > replay_start_offset),
 replay_file_sha256 text NOT NULL CHECK (replay_file_sha256 ~ '^[0-9a-f]{64}$'),
 replay_range_sha256 text NOT NULL CHECK (replay_range_sha256 ~ '^[0-9a-f]{64}$'),
 old_pending_manifest_sha256 text NOT NULL CHECK (old_pending_manifest_sha256 ~ '^[0-9a-f]{64}$'),
 plan_sha256 text NOT NULL CHECK (plan_sha256 ~ '^[0-9a-f]{64}$'),
 replay_records bigint NOT NULL CHECK (replay_records > 0),
 pending_segments integer NOT NULL CHECK (pending_segments BETWEEN 1 AND 64),
 pending_events integer NOT NULL CHECK (pending_events > 0),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(new_epoch,source_kind,source_path),
 FOREIGN KEY(new_epoch,source_kind,source_path)
  REFERENCES stream_source_cutovers(epoch,source_kind,source_path),
 CHECK (replay_start_offset < old_cursor_offset AND old_cursor_offset <= replay_file_end_offset),
 CHECK (old_file_id <> replay_file_id)
);

CREATE FUNCTION prevent_stream_source_replay_change() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'stream source replay evidence is immutable';
END $$;
CREATE TRIGGER stream_source_replay_immutable BEFORE UPDATE OR DELETE ON stream_source_replays
 FOR EACH ROW EXECUTE FUNCTION prevent_stream_source_replay_change();
