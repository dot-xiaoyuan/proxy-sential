-- A fresh source epoch is an explicit, audited operation. Legacy pending work
-- remains in its original tables with its original status and processing offset.
CREATE TABLE stream_source_cutovers (
 epoch text NOT NULL,
 source_kind text NOT NULL,
 source_path text NOT NULL,
 sensor_id text NOT NULL,
 file_id text NOT NULL,
 start_offset bigint NOT NULL CHECK(start_offset>=0),
 parser_version text NOT NULL,
 previous_release text NOT NULL,
 legacy_cutoff_at timestamptz NOT NULL,
 legacy_cancel_id text NOT NULL,
 cutover_at timestamptz NOT NULL DEFAULT now(),
 state text NOT NULL DEFAULT 'prepared' CHECK(state IN ('prepared','active','paused','closed')),
 cancel_manifest_sha256 text NOT NULL,
 PRIMARY KEY(epoch,source_kind,source_path)
);
CREATE UNIQUE INDEX stream_one_active_epoch_per_source
 ON stream_source_cutovers(source_kind,source_path) WHERE state='active';

CREATE TABLE stream_discard_manifest (
 epoch text NOT NULL,
 source_kind text NOT NULL,
 source_path text NOT NULL,
 legacy_kind text NOT NULL,
 legacy_reference text NOT NULL,
 legacy_status text NOT NULL,
 content_sha256 text NOT NULL DEFAULT '',
 unprocessed_records bigint NOT NULL CHECK(unprocessed_records>=0),
 first_unprocessed_at timestamptz,
 last_unprocessed_at timestamptz,
 recorded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(epoch,source_kind,source_path,legacy_kind,legacy_reference),
 FOREIGN KEY(epoch,source_kind,source_path)
  REFERENCES stream_source_cutovers(epoch,source_kind,source_path)
);
