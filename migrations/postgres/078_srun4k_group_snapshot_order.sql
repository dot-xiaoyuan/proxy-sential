-- Preserve complete group-directory observations, including empty directories,
-- so late responses cannot reactivate old policy scope members.
SET LOCAL lock_timeout = '250ms';
SET LOCAL statement_timeout = '5s';
CREATE TABLE srun4k_group_snapshots (
  source text NOT NULL,
  observed_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  content_sha256 text CHECK(content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$'),
  groups jsonb NOT NULL CHECK(jsonb_typeof(groups)='array'),
  legacy_import boolean NOT NULL DEFAULT false,
  PRIMARY KEY(source,observed_at)
);
-- The old catalog is a current-state baseline, not a claimed upstream replay.
-- Keep its row content and active flags untouched; the importer records its
-- original latest observation as a watermark and identifies this provenance.
INSERT INTO srun4k_group_snapshots(source,observed_at,groups,legacy_import)
SELECT source,max(observed_at),
  coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'id',group_id,'name',name,'pid',nullif(parent_id,''),'path',nullif(path,'')))
    ORDER BY group_id COLLATE "C") FILTER(WHERE active),'[]'::jsonb),true
FROM srun4k_group_catalog
GROUP BY source;
