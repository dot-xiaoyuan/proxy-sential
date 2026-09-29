-- One-time bootstrap and bounded per-statement deltas replace request-time
-- scans of all evidence. Lock bootstrap against concurrent ingestion.
LOCK TABLE evidence IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE IF NOT EXISTS evidence_type_counts (type TEXT PRIMARY KEY,evidence_count BIGINT NOT NULL);
INSERT INTO evidence_type_counts(type,evidence_count)
SELECT type,count(*) FROM evidence GROUP BY type
ON CONFLICT(type) DO UPDATE SET evidence_count=EXCLUDED.evidence_count;

CREATE OR REPLACE FUNCTION sentinel_evidence_count_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO evidence_type_counts(type,evidence_count) SELECT type,count(*) FROM new_evidence GROUP BY type ORDER BY type
 ON CONFLICT(type) DO UPDATE SET evidence_count=evidence_type_counts.evidence_count+EXCLUDED.evidence_count;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION sentinel_evidence_count_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO evidence_type_counts(type,evidence_count) SELECT type,-count(*) FROM old_evidence GROUP BY type ORDER BY type
 ON CONFLICT(type) DO UPDATE SET evidence_count=evidence_type_counts.evidence_count+EXCLUDED.evidence_count;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION sentinel_evidence_count_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO evidence_type_counts(type,evidence_count)
 SELECT type,sum(delta) FROM (SELECT type,count(*) AS delta FROM new_evidence GROUP BY type UNION ALL SELECT type,-count(*) AS delta FROM old_evidence GROUP BY type) changes
 GROUP BY type HAVING sum(delta)<>0 ORDER BY type
 ON CONFLICT(type) DO UPDATE SET evidence_count=evidence_type_counts.evidence_count+EXCLUDED.evidence_count;
 RETURN NULL;
END $$;
CREATE TRIGGER evidence_count_insert AFTER INSERT ON evidence REFERENCING NEW TABLE AS new_evidence FOR EACH STATEMENT EXECUTE FUNCTION sentinel_evidence_count_insert();
CREATE TRIGGER evidence_count_delete AFTER DELETE ON evidence REFERENCING OLD TABLE AS old_evidence FOR EACH STATEMENT EXECUTE FUNCTION sentinel_evidence_count_delete();
CREATE TRIGGER evidence_count_update AFTER UPDATE ON evidence REFERENCING OLD TABLE AS old_evidence NEW TABLE AS new_evidence FOR EACH STATEMENT EXECUTE FUNCTION sentinel_evidence_count_update();
