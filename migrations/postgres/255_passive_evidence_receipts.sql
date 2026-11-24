-- The existing ingest ledger owns the file coordinates and first successful
-- commit time. This outbox stores only immutable references and state changes.
CREATE TABLE passive_archive_rows (
 batch_id text NOT NULL, row_hash text NOT NULL, batch_hash text NOT NULL,
 attempts int NOT NULL DEFAULT 0, next_attempt timestamptz NOT NULL DEFAULT now(),
 accepted_at timestamptz, verified_at timestamptz, last_error text NOT NULL DEFAULT '',
 PRIMARY KEY(batch_id,row_hash)
);
CREATE INDEX passive_archive_due ON passive_archive_rows(next_attempt,batch_id) WHERE verified_at IS NULL AND attempts<8;
CREATE TABLE passive_archive_members (
 observation_id text NOT NULL, event_id text NOT NULL, observed_at timestamptz NOT NULL,
 semantic_hash text NOT NULL, withdrawn boolean NOT NULL, batch_id text NOT NULL, row_hash text NOT NULL,
 PRIMARY KEY(observation_id,event_id,semantic_hash,withdrawn,batch_id,row_hash)
);
CREATE FUNCTION passive_archive_enqueue(k text, doc jsonb, observed timestamptz, revoked boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE refs jsonb; ref jsonb; batch text; row_digest text; batch_digest text;
BEGIN
 refs:=doc#>'{evidence,raw_ref}';
 FOR ref IN SELECT refs UNION ALL SELECT item->'raw_ref' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(refs->'records')='array' THEN refs->'records' ELSE '[]'::jsonb END) item
 LOOP
  batch:=ref#>>'{ingest_source_ref,batch_id}'; row_digest:=ref->>'content_sha256'; batch_digest:=ref#>>'{ingest_source_ref,content_sha256}';
  IF batch IS NULL OR row_digest IS NULL OR row_digest!~'^[a-f0-9]{64}$' OR batch_digest IS NULL OR batch_digest!~'^[a-f0-9]{64}$' THEN
   -- Composite roots have no row of their own. Keep an explicit missing
   -- member if a child or a standalone record has no usable reference.
   IF ref IS NOT DISTINCT FROM refs AND jsonb_typeof(refs->'records')='array' AND jsonb_array_length(refs->'records')>0 THEN CONTINUE; END IF;
   batch:=''; row_digest:=coalesce(ref->>'content_sha256','');
  ELSE
   INSERT INTO passive_archive_rows(batch_id,row_hash,batch_hash) VALUES(batch,row_digest,batch_digest) ON CONFLICT DO NOTHING;
  END IF;
  INSERT INTO passive_archive_members VALUES(k,coalesce(doc->>'event_id',''),observed,coalesce(doc->>'semantic_hash',''),revoked,batch,row_digest) ON CONFLICT DO NOTHING;
 END LOOP;
END $$;
CREATE FUNCTION passive_archive_observation_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM passive_archive_enqueue(NEW.id,NEW.data,NEW.observed_at,NEW.withdrawn);
 RETURN NULL;
END $$;
CREATE TRIGGER passive_archive_capture AFTER INSERT OR UPDATE OF data,withdrawn ON discovery_observations
 FOR EACH ROW EXECUTE FUNCTION passive_archive_observation_changed();
ALTER TABLE discovery_observations DISABLE TRIGGER passive_archive_capture;

-- Restartable traversal of retained rows. New writes are captured separately
-- before historical adoption starts. A snapshot timestamp is never substituted
-- for a missing first successful ingest time.
CREATE TABLE passive_archive_adoption (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), last_id text NOT NULL DEFAULT '', complete boolean NOT NULL DEFAULT false,
 examined bigint NOT NULL DEFAULT 0, started_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO passive_archive_adoption DEFAULT VALUES;
CREATE FUNCTION passive_archive_adopt(n integer) RETURNS integer LANGUAGE plpgsql AS $$
DECLARE pos text; done boolean; item record; taken int:=0; used bigint:=0;
BEGIN
 IF n IS NULL OR n NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'invalid archive adoption batch'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(current_schema()||':passive-archive-adopt',3)) THEN RETURN 0; END IF;
 SELECT last_id,complete INTO STRICT pos,done FROM passive_archive_adoption WHERE singleton;
 IF done THEN RETURN 0; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='discovery_observations'::regclass AND tgname='passive_archive_capture' AND tgenabled IN ('A','O'))
 THEN RAISE EXCEPTION 'enable passive archive capture before adoption'; END IF;
 FOR item IN SELECT id,data,observed_at,withdrawn,pg_column_size(data) AS bytes FROM discovery_observations WHERE id>pos ORDER BY id LIMIT n
 LOOP
  IF taken>0 AND used+item.bytes>1048576 THEN EXIT; END IF;
  IF item.bytes>1048576 THEN RAISE EXCEPTION 'retained observation % exceeds archive adoption budget',item.id; END IF;
  PERFORM passive_archive_enqueue(item.id,item.data,item.observed_at,item.withdrawn);
  pos:=item.id; taken:=taken+1;used:=used+item.bytes;
 END LOOP;
 UPDATE passive_archive_adoption SET last_id=pos,examined=examined+taken,complete=(taken=0) WHERE singleton;
 RETURN taken;
END $$;
CREATE INDEX passive_archive_verified_time ON passive_archive_rows(accepted_at,batch_id) WHERE verified_at IS NOT NULL;
