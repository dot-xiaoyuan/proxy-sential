CREATE TRIGGER identity_derived_ready_on_terminal AFTER UPDATE OF derived_state ON identity_ingest_fragments
 FOR EACH ROW EXECUTE FUNCTION identity_derived_ready_on_terminal();
INSERT INTO identity_derived_fresh_starts(cancel_id,sensor_id,accepted_after,reason) VALUES('test-cutover','ncu','2026-10-29T05:11:29Z','explicit test fresh start');
SAVEPOINT interrupted_page;
SELECT * FROM cancel_identity_derived_page('test-cutover',2);
ROLLBACK TO SAVEPOINT interrupted_page;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM identity_derived_cancelled_fragments) OR EXISTS(SELECT 1 FROM identity_ingest_fragments WHERE derived_state='cancelled') THEN RAISE EXCEPTION 'interrupted page leaked cancellation'; END IF; END $$;
SELECT * FROM cancel_identity_derived_page('test-cutover',2);
SELECT * FROM cancel_identity_derived_page('test-cutover',2);
SELECT * FROM cancel_identity_derived_page('test-cutover',2);
SELECT * FROM cancel_identity_derived_page('test-cutover',2);
SELECT * FROM cancel_identity_derived_page('test-cutover',2);
DO $$ BEGIN
 IF (SELECT count(*) FROM identity_derived_cancelled_fragments)<>2 THEN RAISE EXCEPTION 'wrong audit count'; END IF;
 IF (SELECT count(*) FROM identity_ingest_fragments WHERE derived_state='cancelled')<>2 THEN RAISE EXCEPTION 'wrong cancelled count'; END IF;
 IF EXISTS(SELECT 1 FROM identity_ingest_fragments WHERE normalized_events<>'[{"original":"keep"}]'::jsonb) THEN RAISE EXCEPTION 'evidence changed'; END IF;
 IF (SELECT derived_state FROM identity_ingest_fragments WHERE batch_id='c-completed')<>'completed' THEN RAISE EXCEPTION 'completed state changed'; END IF;
 IF EXISTS(SELECT 1 FROM identity_ingest_fragments WHERE batch_id IN ('d-other','e-boundary','f-new') AND derived_state<>'pending') THEN RAISE EXCEPTION 'new or other sensor work cancelled'; END IF;
 IF EXISTS(SELECT 1 FROM identity_derived_ready WHERE batch_id IN ('a-old','b-leased')) THEN RAISE EXCEPTION 'cancelled key can still be claimed'; END IF;
 IF NOT EXISTS(SELECT 1 FROM identity_ingest_fragments WHERE batch_id='b-leased' AND derived_lease_epoch=5 AND derived_lease_until IS NULL) THEN RAISE EXCEPTION 'old worker was not fenced'; END IF;
 IF NOT EXISTS(SELECT 1 FROM identity_derived_cancel_progress WHERE done AND cancelled_events=2 AND cancelled_fragments=2) THEN RAISE EXCEPTION 'progress does not match audit'; END IF;
 BEGIN
  UPDATE identity_derived_fresh_starts SET accepted_after=now();
  RAISE EXCEPTION 'audit mutation accepted';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM='audit mutation accepted' THEN RAISE; END IF;
 END;
 BEGIN
  INSERT INTO identity_ingest_batches(batch_id,sensor_id,accepted_at,received_at,payload_format) VALUES('bad-new','ncu','2026-10-29T05:11:30Z','2026-10-29T05:11:30Z','legacy_json');
  RAISE EXCEPTION 'new legacy body silently accepted';
 EXCEPTION WHEN check_violation THEN NULL;
 END;
END $$;
