-- Cancellation ranges and per-batch hashes are evidence. State transitions
-- happen on the source cutover row; manifest entries are append only.
CREATE FUNCTION prevent_stream_discard_manifest_change() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'stream discard manifest is immutable';
END $$;
CREATE TRIGGER stream_discard_manifest_immutable BEFORE UPDATE OR DELETE ON stream_discard_manifest
 FOR EACH ROW EXECUTE FUNCTION prevent_stream_discard_manifest_change();
