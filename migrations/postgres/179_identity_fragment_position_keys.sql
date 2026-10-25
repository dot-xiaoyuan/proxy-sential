-- Keep the event-key algorithm fixed with each fragment. Already confirmed
-- fragments retain their original event-id keys; new fragments use source
-- positions so repeated source records remain separately accountable.
ALTER TABLE identity_ingest_fragments
  ADD COLUMN key_scheme text NOT NULL DEFAULT 'event_id_v1'
  CHECK (key_scheme IN ('event_id_v1','source_position_v1'));
