-- Validate in a separate transaction so the brief ACCESS EXCLUSIVE lock in
-- migration 199 is released before this existing-row check. Normal ingestion
-- can continue while this broader but read-only validation runs.
ALTER TABLE identity_ingest_fragments VALIDATE CONSTRAINT identity_ingest_fragments_derived_state_check;
