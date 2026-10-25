-- Bind each fresh file-source epoch to the exact operator-approved capture
-- scope. Existing passive epochs retain their previous validation path.
ALTER TABLE stream_source_cutovers
 ADD COLUMN capture_scope_sha256 text NOT NULL DEFAULT ''
 CHECK (capture_scope_sha256='' OR length(capture_scope_sha256)=64);
