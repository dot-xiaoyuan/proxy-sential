ALTER TABLE local_users ADD COLUMN IF NOT EXISTS auth_source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE local_users ADD COLUMN IF NOT EXISTS external_subject TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_local_users_external_identity
ON local_users(auth_source, external_subject)
WHERE external_subject IS NOT NULL;
