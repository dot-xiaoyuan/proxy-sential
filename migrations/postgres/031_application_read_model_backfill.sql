CREATE TABLE IF NOT EXISTS application_read_model_backfills (
 name TEXT PRIMARY KEY,
 cursor_at TIMESTAMPTZ NOT NULL,
 until_at TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('running','completed')),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
