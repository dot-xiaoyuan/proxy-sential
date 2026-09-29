CREATE SEQUENCE IF NOT EXISTS application_connection_summary_revision_seq;
CREATE TABLE IF NOT EXISTS application_connection_read_model_cursor (
 id INTEGER PRIMARY KEY CHECK(id=1),
 cursor_document JSONB NOT NULL DEFAULT '{}',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
