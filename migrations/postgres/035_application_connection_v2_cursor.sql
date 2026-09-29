-- An independent cursor replays retained dirty receipts into the new indexed
-- model while an older program may still be updating the previous model.
CREATE TABLE IF NOT EXISTS application_connection_read_model_v2_cursor (
 id INTEGER PRIMARY KEY CHECK(id=1),
 cursor_document JSONB NOT NULL DEFAULT '{}',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
