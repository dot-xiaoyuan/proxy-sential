CREATE TABLE IF NOT EXISTS application_observation_read_model_cursor (
 id integer PRIMARY KEY CHECK(id=1),cursor_document jsonb NOT NULL DEFAULT '{}',updated_at timestamptz NOT NULL DEFAULT 'epoch'
);
