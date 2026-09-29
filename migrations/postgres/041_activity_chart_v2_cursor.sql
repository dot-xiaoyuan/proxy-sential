CREATE TABLE IF NOT EXISTS activity_chart_read_model_cursor_v2 (
 id integer PRIMARY KEY CHECK(id=1),cursor_document jsonb NOT NULL DEFAULT '{}',updated_at timestamptz NOT NULL DEFAULT 'epoch'
);
