CREATE TABLE IF NOT EXISTS proxy_protocol_results (
 evidence_id text PRIMARY KEY,
 ip text NOT NULL,
 observed_at timestamptz NOT NULL,
 document jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS proxy_protocol_results_ip_time ON proxy_protocol_results(ip,observed_at DESC);
CREATE INDEX IF NOT EXISTS proxy_protocol_results_time ON proxy_protocol_results(observed_at DESC);
CREATE TABLE IF NOT EXISTS proxy_protocol_scan (id text PRIMARY KEY,document jsonb NOT NULL);
