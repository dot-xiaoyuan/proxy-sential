SET LOCAL lock_timeout='5s';
CREATE INDEX identity_projection_intervals_retention ON identity_projection_intervals(first_received_at,scope_key,session_id,ip,interval_hash);
