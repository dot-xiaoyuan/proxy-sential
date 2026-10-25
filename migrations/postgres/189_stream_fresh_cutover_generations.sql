-- A failed fresh trial can be audited and retired without reusing its risk
-- generation. Keep every prior immutable cutoff and its exact canceled dirty
-- subjects; current reads use only the latest cutoff for each sensor.
ALTER TABLE stream_risk_fresh_cutovers DROP CONSTRAINT stream_risk_fresh_cutovers_pkey;
ALTER TABLE stream_risk_fresh_cutovers ADD PRIMARY KEY(sensor_id,accepted_after);

-- The router index cursor uses the same append-only generation history. The
-- mutable worker state has one row per sensor and is reseeded only after its
-- previous lease is stopped.
ALTER TABLE stream_router_fresh_cutovers DROP CONSTRAINT stream_router_fresh_cutovers_pkey;
ALTER TABLE stream_router_fresh_cutovers ADD PRIMARY KEY(sensor_id,indexed_after);
ALTER TABLE stream_router_fresh_cutovers ADD COLUMN prior_processed_events bigint NOT NULL DEFAULT 0;
