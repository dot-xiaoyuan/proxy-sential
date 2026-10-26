-- A later audited source reset may require a new risk generation. Preserve
-- every earlier cancellation header and its subject ledger.
ALTER TABLE stream_risk_fresh_cutovers DROP CONSTRAINT stream_risk_fresh_cutovers_pkey;
ALTER TABLE stream_risk_fresh_cutovers ADD PRIMARY KEY(sensor_id,cancel_id);
CREATE UNIQUE INDEX stream_risk_fresh_cutovers_sensor_cutoff_unique
 ON stream_risk_fresh_cutovers(sensor_id,accepted_after);
