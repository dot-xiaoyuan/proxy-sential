-- The primary order serves sensor/IP/time reads. Account claims and unknown
-- write repair need independent granule pruning without copying feature JSON.
ALTER TABLE stream_risk_features_v1
 ADD INDEX IF NOT EXISTS risk_feature_account_bloom account_id TYPE bloom_filter(0.01) GRANULARITY 1;
ALTER TABLE stream_risk_features_v1
 ADD INDEX IF NOT EXISTS risk_feature_key_bloom event_key TYPE bloom_filter(0.01) GRANULARITY 1;
