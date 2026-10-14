-- Device center address scopes need "does this endpoint ever have an IP" per device.
-- `identity_ip_mac_history` is ~11M rows / 8.8GB on the field, so the plain lookup plan
-- degraded into a full scan and the 10s request budget was blown for the 历史地址 and
-- 仅有链路证据 scopes.
--
-- The index is partial and covers only the endpoint id, so it stays small (~66MB) and the
-- per-endpoint existence probe is an index-only lookup.
--
-- Application-only upgrades execute each migration inside a transaction, which cannot run
-- CREATE INDEX CONCURRENTLY. On an existing installation the index is therefore built
-- concurrently ahead of the upgrade and this statement records the migration as a no-op;
-- a fresh installation builds it here, where there is no live traffic to block.
CREATE INDEX IF NOT EXISTS idx_ip_history_endpoint_has_ip
 ON identity_ip_mac_history(endpoint_id) WHERE ip IS NOT NULL;

-- The field tables had never been analysed: with the default scale factor an 11M-row table
-- only re-analyses after ~1.1M changes, so the planner estimated current_addresses at 129
-- rows instead of ~12k and the terminal total took 20s. Tighten analysis for the tables the
-- device center reads so the estimate cannot rot back to that state.
ALTER TABLE identity_ip_mac_history SET (autovacuum_analyze_scale_factor = 0.005);
ALTER TABLE endpoint_recognition_summary SET (autovacuum_analyze_scale_factor = 0.02);
ALTER TABLE device_address_leases SET (autovacuum_analyze_scale_factor = 0.02);
ALTER TABLE account_sessions SET (autovacuum_analyze_scale_factor = 0.02);
