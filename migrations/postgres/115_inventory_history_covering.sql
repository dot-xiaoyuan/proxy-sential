-- Initial per-device projection and bounded history reads need these scalar
-- facts. Avoid repeatedly fetching scattered heap pages for each association.
-- Large raw evidence remains in the source and is not duplicated here.
CREATE INDEX inventory_ip_history_fact_cover ON identity_ip_mac_history(endpoint_id,last_seen DESC)
 INCLUDE(first_seen,ip,account_id,source,event_id,identity_confidence);
CREATE INDEX inventory_access_history_fact_cover ON identity_access_history(endpoint_id,last_seen DESC)
 INCLUDE(first_seen,access_id,account_id,source,event_id,identity_confidence);
