-- Profiles materialized before router_status/role_source existed keep the old
-- identity semantics (candidate shown as history, discovery hints as current
-- identity) until one of their sources changes. Enqueue every live profile once
-- so the materializer rebuilds it; the list_item document carries the new fields,
-- so no column change is needed.
SELECT enqueue_shared_device_profile_job(p.sensor_id,p.campus_id,p.endpoint_id,p.mac,p.primary_ip,p.vlan,now())
FROM shared_device_profiles p
WHERE p.merged_into_profile_id IS NULL;
