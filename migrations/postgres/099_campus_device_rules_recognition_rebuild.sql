-- Device rules now read the DHCP vendor class and recognise campus routers,
-- access points, switches, printers and IoT terminals. Recognition jobs only
-- run when an endpoint changes, so re-enqueue endpoints seen in the last seven
-- days once; older endpoints pick the new rules up on their next DHCP renewal.
INSERT INTO endpoint_recognition_jobs(endpoint_id)
SELECT endpoint_id FROM endpoint_entities
WHERE entity_role='endpoint' AND last_seen>now()-interval '7 days'
ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=now();
