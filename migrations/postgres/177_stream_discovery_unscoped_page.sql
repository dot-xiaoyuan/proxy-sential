-- The current-device list orders across scopes. Limit indexed keys by active
-- epoch before reading JSON documents, including on a cold shared disk.
CREATE INDEX stream_discovery_state_unscoped_page
ON stream_discovery_device_state(epoch,last_seen DESC,device_key);

CREATE INDEX stream_discovery_state_unscoped_iot_page
ON stream_discovery_device_state(epoch,last_seen DESC,device_key)
WHERE classification_status IN ('identified','expired','conflict');
