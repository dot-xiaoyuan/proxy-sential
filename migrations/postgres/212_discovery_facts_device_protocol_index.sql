-- Speed up the event-bus passive-device existence filter.
CREATE INDEX IF NOT EXISTS discovery_service_facts_shadow_device_protocol_idx
  ON discovery_service_facts_shadow (device_key, protocol);
