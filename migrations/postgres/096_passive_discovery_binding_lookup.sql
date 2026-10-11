-- mDNS service observations reuse only an event-time DHCP/ARP/NDP binding.
-- Without this partial expression index every service record scans the full
-- discovery history, causing a busy sensor to exhaust its materializer lease.
CREATE INDEX IF NOT EXISTS discovery_observation_binding_lookup
ON discovery_observations (
 (data->>'node'),
 (data->>'ip'),
 observed_at DESC,
 id DESC
)
WHERE origin IN ('dhcp','arp','ndp')
  AND coalesce(data->>'mac','')<>'';
