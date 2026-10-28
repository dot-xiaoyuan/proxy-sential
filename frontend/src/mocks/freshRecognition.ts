import type { components } from '../shared/api/generated'

type Protocol = components['schemas']['FreshRecognitionProtocol']
const empty = { inputs: 0, parsed: 0, attributed: 0, features: 0, candidates: 0, conclusions: 0, conflict: 0, processing: 0, unattributed: 0, insufficient: 0, errors: 0, overdue: 0 }
export const freshRecognition: components['schemas']['FreshRecognitionCoverage'] = {
  status: 'ready', since: '2026-10-28T00:00:00Z', as_of: '2026-10-28T02:00:00Z', window: '24h',
  input_semantics: 'accepted_standard_discovery_events', completion_semantics: 'generation_commit_upper_bound', http_visibility: 'requires_authenticated_probe', history_policy: 'excluded_without_backfill',
  items: [
    { ...empty, protocol: 'ssdp', purpose: 'product', status: 'observed', inputs: 100, parsed: 99, attributed: 80, features: 90, candidates: 50, conclusions: 40, conflict: 2, processing: 3, unattributed: 10, insufficient: 20, errors: 1, overdue: 4, timed: 70, read_and_prepare_ms: 13, lookup_ms: 1, rules_ms: 2, write_ms: 5, processing_upper_p95_ms: 4300 },
    ...['dhcp', 'dhcpv6', 'lldp', 'cdp', 'dns_sd', 'mdns', 'snmp', 'http', 'tls', 'ipp', 'onvif', 'ws_discovery', 'ssh', 'sip', 'mqtt', 'coap', 'bacnet', 'rtsp', 'arp', 'ndp', 'ieee1905'].map((protocol): Protocol => ({ ...empty, protocol, purpose: ['arp', 'ndp', 'ieee1905'].includes(protocol) ? 'association' : protocol === 'rtsp' ? 'fields_pending' : 'product', status: 'no_input' })),
  ],
}
