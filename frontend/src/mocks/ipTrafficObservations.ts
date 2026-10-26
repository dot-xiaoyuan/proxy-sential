import { http, HttpResponse } from 'msw'
import type { IpTrafficObservationPage, NormalizedEventSummary } from '../shared/api/types'

export const ipTrafficObservationHandlers = [
  http.get('/api/v1/ips/:ip/traffic-observations', ({ request, params }) => {
    const q = new URL(request.url).searchParams
    const from = q.get('from')!, to = q.get('to')!
    const owner = q.get('source_owner') === 'packet-sidecar' ? 'packet-sidecar' : 'handshake-sidecar'
    const ip = decodeURIComponent(String(params.ip))
    const protocols = q.get('protocol') ? [q.get('protocol')!] : ['handshake', 'ttl']
    const events = q.get('cursor') ? [] : protocols.map((protocol, index) => ({
      observed_at: new Date(Date.parse(to) - (index + 1) * 30_000).toISOString(), event_key: `traffic-fixture:${protocol}:${ip}`,
      protocol, event_type: 'device', source: protocol === 'handshake' ? 'handshake-sidecar' : 'packet-sidecar', sensor_id: 'mock-sensor', subject_ip: ip,
      body_ref: { class: protocol === 'handshake' ? 'evidence' as const : 'short' as const, month: to.slice(0, 7).replace('-', ''), scope: 'scope-fixture', key: `traffic-fixture:${protocol}:${ip}`, sha256: 'b'.repeat(64) },
    }))
    const page: IpTrafficObservationPage = { ip, source_owner: owner, status: 'ready', from, to, queried_at: new Date().toISOString(),
      source: { epoch: 'traffic-fixture', scope_id: 'scope-fixture', state: 'active', cutoff_at: new Date(Date.parse(from) - 60_000).toISOString() }, events }
    return HttpResponse.json(page)
  }),
  http.get('/api/v1/events/stream-body', ({ request }) => {
    const ref = JSON.parse(new URL(request.url).searchParams.get('ref') ?? '{}')
    if (!String(ref.key).startsWith('traffic-fixture:')) return
    const protocol = String(ref.key).split(':')[1]
    const event: NormalizedEventSummary = { event_id: ref.key, type: 'device', source: protocol === 'handshake' ? 'handshake-sidecar' : 'packet-sidecar', timestamp: new Date().toISOString(), subject: { ip: String(ref.key).split(':').slice(2).join(':') }, flow: {}, confidence: .8,
      payload: protocol === 'handshake' ? { observed_count: 128, mac: '90:fb:5d:a7:40:4b', snis: ['api.example.com', 'very-long-client-application-hostname.example.net'], hosts: ['example.org'], user_agents: ['Mozilla/5.0 (Linux; Android 15; ExampleDevice) AppleWebKit/537.36 Chrome/130.0.0.0 Mobile Safari/537.36'] } : { observed_count: 512, ttl: 63, neighbor_role: 'unverified', direction: 'unknown' } }
    return HttpResponse.json(event)
  }),
]
