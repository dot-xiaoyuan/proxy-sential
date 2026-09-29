import { http, HttpResponse } from 'msw'
import type { RouterAssessment, RouterObservationDetail } from '../shared/api/types'

const now = '2026-09-24T09:30:00Z'
const first = '2026-09-24T08:10:00Z'
const expires = '2026-09-25T09:30:00Z'

export const routerObservations: RouterObservationDetail[] = [
  {
    assessment_id: 'router-huawei-ar-001', endpoint_id: 'endpoint-router-001', ip: '192.0.2.10', mac: '00:46:4b:12:34:56', vlans: ['120'], brand: 'Huawei', series: 'AR', model: 'AR6140', role: 'router', status: 'confirmed', confidence: 95, independent_sources: 2, sources: ['dhcp', 'lldp'], infrastructure: false, brand_reference_only: false, association_quality: 'mac', ambiguous: false, confirmed_router: true, rule_version: 'router-rules-2026.09.1', first_seen: first, last_seen: now, expires_at: expires, conflicts: [], merged_records: 3,
    score_components: [{ source_family: 'dhcp', evidence_id: 'ev-dhcp-ar', score: 55, explanation: 'DHCP vendor class 明确包含 Huawei AR6140' }, { source_family: 'lldp', evidence_id: 'ev-lldp-ar', score: 55, explanation: 'LLDP 宣告 router capability 与型号' }],
    evidence: [
      { evidence_id: 'ev-lldp-ar', assessment_id: 'router-huawei-ar-001', kind: 'router_signal', endpoint_id: 'endpoint-router-001', ip: '192.0.2.10', mac: '00:46:4b:12:34:56', vlan: '120', brand: 'Huawei', series: 'AR', model: 'AR6140', role: 'router', source: 'zeek', source_family: 'lldp', source_event_type: 'device', raw_value: 'Huawei AR6140 router', strength: 'strong', score: 55, rule_id: 'huawei-router-ar', rule_version: 'router-rules-2026.09.1', explanation: 'LLDP 路由能力与 Huawei AR 型号同时命中', conflict: false, exclusion: false, brand_reference_only: false, association_quality: 'mac', ambiguous: false, first_seen: first, last_seen: now, expires_at: expires, expired: false, event_ids: ['evt-lldp-ar'] },
      { evidence_id: 'ev-dhcp-ar', assessment_id: 'router-huawei-ar-001', kind: 'router_signal', endpoint_id: 'endpoint-router-001', ip: '192.0.2.10', mac: '00:46:4b:12:34:56', vlan: '120', brand: 'Huawei', series: 'AR', model: 'AR6140', role: 'router', source: 'zeek', source_family: 'dhcp', source_event_type: 'device', raw_value: 'Huawei AR6140', strength: 'strong', score: 55, rule_id: 'huawei-router-ar', rule_version: 'router-rules-2026.09.1', explanation: 'DHCP vendor class 明确包含路由器型号', conflict: false, exclusion: false, brand_reference_only: false, association_quality: 'mac', ambiguous: false, first_seen: first, last_seen: now, expires_at: expires, expired: false, event_ids: ['evt-dhcp-ar'] },
    ],
    history: [{ status: 'candidate', confidence: 55, rule_version: 'router-rules-2026.09.1', changed_at: first, conflicts: [] }, { status: 'confirmed', confidence: 95, rule_version: 'router-rules-2026.09.1', changed_at: now, conflicts: [] }],
  },
  {
    assessment_id: 'router-h3c-msr-002', ip: '192.0.2.22', mac: '00:1a:a9:65:43:21', vlans: ['220'], brand: 'H3C', series: 'MSR', model: 'MSR3600', role: 'router', status: 'likely', confidence: 75, independent_sources: 2, sources: ['software', 'http_management'], infrastructure: false, brand_reference_only: false, association_quality: 'mac', ambiguous: false, confirmed_router: false, rule_version: 'router-rules-2026.09.1', first_seen: first, last_seen: now, expires_at: expires, conflicts: ['strong_evidence_required'], score_components: [{ source_family: 'software', evidence_id: 'ev-soft-msr', score: 45, explanation: '软件标识包含 H3C MSR' }, { source_family: 'http_management', evidence_id: 'ev-http-msr', score: 30, explanation: '管理面标题包含型号' }], evidence: [], history: [{ status: 'likely', confidence: 75, rule_version: 'router-rules-2026.09.1', changed_at: now, conflicts: ['strong_evidence_required'] }],
  },
  {
    assessment_id: 'router-huawei-oui-003', ip: '192.0.2.33', mac: '70:72:3c:11:22:33', vlans: ['120'], brand: 'Huawei', role: 'unknown', status: 'candidate', confidence: 10, independent_sources: 1, sources: ['oui'], infrastructure: false, brand_reference_only: true, association_quality: 'mac', ambiguous: false, confirmed_router: false, rule_version: 'router-rules-2026.09.1', first_seen: first, last_seen: now, expires_at: expires, conflicts: ['brand_reference_only'], score_components: [{ source_family: 'oui', evidence_id: 'ev-oui-huawei', score: 10, explanation: 'MAC OUI 仅确认厂商' }], evidence: [], history: [{ status: 'candidate', confidence: 10, rule_version: 'router-rules-2026.09.1', changed_at: now, conflicts: ['brand_reference_only'] }],
  },
]

function matches(item: RouterAssessment, url: URL) {
  const text = [item.assessment_id, item.endpoint_id, item.ip, item.mac, item.brand, item.series, item.model].filter(Boolean).join(' ').toLowerCase()
  const keyword = url.searchParams.get('keyword')?.toLowerCase()
  const equal = (name: string, value?: string) => !url.searchParams.get(name) || value?.toLowerCase() === url.searchParams.get(name)?.toLowerCase()
  const minimum = Number(url.searchParams.get('confidence_min') || 0)
  const maximum = Number(url.searchParams.get('confidence_max') || 100)
  return (!keyword || text.includes(keyword)) && equal('ip', item.ip) && equal('mac', item.mac) && equal('brand', item.brand) && equal('model', item.model) && equal('role', item.role) && equal('status', item.status) && (!url.searchParams.get('vlan') || item.vlans?.includes(url.searchParams.get('vlan') || '')) && (!url.searchParams.get('source') || item.sources.includes(url.searchParams.get('source') || '')) && (!url.searchParams.has('infrastructure') || item.infrastructure === (url.searchParams.get('infrastructure') === 'true')) && item.confidence >= minimum && item.confidence <= maximum
}

export const routerObservationHandlers = [
  http.get('/api/v1/router-observations', ({ request }) => {
    const url = new URL(request.url)
    const limit = Number(url.searchParams.get('limit') || 20)
    const offset = Number(url.searchParams.get('cursor') || 0)
    const filtered = routerObservations.filter(item => matches(item, url))
    const items = filtered.slice(offset, offset + limit).map(({ evidence: _evidence, history: _history, ...item }) => item)
    return HttpResponse.json({ items, page: { limit, next_cursor: offset + items.length < filtered.length ? String(offset + items.length) : null, total: filtered.length } })
  }),
  http.get('/api/v1/router-observations/:assessmentId', ({ params }) => {
    const item = routerObservations.find(entry => entry.assessment_id === params.assessmentId)
    return item ? HttpResponse.json(item) : HttpResponse.json({ code: 'not_found', message: '路由观察不存在' }, { status: 404 })
  }),
]
