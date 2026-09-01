import { delay, http, HttpResponse } from 'msw'

import type { CreateLabelRequest, RiskCase } from '../shared/api/types'
import {
  activityByIp,
  getActivityOverviewByWindow,
  auditLogs,
  deviceInventoriesByIp,
  eventsByIp,
  evidenceByIp,
  ingestDiagnostics,
  ingestEventTypes,
  ingestStatus,
  mockDpiProtocolFlows,
  mockDpiTrendPoints,
  mockFingerprintConflicts,
  mockFlowSamples,
  mockSession,
  overview,
  proxyReviewResponse,
  riskSnapshots,
  shadowRuns,
  shadowEvaluation,
} from './fixtures'

function normalizeIp(value: string) {
  return decodeURIComponent(value)
}

const mockCases: RiskCase[] = proxyReviewResponse.items.map((item, index) => ({
  case_id: item.case_id,
  subject_type: 'ip',
  subject_id: item.ip,
  ip: item.ip,
  account_id: item.account_id,
  endpoint_id: item.endpoint_id,
  campus_id: index === 0 ? 'main' : 'north',
  status: index === 0 ? 'investigating' as const : 'new' as const,
  priority: item.risk_score >= 90 ? 'high' as const : 'medium' as const,
  risk_score: item.risk_score,
  risk_confidence: Math.min(0.99, Math.max(0.5, item.risk_score / 100)),
  assessment_level: item.risk_score >= 90 ? 'high' : 'medium',
  due_at: new Date(Date.now() + (index - 1) * 3_600_000).toISOString(),
  first_seen: item.first_seen,
  last_seen: item.last_seen,
  created_at: item.first_seen,
  updated_at: item.last_seen,
  comments: [],
  timeline: [{ event_id: `timeline-${index}`, actor_id: 'system', type: 'case.created', created_at: item.first_seen }],
  evidence_snapshot: item,
}))

const mockOrganization = {
  campuses: [{ campus_id: 'main', code: 'MAIN', name: '主校区', enabled: true }, { campus_id: 'north', code: 'NORTH', name: '北校区', enabled: true }],
  buildings: [{ building_id: 'lib', campus_id: 'main', code: 'LIB', name: '图书馆', enabled: true }],
  network_zones: [{ network_zone_id: 'student-wifi', campus_id: 'main', name: '学生无线网', cidrs: ['10.20.0.0/16'], ssids: ['Campus-WiFi'], vlans: ['120'], enabled: true }],
  access_points: [{ access_point_id: 'ap-lib-01', campus_id: 'main', building_id: 'lib', network_zone_id: 'student-wifi', kind: 'ap', name: '图书馆一层 AP', management_ip: '10.1.1.10', enabled: true }],
}

const mockConnectors = [{ connector_id: 'portal-gateway', name: 'Portal 北向网关', endpoint_url: 'https://portal.example.edu/api/actions', action_mapping: { disconnect: 'kick' }, mode: 'shadow' as const, enabled: true, shadow_ready: false, updated_at: new Date().toISOString() }]
const mockActions: Array<Record<string, unknown>> = []

export const handlers = [
  http.get('/api/v1/session', async () => {
    await delay(120)
    return HttpResponse.json(mockSession)
  }),
  http.post('/api/v1/auth/login', () => HttpResponse.json(mockSession)),
  http.post('/api/v1/auth/logout', () => new HttpResponse(null, { status: 204 })),
  http.get('/api/v1/cases', ({ request }) => {
    const url = new URL(request.url)
    const result = mockPage(mockCases.filter((item) => !url.searchParams.get('status') || item.status === url.searchParams.get('status')), url)
    return HttpResponse.json(result)
  }),
  http.get('/api/v1/cases/:caseId', ({ params }) => {
    const item = mockCases.find((entry) => entry.case_id === params.caseId)
    return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 })
  }),
  http.post('/api/v1/cases/:caseId/:operation', async ({ params, request }) => {
    const item = mockCases.find((entry) => entry.case_id === params.caseId)
    if (!item) return new HttpResponse(null, { status: 404 })
    const payload = await request.json() as Record<string, string>
    if (params.operation === 'assign') Object.assign(item, { assignee_id: payload.assignee_id, status: 'assigned' })
    if (params.operation === 'status') Object.assign(item, { status: payload.status })
    if (params.operation === 'disposition') Object.assign(item, { disposition: payload.disposition, status: 'resolved' })
    if (params.operation === 'comments') (item.comments ??= []).push({ comment_id: `comment-${Date.now()}`, author_id: mockSession.user.id, body: payload.body, created_at: new Date().toISOString() })
    return HttpResponse.json(item)
  }),
  http.get('/api/v1/organization', () => HttpResponse.json(mockOrganization)),
  http.get('/api/v1/actions/connectors', () => HttpResponse.json({ items: mockConnectors, global_stop: false })),
  http.get('/api/v1/actions', ({ request }) => { const result = mockPage(mockActions, new URL(request.url)); return HttpResponse.json(result) }),
  http.post('/api/v1/actions/execute', async ({ request }) => {
    const payload = await request.json() as Record<string, string>
    const action = { ...payload, action_id: `action-${Date.now()}`, idempotency_key: 'mock', subject_id: payload.ip, mode: 'shadow', status: 'shadow', blockers: [], created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
    mockActions.unshift(action)
    return HttpResponse.json(action, { status: 202 })
  }),
  http.post('/api/v1/actions/:actionId/revoke', ({ params }) => HttpResponse.json({ action_id: params.actionId, status: 'revoked', updated_at: new Date().toISOString() })),
  http.post('/api/v1/actions/emergency-stop', () => HttpResponse.json({ global_stop: true })),
  http.get('/api/v1/overview', async () => {
    await delay(160)
    return HttpResponse.json(overview)
  }),
  http.get('/api/v1/activity/overview', ({ request }) => {
    const url = new URL(request.url)
    const windowValue = url.searchParams.get('window') ?? '1h'
    return HttpResponse.json(getActivityOverviewByWindow(windowValue))
  }),
  http.get('/api/v1/proxy-reviews', ({ request }) => {
    const url = new URL(request.url)
    const window = url.searchParams.get('window') === '24h' ? '24h' : '7d'
    const page = mockPage(proxyReviewResponse.items, url)
    return HttpResponse.json({ ...proxyReviewResponse, window, items: page.items, page: page.page })
  }),
  http.get('/api/v1/proxy-reviews/:caseId', ({ params }) => {
    const item = proxyReviewResponse.items.find((entry) => entry.case_id === params.caseId)
    return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 })
  }),
  http.get('/api/v1/dpi/overview', ({ request }) => {
    const url = new URL(request.url)
    const windowValue = url.searchParams.get('window') ?? '1h'
    const activity = getActivityOverviewByWindow(windowValue)
    return HttpResponse.json({
      sensor_id: activity.sensor_id,
      window: activity.window,
      event_count: activity.event_count,
      active_ip_count: activity.active_ip_count,
      protocol_flow_count: mockDpiProtocolFlows.length,
      fingerprint_conflict_count: mockFingerprintConflicts.length,
      flow_sample_count: Object.values(mockFlowSamples).flat().length,
      first_seen: activity.first_seen,
      last_seen: activity.last_seen,
    })
  }),
  http.get('/api/v1/dpi/trends', () => HttpResponse.json({ points: mockDpiTrendPoints })),
  http.get('/api/v1/dpi/protocol-flows', () => HttpResponse.json({ items: mockDpiProtocolFlows })),
  http.get('/api/v1/dpi/fingerprint-conflicts', () => HttpResponse.json({ items: mockFingerprintConflicts })),
  http.get('/api/v1/dpi/flows', ({ request }) => {
    const url = new URL(request.url)
    return HttpResponse.json(filterMockFlows(url))
  }),
  http.get('/api/v1/dpi/flows/:flowId', ({ params }) => {
    const flowId = normalizeIp(String(params.flowId))
    const flow = Object.values(mockFlowSamples).flat().find((item) => item.flow_id === flowId || item.event_id === flowId)
    return flow
      ? HttpResponse.json({
          flow,
          event: Object.values(eventsByIp).flat().find((item) => item.event_id === flow.event_id) ?? eventsByIp['10.255.0.59'][0],
          risk: riskSnapshots.find((item) => item.ip === flow.src_ip) ?? riskSnapshots[3],
          evidence: evidenceByIp[flow.src_ip ?? ''] ?? [],
        })
      : HttpResponse.json({ code: 'not_found', message: 'dpi flow not found' }, { status: 404 })
  }),
  http.get('/api/v1/dpi/ips/:ip/flows', ({ params, request }) => {
    const url = new URL(request.url)
    url.searchParams.set('src_ip', normalizeIp(String(params.ip)))
    return HttpResponse.json(filterMockFlows(url))
  }),
  http.get('/api/v1/risks', ({ request }) => {
    const url = new URL(request.url)
    const level = url.searchParams.get('level')
    const q = url.searchParams.get('q')?.toLowerCase()
    const limit = Number(url.searchParams.get('limit') ?? 50)
    const filtered = riskSnapshots
      .filter((item) => !level || item.level === level)
      .filter((item) => !q || item.ip.toLowerCase().includes(q) || item.summary.toLowerCase().includes(q))
      .slice(0, limit)

    return HttpResponse.json({
      items: filtered,
      page: { limit, next_cursor: null, total: filtered.length },
    })
  }),
  http.get('/api/v1/ips/:ip/risk', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    const snapshot = riskSnapshots.find((item) => item.ip === ip)
    return snapshot ? HttpResponse.json(snapshot) : HttpResponse.json(riskSnapshots[3])
  }),
  http.get('/api/v1/ips/:ip/evidence', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json({ evidence: evidenceByIp[ip] ?? [] })
  }),
  http.get('/api/v1/ips/:ip/activity', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json(
      activityByIp[ip] ?? {
        ip,
        window: 'latest-run',
        event_count: 0,
        event_type_counts: [],
        protocol_counts: [],
        top_domains: [],
        top_http_hosts: [],
        top_tls_sni: [],
        top_user_agents: [],
        top_tls_fingerprints: [],
        top_dst_ports: [],
        top_dst_ips: [],
        recent_accesses: [],
      },
    )
  }),
  http.get('/api/v1/ips/:ip/devices', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json(
      deviceInventoriesByIp[ip] ?? {
        ip,
        window: '1h',
        suspected_device_count: 0,
        confidence: 0,
        status: 'insufficient_signal',
        summary: '当前标准事件中没有足够设备识别信号，无法判断该 IP 背后设备数量或品牌',
        devices: [],
        signals: [],
        conflicts: [],
      },
    )
  }),
  http.get('/api/v1/devices', ({ request }) => {
    const url = new URL(request.url)
    const q = url.searchParams.get('q')?.toLowerCase()
    const ip = url.searchParams.get('ip')
    const limit = Number(url.searchParams.get('limit') ?? 50)
    const cursor = Number(url.searchParams.get('cursor') ?? 0)
    const endpointItems = Object.values(deviceInventoriesByIp).flatMap((inventory) =>
      inventory.devices.map((device) => ({
        endpoint_id: device.endpoint_id || device.device_id,
        primary_mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
        entity_role: device.entity_role || 'endpoint',
        registration_status: device.endpoint_id ? 'registered' : 'unregistered',
        owner_account: device.account_id || '',
        owner_name: device.account_id ? '样本用户' : '',
        owner_department: device.account_id ? '网络中心' : '',
        asset_tag: device.endpoint_id ? `ASSET-${device.device_id.slice(-4)}` : '',
        merge_status: 'active',
        current_account: device.account_id || '',
        current_ip: inventory.ip,
        current_access_id: device.access_id || '',
        accounts: device.account_id ? [device.account_id] : [],
        ips: [inventory.ip],
        access_ids: device.access_id ? [device.access_id] : [],
        brand: device.brand || device.vendor || '',
        vendor: device.vendor || '',
        model: device.model || '',
        first_seen: device.first_seen || inventory.first_seen,
        last_seen: device.last_seen || inventory.last_seen,
        identity_confidence: device.confidence,
        summary: `${device.brand && device.brand !== 'unknown' ? device.brand + ' ' : ''}${device.model && device.model !== 'unknown' ? device.model + ' ' : ''}终端 ${device.endpoint_id || device.device_id}，观察到 1 个 IP`,
      })),
    )
    const filtered = endpointItems
      .filter((item) => !ip || item.current_ip === ip)
      .filter((item) => !q || JSON.stringify(item).toLowerCase().includes(q))
    const pageItems = filtered.slice(cursor, cursor + limit)
    const nextCursor = cursor + pageItems.length < filtered.length ? String(cursor + pageItems.length) : null

    return HttpResponse.json({
      items: pageItems,
      page: { limit, next_cursor: nextCursor, total: filtered.length },
    })
  }),
  http.get('/api/v1/endpoints/:endpointId/identity', ({ params }) => {
    const endpointId = decodeURIComponent(String(params.endpointId))
    for (const inventory of Object.values(deviceInventoriesByIp)) {
      const device = inventory.devices.find((item) => item.endpoint_id === endpointId || item.device_id === endpointId)
      if (!device) {
        continue
      }
      const accountId = device.account_id || '2026000123'
      return HttpResponse.json({
        endpoint_id: endpointId,
        summary: `终端 ${endpointId} 关联 1 个账号、1 个 IP 和 1 个接入位置`,
        endpoint: {
          endpoint_id: endpointId,
          primary_mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
          entity_role: 'endpoint',
          first_seen: device.first_seen || inventory.first_seen,
          last_seen: device.last_seen || inventory.last_seen,
          identity_confidence: device.confidence,
          attributes: {},
          registration_status: device.endpoint_id ? 'registered' : 'unregistered',
          owner_account: accountId,
          owner_name: '样本用户',
          owner_department: '网络中心',
          asset_tag: `ASSET-${device.device_id.slice(-4)}`,
          registration_note: 'Mock endpoint 登记样本',
          merge_status: 'active',
        },
        accounts: [accountId],
        sessions: [
          {
            session_id: `session-${device.device_id}`,
            account_id: accountId,
            endpoint_id: endpointId,
            ip: inventory.ip,
            mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
            access_id: device.access_id || 'Dorm-A-AP01',
            source: 'mock',
            started_at: device.first_seen || inventory.first_seen,
            ended_at: device.last_seen || inventory.last_seen,
            identity_confidence: device.confidence,
          },
        ],
        ip_history: [
          {
            event_id: `ip-${device.device_id}`,
            endpoint_id: endpointId,
            account_id: accountId,
            entity_role: 'endpoint',
            ip: inventory.ip,
            mac: device.signals.find((signal) => signal.kind === 'mac')?.normalized_value,
            source: 'mock',
            first_seen: inventory.first_seen,
            last_seen: inventory.last_seen,
            identity_confidence: device.confidence,
            event_ids_sample: [`event-device-${device.device_id}`],
          },
        ],
        access_history: [
          {
            event_id: `access-${device.device_id}`,
            endpoint_id: endpointId,
            account_id: accountId,
            entity_role: 'endpoint',
            access_id: device.access_id || 'Dorm-A-AP01',
            access_type: 'wireless',
            ap: device.access_id || 'Dorm-A-AP01',
            source: 'mock',
            first_seen: inventory.first_seen,
            last_seen: inventory.last_seen,
            identity_confidence: device.confidence,
            event_ids_sample: [`event-access-${device.device_id}`],
          },
        ],
        first_seen: device.first_seen || inventory.first_seen,
        last_seen: device.last_seen || inventory.last_seen,
      })
    }
    return HttpResponse.json({
      endpoint_id: endpointId,
      summary: `终端 ${endpointId} 暂无完整身份历史`,
      endpoint: {
        endpoint_id: endpointId,
        entity_role: 'endpoint',
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        identity_confidence: 0,
        attributes: {},
        registration_status: 'unregistered',
        merge_status: 'active',
      },
      accounts: [],
      sessions: [],
      ip_history: [],
      access_history: [],
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
    })
  }),
  http.get('/api/v1/device-signals', () =>
    HttpResponse.json({ items: Object.values(deviceInventoriesByIp).flatMap((item) => item.signals) }),
  ),
  http.get('/api/v1/device-fingerprint-conflicts', () =>
    HttpResponse.json({ items: Object.values(deviceInventoriesByIp).flatMap((item) => item.conflicts) }),
  ),
  http.get('/api/v1/ips/:ip/events', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json({ events: eventsByIp[ip] ?? [] })
  }),
  http.get('/api/v1/events', ({ request }) => {
    const url = new URL(request.url)
    const q = url.searchParams.get('q')?.toLowerCase()
    const eventType = url.searchParams.get('type')
    const domain = url.searchParams.get('domain')?.toLowerCase()
    const srcIp = url.searchParams.get('src_ip')
    const dstIp = url.searchParams.get('dst_ip')
    const userAgent = url.searchParams.get('user_agent')?.toLowerCase()
    const fingerprint = url.searchParams.get('fingerprint')?.toLowerCase()
    const proto = url.searchParams.get('proto')?.toLowerCase()
    const port = url.searchParams.get('port')
    const limit = Number(url.searchParams.get('limit') ?? 50)
    const cursor = Number(url.searchParams.get('cursor') ?? 0)
    const allEvents = Object.values(eventsByIp).flat()
    const filtered = allEvents
      .filter((event) => !eventType || event.type === eventType)
      .filter((event) => !q || event.event_id.toLowerCase().includes(q) || JSON.stringify(event.subject).toLowerCase().includes(q))
      .filter((event) => !domain || JSON.stringify(event.payload).toLowerCase().includes(domain))
      .filter((event) => !srcIp || event.flow?.src_ip === srcIp || event.subject?.ip === srcIp)
      .filter((event) => !dstIp || event.flow?.dst_ip === dstIp)
      .filter((event) => !userAgent || String(event.payload?.user_agent ?? '').toLowerCase().includes(userAgent))
      .filter((event) => !fingerprint || String(`${event.payload?.ja3 ?? ''} ${event.payload?.ja4 ?? ''}`).toLowerCase().includes(fingerprint))
      .filter((event) => !proto || String(event.flow?.proto ?? '').toLowerCase() === proto)
      .filter((event) => !port || String(event.flow?.dst_port ?? '') === port)
    const pageItems = filtered.slice(cursor, cursor + limit)
    const nextCursor = cursor + pageItems.length < filtered.length ? String(cursor + pageItems.length) : null
    return HttpResponse.json({ events: pageItems, page: { limit, next_cursor: nextCursor, total: filtered.length } })
  }),
  http.get('/api/v1/events/:eventId', ({ params }) => {
    const item = Object.values(eventsByIp).flat().find((entry) => entry.event_id === params.eventId)
    return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 })
  }),
  http.get('/api/v1/ingest/status', () => HttpResponse.json(ingestStatus)),
  http.get('/api/v1/ingest/runs', () => HttpResponse.json({ runs: shadowRuns })),
  http.get('/api/v1/ingest/diagnostics', ({ request }) => { const result = mockPage(ingestDiagnostics, new URL(request.url)); return HttpResponse.json({ diagnostics: result.items, page: result.page }) }),
  http.get('/api/v1/ingest/diagnostics/:diagnosticId', ({ params }) => { const item = ingestDiagnostics.find((entry) => entry.diagnostic_id === params.diagnosticId); return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 }) }),
  http.get('/api/v1/ingest/event-types', () => HttpResponse.json({ event_types: ingestEventTypes })),
  http.get('/api/v1/ingest/errors', ({ request }) => { const result = mockPage(ingestDiagnostics.filter((item) => item.severity !== 'info'), new URL(request.url)); return HttpResponse.json({ diagnostics: result.items, page: result.page }) }),
  http.post('/api/v1/labels', async ({ request }) => {
    const payload = (await request.json()) as CreateLabelRequest
    const created = {
      ...payload,
      label_id: `label-${Date.now()}`,
      created_by: mockSession.user.id,
      created_at: new Date().toISOString(),
    }
    auditLogs.unshift({
      audit_id: `audit-${Date.now()}`,
      actor: mockSession.user.id,
      action: 'labels.create',
      target: `${payload.target_type}:${payload.target_id}`,
      outcome: payload.label,
      created_at: created.created_at,
    })
    return HttpResponse.json(created, { status: 201 })
  }),
  http.get('/api/v1/shadow/runs', ({ request }) => { const result = mockPage(shadowRuns, new URL(request.url)); return HttpResponse.json({ runs: result.items, page: result.page }) }),
  http.get('/api/v1/shadow/runs/:runId', ({ params }) => { const item = shadowRuns.find((entry) => entry.run_id === params.runId); return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 }) }),
  http.get('/api/v1/shadow/evaluation', () => HttpResponse.json(shadowEvaluation)),
  http.get('/api/v1/audit-logs', ({ request }) => { const result = mockPage(auditLogs, new URL(request.url)); return HttpResponse.json({ logs: result.items, page: result.page }) }),
  http.get('/api/v1/audit-logs/:auditId', ({ params }) => { const item = auditLogs.find((entry) => entry.audit_id === params.auditId); return item ? HttpResponse.json(item) : new HttpResponse(null, { status: 404 }) }),
  http.get('/api/v1/device-fingerprint-library', () => HttpResponse.json({ version:'offline-20260831-mock',status:'ready',source:'offline-bundle',checksum:'mock',offline_mode:true,rule_count:860,oui_count:42000,dhcp_rule_count:310,licenses:['Apache-2.0','ODbL-1.0','DbCL-1.0'],backfill_status:'completed',backfill_processed:110 })),
  http.post('/api/v1/device-fingerprint-library/update', () => HttpResponse.json({ code:'offline_update_required',message:'import a verified bundle' },{status:409})),
  http.post('/api/v1/device-fingerprint-library/validate', () => HttpResponse.json({schema_version:'device-fingerprint-bundle/v1',version:'offline-20260831-mock',created_at:new Date().toISOString(),sources:[{name:'IEEE MA-L/MA-M/MA-S',version:'2026-08-31',url:'https://standards-oui.ieee.org/',license:'IEEE public registry'},{name:'uap-core',version:'mocksha',url:'https://github.com/ua-parser/uap-core',license:'Apache-2.0'},{name:'Fingerbank public snapshot',version:'6.8.2-20140609',url:'https://github.com/karottc/fingerbank',license:'ODbL-1.0/DbCL-1.0'}],files:{}})),
  http.post('/api/v1/device-fingerprint-library/import', () => HttpResponse.json({version:'offline-20260831-mock',status:'ready',source:'offline-bundle',checksum:'mock',offline_mode:true,rule_count:860,oui_count:42000,dhcp_rule_count:310,licenses:['Apache-2.0','ODbL-1.0','DbCL-1.0'],backfill_status:'pending',backfill_processed:0})),
  http.post('/api/v1/rules/reload', () =>
    HttpResponse.json(
      { status: 'accepted', mode: 'shadow', requested_at: new Date().toISOString() },
      { status: 202 },
    ),
  ),
]

function mockPage<T>(items: T[], url: URL) {
  const limit = Number(url.searchParams.get('limit') ?? 20)
  const cursor = Number(url.searchParams.get('cursor') ?? 0)
  const pageItems = items.slice(cursor, cursor + limit)
  return { items: pageItems, page: { limit, next_cursor: cursor + pageItems.length < items.length ? String(cursor + pageItems.length) : null, total: items.length } }
}

function filterMockFlows(url: URL) {
  const q = url.searchParams.get('q')?.toLowerCase()
  const domain = url.searchParams.get('domain')?.toLowerCase()
  const srcIp = url.searchParams.get('src_ip')
  const dstIp = url.searchParams.get('dst_ip')
  const userAgent = url.searchParams.get('user_agent')?.toLowerCase()
  const fingerprint = url.searchParams.get('fingerprint')?.toLowerCase()
  const proto = url.searchParams.get('proto')?.toLowerCase()
  const port = url.searchParams.get('port')
  const limit = Number(url.searchParams.get('limit') ?? 50)
  const cursor = Number(url.searchParams.get('cursor') ?? 0)
  const filtered = Object.values(mockFlowSamples)
    .flat()
    .filter((flow) => !q || JSON.stringify(flow).toLowerCase().includes(q))
    .filter((flow) => !domain || String(flow.domain ?? flow.tls_sni ?? '').toLowerCase().includes(domain))
    .filter((flow) => !srcIp || flow.src_ip === srcIp)
    .filter((flow) => !dstIp || flow.dst_ip === dstIp)
    .filter((flow) => !userAgent || String(flow.user_agent ?? '').toLowerCase().includes(userAgent))
    .filter((flow) => !fingerprint || String(`${flow.ja3 ?? ''} ${flow.ja4 ?? ''}`).toLowerCase().includes(fingerprint))
    .filter((flow) => !proto || String(flow.protocol ?? '').toLowerCase() === proto)
    .filter((flow) => !port || String(flow.dst_port ?? '') === port)
  const items = filtered.slice(cursor, cursor + limit)
  const nextCursor = cursor + items.length < filtered.length ? String(cursor + items.length) : null
  return { items, page: { limit, next_cursor: nextCursor, total: filtered.length } }
}
