import { delay, http, HttpResponse } from 'msw'

import type { CreateLabelRequest } from '../shared/api/types'
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
  riskSnapshots,
  shadowRuns,
} from './fixtures'

function normalizeIp(value: string) {
  return decodeURIComponent(value)
}

export const handlers = [
  http.get('/api/v1/session', async () => {
    await delay(120)
    return HttpResponse.json(mockSession)
  }),
  http.get('/api/v1/overview', async () => {
    await delay(160)
    return HttpResponse.json(overview)
  }),
  http.get('/api/v1/activity/overview', ({ request }) => {
    const url = new URL(request.url)
    const windowValue = url.searchParams.get('window') ?? '1h'
    return HttpResponse.json(getActivityOverviewByWindow(windowValue))
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
  http.get('/api/v1/devices', () =>
    HttpResponse.json({
      items: Object.values(deviceInventoriesByIp),
      page: { limit: 50, next_cursor: null, total: Object.values(deviceInventoriesByIp).length },
    }),
  ),
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
  http.get('/api/v1/ingest/status', () => HttpResponse.json(ingestStatus)),
  http.get('/api/v1/ingest/runs', () => HttpResponse.json({ runs: shadowRuns })),
  http.get('/api/v1/ingest/diagnostics', () => HttpResponse.json({ diagnostics: ingestDiagnostics })),
  http.get('/api/v1/ingest/event-types', () => HttpResponse.json({ event_types: ingestEventTypes })),
  http.get('/api/v1/ingest/errors', () =>
    HttpResponse.json({ diagnostics: ingestDiagnostics.filter((item) => item.severity !== 'info') }),
  ),
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
  http.get('/api/v1/shadow/runs', () => HttpResponse.json({ runs: shadowRuns })),
  http.get('/api/v1/audit-logs', () => HttpResponse.json({ logs: auditLogs })),
  http.post('/api/v1/rules/reload', () =>
    HttpResponse.json(
      { status: 'accepted', mode: 'shadow', requested_at: new Date().toISOString() },
      { status: 202 },
    ),
  ),
]

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
