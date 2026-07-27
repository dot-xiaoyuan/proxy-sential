import { delay, http, HttpResponse } from 'msw'

import type { CreateLabelRequest } from '../shared/api/types'
import {
  activityByIp,
  auditLogs,
  eventsByIp,
  evidenceByIp,
  ingestDiagnostics,
  ingestEventTypes,
  ingestStatus,
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
  http.get('/api/v1/ips/:ip/events', ({ params }) => {
    const ip = normalizeIp(String(params.ip))
    return HttpResponse.json({ events: eventsByIp[ip] ?? [] })
  }),
  http.get('/api/v1/events', ({ request }) => {
    const url = new URL(request.url)
    const q = url.searchParams.get('q')?.toLowerCase()
    const eventType = url.searchParams.get('type')
    const limit = Number(url.searchParams.get('limit') ?? 50)
    const allEvents = Object.values(eventsByIp).flat()
    const filtered = allEvents
      .filter((event) => !eventType || event.type === eventType)
      .filter((event) => !q || event.event_id.toLowerCase().includes(q) || JSON.stringify(event.subject).toLowerCase().includes(q))
      .slice(0, limit)
    return HttpResponse.json({ events: filtered })
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
