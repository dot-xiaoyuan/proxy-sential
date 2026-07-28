import type {
  ActivityOverview,
  ActivityOverviewQuery,
  AuditLog,
  CreateLabelRequest,
  DpiFlowDetail,
  DpiFlowListResponse,
  DpiOverview,
  DpiProtocolFlowItem,
  DpiTrendPoint,
  Evidence,
  EventListResponse,
  EventQuery,
  EventTypeCount,
  FingerprintConflictItem,
  IngestDiagnostic,
  IngestStatus,
  IpActivityProfile,
  Label,
  NormalizedEventSummary,
  Overview,
  RiskListResponse,
  RiskQuery,
  RiskSnapshot,
  RuleReloadResult,
  Session,
  ShadowRun,
} from './types'

export function getApiBase(): string {
  const envBase = import.meta.env.VITE_API_BASE
  if (envBase) {
    return envBase.replace(/\/+$/, '')
  }
  return '/api/v1'
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const baseUrl = getApiBase()
  const cleanPath = path.startsWith('/') ? path : `/${path}`
  const response = await fetch(`${baseUrl}${cleanPath}`, {
    headers: {
      'content-type': 'application/json',
      ...init?.headers,
    },
    ...init,
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(text || `HTTP ${response.status}`)
  }

  return response.json() as Promise<T>
}

function search(params: Record<string, string | number | undefined>) {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') {
      query.set(key, String(value))
    }
  }
  const text = query.toString()
  return text ? `?${text}` : ''
}

export const api = {
  session: () => request<Session>('/session'),
  overview: () => request<Overview>('/overview'),
  activityOverview: (query: ActivityOverviewQuery) =>
    request<ActivityOverview>(`/activity/overview${search(query)}`),
  dpiOverview: (query: ActivityOverviewQuery) =>
    request<DpiOverview>(`/dpi/overview${search(query)}`),
  dpiTrends: (query: ActivityOverviewQuery) =>
    request<{ points: DpiTrendPoint[] }>(`/dpi/trends${search(query)}`),
  dpiProtocolFlows: (query: ActivityOverviewQuery) =>
    request<{ items: DpiProtocolFlowItem[] }>(`/dpi/protocol-flows${search(query)}`),
  dpiFingerprintConflicts: (query: ActivityOverviewQuery) =>
    request<{ items: FingerprintConflictItem[] }>(`/dpi/fingerprint-conflicts${search(query)}`),
  dpiFlows: (query: EventQuery) => request<DpiFlowListResponse>(`/dpi/flows${search(query)}`),
  dpiIpFlows: (ip: string, query: EventQuery) =>
    request<DpiFlowListResponse>(`/dpi/ips/${encodeURIComponent(ip)}/flows${search(query)}`),
  dpiFlow: (flowId: string) =>
    request<DpiFlowDetail>(`/dpi/flows/${encodeURIComponent(flowId)}`),
  risks: (query: RiskQuery) => request<RiskListResponse>(`/risks${search(query)}`),
  ipRisk: (ip: string) => request<RiskSnapshot>(`/ips/${encodeURIComponent(ip)}/risk`),
  ipEvidence: (ip: string) =>
    request<{ evidence: Evidence[] }>(`/ips/${encodeURIComponent(ip)}/evidence`),
  ipActivity: (ip: string, limit = 50) =>
    request<IpActivityProfile>(`/ips/${encodeURIComponent(ip)}/activity${search({ limit })}`),
  ipEvents: (ip: string, limit = 50) =>
    request<{ events: NormalizedEventSummary[] }>(
      `/ips/${encodeURIComponent(ip)}/events${search({ limit })}`,
    ),
  events: (query: EventQuery) => request<EventListResponse>(`/events${search(query)}`),
  ingestStatus: () => request<IngestStatus>('/ingest/status'),
  ingestRuns: () => request<{ runs: ShadowRun[] }>('/ingest/runs'),
  ingestDiagnostics: (limit = 50) =>
    request<{ diagnostics: IngestDiagnostic[] }>(`/ingest/diagnostics${search({ limit })}`),
  ingestEventTypes: () => request<{ event_types: EventTypeCount[] }>('/ingest/event-types'),
  ingestErrors: (limit = 50) =>
    request<{ diagnostics: IngestDiagnostic[] }>(`/ingest/errors${search({ limit })}`),
  createLabel: (payload: CreateLabelRequest) =>
    request<Label>('/labels', { method: 'POST', body: JSON.stringify(payload) }),
  shadowRuns: () => request<{ runs: ShadowRun[] }>('/shadow/runs'),
  auditLogs: (limit = 50) => request<{ logs: AuditLog[] }>(`/audit-logs${search({ limit })}`),
  reloadRules: () => request<RuleReloadResult>('/rules/reload', { method: 'POST' }),
}
