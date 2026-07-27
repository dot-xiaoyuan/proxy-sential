import type {
  AuditLog,
  CreateLabelRequest,
  Evidence,
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

const API_BASE = '/api/v1'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
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
  risks: (query: RiskQuery) => request<RiskListResponse>(`/risks${search(query)}`),
  ipRisk: (ip: string) => request<RiskSnapshot>(`/ips/${encodeURIComponent(ip)}/risk`),
  ipEvidence: (ip: string) =>
    request<{ evidence: Evidence[] }>(`/ips/${encodeURIComponent(ip)}/evidence`),
  ipEvents: (ip: string, limit = 50) =>
    request<{ events: NormalizedEventSummary[] }>(
      `/ips/${encodeURIComponent(ip)}/events${search({ limit })}`,
    ),
  createLabel: (payload: CreateLabelRequest) =>
    request<Label>('/labels', { method: 'POST', body: JSON.stringify(payload) }),
  shadowRuns: () => request<{ runs: ShadowRun[] }>('/shadow/runs'),
  auditLogs: (limit = 50) => request<{ logs: AuditLog[] }>(`/audit-logs${search({ limit })}`),
  reloadRules: () => request<RuleReloadResult>('/rules/reload', { method: 'POST' }),
}
