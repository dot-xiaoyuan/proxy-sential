import type {
  ActivityOverview,
  ActivityOverviewQuery,
  AccountIdentityProfile,
  AuditLog,
  AuditLogListResponse,
  CreateLabelRequest,
  DpiFlowDetail,
  DpiFlowListResponse,
  DpiOverview,
  DpiProtocolFlowItem,
  DpiTrendPoint,
  DeviceConflict,
  DeviceListResponse,
  DeviceQuery,
  DeviceSignal,
  EndpointEntity,
  Evidence,
  EventListResponse,
  EventQuery,
  EvidenceQuery,
  EventTypeCount,
  FingerprintConflictItem,
  IngestDiagnostic,
  IngestStatus,
  IngestDiagnosticListResponse,
  IpDeviceInventory,
  IpActivityProfile,
  EndpointIdentityProfile,
  IdentityQuery,
  Label,
  NormalizedEventSummary,
  ObservedDevice,
  Overview,
  ProxyReviewQuery,
  ProxyReviewResponse,
  RiskListResponse,
  RiskQuery,
  RiskSnapshot,
  RuleReloadResult,
  Session,
  ShadowRun,
  ShadowRunListResponse,
  ShadowEvaluation,
  UpdateEndpointRegistrationRequest,
  ListQuery,
  DeviceFingerprintLibraryStatus,
  DeviceFingerprintBundleManifest,
  ProxyReviewCase,
	LoginRequest,
	RiskCase,
	RiskCaseListResponse,
	Organization,
	ActionConnector,
	EnforcementAction,
	Page,
	LocalUser,
	UserMutation,
	CampusException,
} from './types'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status=status }
}

let csrfToken = ''

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
  const headers = new Headers(init?.headers)
  if (!(init?.body instanceof FormData) && !headers.has('content-type')) headers.set('content-type','application/json')
  if (init?.method && init.method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
  const response = await fetch(`${baseUrl}${cleanPath}`, {
    headers,
    credentials: 'include',
    ...init,
  })

  if (!response.ok) {
    const text = await response.text()
    throw new ApiError(response.status, text || `HTTP ${response.status}`)
  }

  if (response.status === 204) return undefined as T

  return response.json() as Promise<T>
}

function search(params: Record<string, string | number | boolean | undefined>) {
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
  session: async () => { const session=await request<Session>('/session');csrfToken=session.csrf_token??'';return session },
  login: async (payload:LoginRequest) => { const session=await request<Session>('/auth/login',{method:'POST',body:JSON.stringify(payload)});csrfToken=session.csrf_token??'';return session },
  logout: async () => { await request<void>('/auth/logout',{method:'POST'});csrfToken='' },
  overview: (query: ActivityOverviewQuery = {}) => request<Overview>(`/overview${search(query)}`),
  activityOverview: (query: ActivityOverviewQuery) =>
    request<ActivityOverview>(`/activity/overview${search(query)}`),
  proxyReviews: (query: ProxyReviewQuery) =>
    request<ProxyReviewResponse>(`/proxy-reviews${search(query)}`),
  proxyReview: (caseId: string, window: '24h' | '7d') =>
    request<ProxyReviewCase>(`/proxy-reviews/${encodeURIComponent(caseId)}${search({ window })}`),
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
  devices: (query: DeviceQuery) => request<DeviceListResponse>(`/devices${search(query)}`),
  device: (deviceId: string, query: DeviceQuery) =>
    request<ObservedDevice>(`/devices/${encodeURIComponent(deviceId)}${search(query)}`),
  deviceSignals: (query: DeviceQuery) =>
    request<{ items: DeviceSignal[] }>(`/device-signals${search(query)}`),
  deviceFingerprintConflicts: (query: DeviceQuery) =>
    request<{ items: DeviceConflict[] }>(`/device-fingerprint-conflicts${search(query)}`),
  risks: (query: RiskQuery) => request<RiskListResponse>(`/risks${search(query)}`),
  ipRisk: (ip: string) => request<RiskSnapshot>(`/ips/${encodeURIComponent(ip)}/risk`),
  ipEvidence: (ip: string, query: EvidenceQuery = {}) =>
    request<{ evidence: Evidence[] }>(`/ips/${encodeURIComponent(ip)}/evidence${search(query)}`),
  ipActivity: (ip: string, limit = 50) =>
    request<IpActivityProfile>(`/ips/${encodeURIComponent(ip)}/activity${search({ limit })}`),
  ipDevices: (ip: string, query: DeviceQuery = {}) =>
    request<IpDeviceInventory>(`/ips/${encodeURIComponent(ip)}/devices${search(query)}`),
  ipEvents: (ip: string, limit = 50) =>
    request<{ events: NormalizedEventSummary[] }>(
      `/ips/${encodeURIComponent(ip)}/events${search({ limit })}`,
    ),
  accountIdentity: (accountId: string, query: IdentityQuery = {}) =>
    request<AccountIdentityProfile>(
      `/accounts/${encodeURIComponent(accountId)}/identity${search(query)}`,
    ),
  endpointIdentity: (endpointId: string, query: IdentityQuery = {}) =>
    request<EndpointIdentityProfile>(
      `/endpoints/${encodeURIComponent(endpointId)}/identity${search(query)}`,
    ),
  updateEndpointRegistration: (endpointId: string, payload: UpdateEndpointRegistrationRequest) =>
    request<EndpointEntity>(`/endpoints/${encodeURIComponent(endpointId)}/registration`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  events: (query: EventQuery) => request<EventListResponse>(`/events${search(query)}`),
  event: (eventId: string) => request<NormalizedEventSummary>(`/events/${encodeURIComponent(eventId)}`),
  ingestStatus: () => request<IngestStatus>('/ingest/status'),
  ingestRuns: (query: ListQuery = {}) => request<ShadowRunListResponse>(`/ingest/runs${search(query)}`),
  ingestDiagnostics: (query: ListQuery = {}) =>
    request<IngestDiagnosticListResponse>(`/ingest/diagnostics${search(query)}`),
  ingestDiagnostic: (diagnosticId: string) =>
    request<IngestDiagnostic>(`/ingest/diagnostics/${encodeURIComponent(diagnosticId)}`),
  ingestEventTypes: () => request<{ event_types: EventTypeCount[] }>('/ingest/event-types'),
  ingestErrors: (query: ListQuery = {}) =>
    request<IngestDiagnosticListResponse>(`/ingest/errors${search(query)}`),
  createLabel: (payload: CreateLabelRequest) =>
    request<Label>('/labels', { method: 'POST', body: JSON.stringify(payload) }),
  shadowRuns: (query: ListQuery = {}) => request<ShadowRunListResponse>(`/shadow/runs${search(query)}`),
  shadowRun: (runId: string) => request<ShadowRun>(`/shadow/runs/${encodeURIComponent(runId)}`),
  shadowEvaluation: () => request<ShadowEvaluation>('/shadow/evaluation'),
  auditLogs: (query: ListQuery = {}) => request<AuditLogListResponse>(`/audit-logs${search(query)}`),
  auditLog: (auditId: string) => request<AuditLog>(`/audit-logs/${encodeURIComponent(auditId)}`),
  deviceFingerprintLibrary: () => request<DeviceFingerprintLibraryStatus>('/device-fingerprint-library'),
  updateDeviceFingerprintLibrary: () => request<DeviceFingerprintLibraryStatus>('/device-fingerprint-library/update', { method: 'POST' }),
  validateDeviceFingerprintBundle: (file: File) => { const body=new FormData();body.append('bundle',file);return request<DeviceFingerprintBundleManifest>('/device-fingerprint-library/validate',{method:'POST',body}) },
  importDeviceFingerprintBundle: (file: File) => { const body=new FormData();body.append('bundle',file);return request<DeviceFingerprintLibraryStatus>('/device-fingerprint-library/import',{method:'POST',body}) },
  reloadRules: () => request<RuleReloadResult>('/rules/reload', { method: 'POST' }),
  cases: (query: ListQuery & {status?:string;assignee_id?:string;campus_id?:string;window?:string} = {}) => request<RiskCaseListResponse>(`/cases${search(query)}`),
  caseDetail: (caseId:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}`),
  assignCase: (caseId:string,assignee_id:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/assign`,{method:'POST',body:JSON.stringify({assignee_id})}),
  updateCaseStatus: (caseId:string,status:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/status`,{method:'POST',body:JSON.stringify({status})}),
  resolveCase: (caseId:string,disposition:string,reason:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/disposition`,{method:'POST',body:JSON.stringify({disposition,reason})}),
  commentCase: (caseId:string,comment:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/comments`,{method:'POST',body:JSON.stringify({comment})}),
  organization: () => request<Organization>('/organization'),
  saveOrganization: <T>(kind:string,payload:T) => request<T>(`/organization/${kind}`,{method:'POST',body:JSON.stringify(payload)}),
  actionConnectors: () => request<{items:ActionConnector[];global_stop:boolean}>('/actions/connectors'),
  saveActionConnector: (payload:ActionConnector & {secret?:string}) => request<ActionConnector>('/actions/connectors',{method:'POST',body:JSON.stringify(payload)}),
  actions: (query:ListQuery={}) => request<{items:EnforcementAction[];page:Page}>(`/actions${search(query)}`),
  executeAction: (payload:{case_id?:string;connector_id:string;action_type:string;ip:string;campus_id?:string;duration_seconds?:number},idempotencyKey:string) => request<EnforcementAction>('/actions/execute',{method:'POST',headers:{'Idempotency-Key':idempotencyKey},body:JSON.stringify(payload)}),
  revokeAction: (actionId:string) => request<EnforcementAction>(`/actions/${encodeURIComponent(actionId)}/revoke`,{method:'POST'}),
  emergencyStop: (enabled:boolean) => request<{global_stop:boolean}>('/actions/emergency-stop',{method:'POST',body:JSON.stringify({enabled})}),
  users: () => request<{items:LocalUser[];page:Page}>('/users'),
  createUser: (payload:UserMutation) => request<LocalUser>('/users',{method:'POST',body:JSON.stringify(payload)}),
  updateUser: (userId:string,operation:'profile'|'password'|'disable'|'enable',payload:UserMutation={}) => request<LocalUser>(`/users/${encodeURIComponent(userId)}/${operation}`,{method:'POST',body:JSON.stringify(payload)}),
  campusExceptions: () => request<{items:CampusException[];page:Page}>('/campus-exceptions'),
  createCampusException: (payload:CampusException) => request<CampusException>('/campus-exceptions',{method:'POST',body:JSON.stringify(payload)}),
  disableCampusException: (exceptionId:string) => request<CampusException>(`/campus-exceptions/${encodeURIComponent(exceptionId)}/disable`,{method:'POST',body:'{}'}),
}
