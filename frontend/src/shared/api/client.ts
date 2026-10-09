import type { FourKSyncResult, ManagedIdentityConfiguration, ManagedIdentitySource, SRun4KIntegration, SRun4KSyncResult, SRun4KTestResult } from "./types"
import { awaitOperationTask, clearOperationTasks, isOperationTask, type OperationTask } from './operationTasks'
import type {
 FourKDatabaseConfig, FourKDatabaseResponse, FourKAuthorizationCheck,
  CaseHistoryKind,
  CaseHistoryResponse,
  NativeObservationPage,
  ActivityOverview,
  ActivityOverviewQuery,
	ActivityReport,
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
  DeviceInventoryListResponse,
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
  SystemStatus,
  ProxyReviewQuery,
  ProxyReviewResponse,
  RiskListResponse,
  RiskQuery,
  RiskSnapshot,
  RuleReloadResult,
  Session,
  ShadowRunListResponse,
  UpdateEndpointRegistrationRequest,
  ListQuery,
  DeviceFingerprintLibraryStatus,
  DeviceFingerprintBundleManifest,
  ProxyReviewCase,
	LoginRequest,
	RiskCase,
	RiskCaseListResponse,
	Organization,
	OrganizationKind,
	OrganizationListResponse,
	ActionConnector,
	EnforcementAction,
	Page,
	LocalUser,
	UserMutation,
	CampusException,
  DeviceRecognitionSummary,
  RouterAssessmentPage,
  RouterObservationDetail,
  RouterObservationQuery,
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

export async function request<T>(path: string, init?: RequestInit & { deferTaskPolling?: boolean }): Promise<T> {
  const baseUrl = getApiBase()
  const cleanPath = path.startsWith('/') ? path : `/${path}`
  const headers = new Headers(init?.headers)
  if (!(init?.body instanceof FormData) && !headers.has('content-type')) headers.set('content-type','application/json')
  if (init?.method && init.method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
  const { deferTaskPolling, ...fetchInit } = init ?? {}
 const response = await fetch(`${baseUrl}${cleanPath}`, {
    credentials: 'include',
    ...fetchInit,
    headers,
  })

  if (!response.ok) {
    const text = await response.text()
    throw new ApiError(response.status, text || `HTTP ${response.status}`)
  }

  if (response.status === 204) return undefined as T

  const payload: unknown = await response.json()
  if (response.status === 202 && !deferTaskPolling && isOperationTask(payload)) {
    const task = await awaitOperationTask(payload, id => request<OperationTask>(`/tasks/${encodeURIComponent(id)}`))
    if (task.status !== 'completed') throw new ApiError(task.response_status || 409, task.result ? JSON.stringify(task.result) : task.error || '任务已取消')
    return task.result as T
  }
  return payload as T
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
  logout: async () => { await request<void>('/auth/logout',{method:'POST'});csrfToken='';clearOperationTasks() },
  overview: (query: ActivityOverviewQuery = {}) => request<Overview>(`/overview${search(query)}`),
  systemStatus: () => request<SystemStatus>('/system/status'),
  activityOverview: (query: ActivityOverviewQuery) =>
    request<ActivityOverview>(`/activity/overview${search(query)}`),
  activityReport: (query:ActivityOverviewQuery & {dimension:string;limit?:number}) => request<ActivityReport>(`/activity/reports${search(query)}`),
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
  deviceInventory: (query: DeviceQuery) => request<DeviceInventoryListResponse>(`/device-inventory${search(query)}`),
  deviceRecognitionSummary: () => request<DeviceRecognitionSummary>('/device-recognition/summary'),
  routerObservations: (query: RouterObservationQuery = {}) =>
    request<RouterAssessmentPage>(`/router-observations${search(query)}`),
  routerObservation: (assessmentId: string) =>
    request<RouterObservationDetail>(`/router-observations/${encodeURIComponent(assessmentId)}`),
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
  deviceNameEvidence: (endpointId: string, offset = 0) => request<{items: {value: string;source: string;kind: string;event_id?: string;sensor_id: string;address?: string;observed_at: string;valid_until: string;attribution: string}[];total: number}>(`/endpoints/${encodeURIComponent(endpointId)}/name-evidence?limit=20&offset=${offset}`),
  updateDeviceName: (endpointId: string, value: string) => request(`/endpoints/${encodeURIComponent(endpointId)}/name-note`, {method: 'POST', body: JSON.stringify({value})}),
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
  auditLogs: (query: ListQuery = {}) => request<AuditLogListResponse>(`/audit-logs${search(query)}`),
  auditLog: (auditId: string) => request<AuditLog>(`/audit-logs/${encodeURIComponent(auditId)}`),
  deviceFingerprintLibrary: () => request<DeviceFingerprintLibraryStatus>('/device-fingerprint-library'),
  updateDeviceFingerprintLibrary: () => request<DeviceFingerprintLibraryStatus>('/device-fingerprint-library/update', { method: 'POST' }),
  validateDeviceFingerprintBundle: (file: File) => { const body=new FormData();body.append('bundle',file);return request<DeviceFingerprintBundleManifest>('/device-fingerprint-library/validate',{method:'POST',body}) },
  importDeviceFingerprintBundle: (file: File) => { const body=new FormData();body.append('bundle',file);return request<DeviceFingerprintLibraryStatus>('/device-fingerprint-library/import',{method:'POST',body}) },
  reloadRules: () => request<RuleReloadResult>('/rules/reload', { method: 'POST' }),
  cases: (query: ListQuery & {status?:string;assignee_id?:string;campus_id?:string;department?:string;person_type?:string;ssid?:string;vlan?:string;ap?:string;nas_ip?:string;window?:string;include_router_observations?:boolean} = {}) => request<RiskCaseListResponse>(`/cases${search(query)}`),
  caseHistory: (caseId:string,kind:CaseHistoryKind,cursor="0") => request<CaseHistoryResponse>(`/cases/${encodeURIComponent(caseId)}/history/${kind}${search({limit:20,cursor})}`),
  caseDetail: (caseId:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}`),
  assignCase: (caseId:string,assignee_id:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/assign`,{method:'POST',body:JSON.stringify({assignee_id})}),
  updateCaseStatus: (caseId:string,status:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/status`,{method:'POST',body:JSON.stringify({status})}),
  updateCasePriority: (caseId:string,priority:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/priority`,{method:'POST',body:JSON.stringify({priority})}),
  resolveCase: (caseId:string,disposition:string,reason:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/disposition`,{method:'POST',body:JSON.stringify({disposition,reason})}),
  commentCase: (caseId:string,comment:string) => request<RiskCase>(`/cases/${encodeURIComponent(caseId)}/comments`,{method:'POST',body:JSON.stringify({comment})}),
  mutateCasesBatch: (case_ids:string[],operation:'assign'|'close',assignee_id?:string) => request<{items:RiskCase[];updated:number}>('/cases/batch',{method:'POST',body:JSON.stringify({case_ids,operation,assignee_id})}),
  organization: () => request<Organization>('/organization'),
  organizationList: <K extends OrganizationKind>(kind:K,query:ListQuery={}) => request<OrganizationListResponse<K>>(`/organization${search({...query,kind})}`),
  saveOrganization: <T>(kind:string,payload:T) => request<T>(`/organization/${kind}`,{method:'POST',body:JSON.stringify(payload)}),
  actionConnectors: () => request<{items:ActionConnector[];global_stop:boolean}>('/actions/connectors'),
  saveActionConnector: (payload:ActionConnector & {secret?:string}) => request<ActionConnector>('/actions/connectors',{method:'POST',body:JSON.stringify(payload)}),
  identitySource: (id: string) => request<ManagedIdentitySource>(`/actions/connectors/${encodeURIComponent(id)}/identity-source`),
  saveIdentitySource: (id: string, value: {configuration: ManagedIdentityConfiguration; config_version: number}) => request<ManagedIdentitySource>(`/actions/connectors/${encodeURIComponent(id)}/identity-source`, {method: 'PUT', body: JSON.stringify(value)}),
  fourKDatabase: (id: string) => request<FourKDatabaseResponse>(`/actions/connectors/${encodeURIComponent(id)}/4k-database`),
  saveFourKDatabase: (id: string, value: FourKDatabaseConfig) => request<FourKDatabaseResponse>(`/actions/connectors/${encodeURIComponent(id)}/4k-database`, { method: 'PUT', body: JSON.stringify(value) }),
  checkFourKDatabase: (id: string) => request<FourKAuthorizationCheck>(`/actions/connectors/${encodeURIComponent(id)}/4k-database`, { method: 'POST' }),
  syncFourK: (id: string, source = 'srun-office') => request<FourKSyncResult>(`/actions/connectors/${encodeURIComponent(id)}/4k-sync`, { method: 'POST', body: JSON.stringify({ source }) }),
  srun4KIntegrations: () => request<{items:SRun4KIntegration[]}>('/integrations/srun4k'),
  srun4KIntegration: (id: string) => request<SRun4KIntegration>(`/integrations/srun4k/${encodeURIComponent(id)}`),
  createSRun4KIntegration: (value: {host:string;reconcile_interval_hours?:number}) => request<SRun4KIntegration>('/integrations/srun4k', {method:'POST',body:JSON.stringify(value)}),
  updateSRun4KIntegration: (id: string, value: {host:string;reconcile_interval_hours?:number}) => request<SRun4KIntegration>(`/integrations/srun4k/${encodeURIComponent(id)}`, {method:'PUT',body:JSON.stringify(value)}),
  testSRun4KIntegration: (id: string) => request<SRun4KTestResult>(`/integrations/srun4k/${encodeURIComponent(id)}/test`, {method:'POST'}),
  syncSRun4KIntegration: (id: string) => request<SRun4KSyncResult>(`/integrations/srun4k/${encodeURIComponent(id)}/sync`, {method:'POST'}),
  testActionConnector: (connectorId:string) => request<{connector_id:string;reachable:boolean;checked_at:string;identity_verified?:boolean}>(`/actions/connectors/${encodeURIComponent(connectorId)}/test`,{method:'POST'}),
  actions: (query:ListQuery={}) => request<{items:EnforcementAction[];page:Page}>(`/actions${search(query)}`),
  executeAction: (payload:{case_id?:string;connector_id:string;action_type:string;ip:string;campus_id?:string;duration_seconds?:number},idempotencyKey:string) => request<EnforcementAction>('/actions/execute',{method:'POST',headers:{'Idempotency-Key':idempotencyKey},body:JSON.stringify(payload)}),
  nativeObservations: (actionId:string, before?:string) => request<NativeObservationPage>(`/actions/${encodeURIComponent(actionId)}/native-observations?limit=50${before ? `&before=${encodeURIComponent(before)}` : ''}`),
  revokeAction: (actionId:string) => request<EnforcementAction>(`/actions/${encodeURIComponent(actionId)}/revoke`,{method:'POST'}),
  emergencyStop: (enabled:boolean) => request<{global_stop:boolean}>('/actions/emergency-stop',{method:'POST',body:JSON.stringify({enabled})}),
  users: (query:ListQuery={}) => request<{items:LocalUser[];page:Page}>(`/users${search(query)}`),
  createUser: (payload:UserMutation) => request<LocalUser>('/users',{method:'POST',body:JSON.stringify(payload)}),
  updateUser: (userId:string,operation:'profile'|'password'|'disable'|'enable',payload:UserMutation={}) => request<LocalUser>(`/users/${encodeURIComponent(userId)}/${operation}`,{method:'POST',body:JSON.stringify(payload)}),
  campusExceptions: (query:ListQuery={}) => request<{items:CampusException[];page:Page}>(`/campus-exceptions${search(query)}`),
  createCampusException: (payload:CampusException) => request<CampusException>('/campus-exceptions',{method:'POST',body:JSON.stringify(payload)}),
  disableCampusException: (exceptionId:string) => request<CampusException>(`/campus-exceptions/${encodeURIComponent(exceptionId)}/disable`,{method:'POST',body:'{}'}),
}
