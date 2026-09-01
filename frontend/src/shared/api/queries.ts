import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type {
  ActivityOverviewQuery,
  CreateLabelRequest,
  DeviceQuery,
  EventQuery,
  EvidenceQuery,
  IdentityQuery,
  ListQuery,
  ProxyReviewQuery,
  RiskQuery,
  UpdateEndpointRegistrationRequest,
} from './types'

export const queryKeys = {
  session: ['session'] as const,
  overview: (query: ActivityOverviewQuery) => ['overview', query] as const,
  activityOverview: (query: ActivityOverviewQuery) => ['activity-overview', query] as const,
  proxyReviews: (query: ProxyReviewQuery) => ['proxy-reviews', query] as const,
  dpiOverview: (query: ActivityOverviewQuery) => ['dpi-overview', query] as const,
  dpiTrends: (query: ActivityOverviewQuery) => ['dpi-trends', query] as const,
  dpiProtocolFlows: (query: ActivityOverviewQuery) => ['dpi-protocol-flows', query] as const,
  dpiFingerprintConflicts: (query: ActivityOverviewQuery) =>
    ['dpi-fingerprint-conflicts', query] as const,
  dpiFlows: (query: EventQuery) => ['dpi-flows', query] as const,
  dpiIpFlows: (ip: string, query: EventQuery) => ['dpi-ip-flows', ip, query] as const,
  dpiFlow: (flowId: string) => ['dpi-flow', flowId] as const,
  devices: (query: DeviceQuery) => ['devices', query] as const,
  device: (deviceId: string, query: DeviceQuery) => ['device', deviceId, query] as const,
  deviceSignals: (query: DeviceQuery) => ['device-signals', query] as const,
  deviceFingerprintConflicts: (query: DeviceQuery) => ['device-fingerprint-conflicts', query] as const,
  risks: (query: RiskQuery) => ['risks', query] as const,
  ipRisk: (ip: string) => ['ip-risk', ip] as const,
  ipEvidence: (ip: string, query: EvidenceQuery) => ['ip-evidence', ip, query] as const,
  ipActivity: (ip: string) => ['ip-activity', ip] as const,
  ipDevices: (ip: string, query: DeviceQuery) => ['ip-devices', ip, query] as const,
  ipEvents: (ip: string, limit: number) => ['ip-events', ip, limit] as const,
  accountIdentity: (accountId: string, query: IdentityQuery) =>
    ['account-identity', accountId, query] as const,
  endpointIdentity: (endpointId: string, query: IdentityQuery) =>
    ['endpoint-identity', endpointId, query] as const,
  events: (query: EventQuery) => ['events', query] as const,
  ingestStatus: ['ingest-status'] as const,
  ingestRuns: (query: ListQuery) => ['ingest-runs', query] as const,
  ingestDiagnostics: (query: ListQuery) => ['ingest-diagnostics', query] as const,
  ingestEventTypes: ['ingest-event-types'] as const,
  ingestErrors: (query: ListQuery) => ['ingest-errors', query] as const,
  shadowRuns: (query: ListQuery) => ['shadow-runs', query] as const,
  shadowRun: (runId: string) => ['shadow-run', runId] as const,
  shadowEvaluation: ['shadow-evaluation'] as const,
  auditLogs: (query: ListQuery) => ['audit-logs', query] as const,
  auditLog: (auditId: string) => ['audit-log', auditId] as const,
  proxyReview: (caseId: string, window: string) => ['proxy-review', caseId, window] as const,
  event: (eventId: string) => ['event', eventId] as const,
  ingestDiagnostic: (diagnosticId: string) => ['ingest-diagnostic', diagnosticId] as const,
  deviceFingerprintLibrary: ['device-fingerprint-library'] as const,
	cases: (query: object) => ['cases',query] as const,
	caseDetail: (caseId:string) => ['case',caseId] as const,
	organization: ['organization'] as const,
	actionConnectors: ['action-connectors'] as const,
	actions: (query:object) => ['actions',query] as const,
	users: ['users'] as const,
	campusExceptions: ['campus-exceptions'] as const,
}

export function useSession() {
  return useQuery({ queryKey: queryKeys.session, queryFn: api.session })
}

export function useOverview(query: ActivityOverviewQuery = {}) {
  return useQuery({ queryKey: queryKeys.overview(query), queryFn: () => api.overview(query) })
}

export function useLogin() { const client=useQueryClient(); return useMutation({mutationFn:api.login,onSuccess:(session)=>{client.setQueryData(queryKeys.session,session)}}) }
export function useLogout() { const client=useQueryClient(); return useMutation({mutationFn:api.logout,onSuccess:()=>{client.clear()}}) }

export function useActivityOverview(query: ActivityOverviewQuery) {
  return useQuery({
    queryKey: queryKeys.activityOverview(query),
    queryFn: () => api.activityOverview(query),
  })
}

export function useProxyReviews(query: ProxyReviewQuery) {
  return useQuery({ queryKey: queryKeys.proxyReviews(query), queryFn: () => api.proxyReviews(query) })
}

export function useProxyReview(caseId: string, window: '24h' | '7d') {
  return useQuery({ queryKey: queryKeys.proxyReview(caseId, window), queryFn: () => api.proxyReview(caseId, window), enabled: !!caseId })
}

export function useDpiOverview(query: ActivityOverviewQuery) {
  return useQuery({ queryKey: queryKeys.dpiOverview(query), queryFn: () => api.dpiOverview(query) })
}

export function useDpiTrends(query: ActivityOverviewQuery) {
  return useQuery({ queryKey: queryKeys.dpiTrends(query), queryFn: () => api.dpiTrends(query) })
}

export function useDpiProtocolFlows(query: ActivityOverviewQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.dpiProtocolFlows(query),
    queryFn: () => api.dpiProtocolFlows(query),
    enabled,
  })
}

export function useDpiFingerprintConflicts(query: ActivityOverviewQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.dpiFingerprintConflicts(query),
    queryFn: () => api.dpiFingerprintConflicts(query),
    enabled,
  })
}

export function useDpiFlows(query: EventQuery) {
  return useQuery({ queryKey: queryKeys.dpiFlows(query), queryFn: () => api.dpiFlows(query) })
}

export function useDpiIpFlows(ip: string, query: EventQuery) {
  return useQuery({
    queryKey: queryKeys.dpiIpFlows(ip, query),
    queryFn: () => api.dpiIpFlows(ip, query),
    enabled: !!ip,
  })
}

export function useDpiFlow(flowId: string) {
  return useQuery({
    queryKey: queryKeys.dpiFlow(flowId),
    queryFn: () => api.dpiFlow(flowId),
    enabled: !!flowId,
  })
}

export function useDevices(query: DeviceQuery) {
  return useQuery({ queryKey: queryKeys.devices(query), queryFn: () => api.devices(query) })
}

export function useDevice(deviceId: string, query: DeviceQuery) {
  return useQuery({
    queryKey: queryKeys.device(deviceId, query),
    queryFn: () => api.device(deviceId, query),
    enabled: !!deviceId,
  })
}

export function useDeviceSignals(query: DeviceQuery) {
  return useQuery({
    queryKey: queryKeys.deviceSignals(query),
    queryFn: () => api.deviceSignals(query),
  })
}

export function useDeviceFingerprintConflicts(query: DeviceQuery) {
  return useQuery({
    queryKey: queryKeys.deviceFingerprintConflicts(query),
    queryFn: () => api.deviceFingerprintConflicts(query),
  })
}

export function useRisks(query: RiskQuery) {
  return useQuery({ queryKey: queryKeys.risks(query), queryFn: () => api.risks(query) })
}

export function useIpRisk(ip: string) {
  return useQuery({ queryKey: queryKeys.ipRisk(ip), queryFn: () => api.ipRisk(ip), enabled: !!ip })
}

export function useIpEvidence(ip: string, query: EvidenceQuery = { limit: 20 }) {
  return useQuery({
    queryKey: queryKeys.ipEvidence(ip, query),
    queryFn: () => api.ipEvidence(ip, query),
    enabled: !!ip,
  })
}

export function useIpActivity(ip: string) {
  return useQuery({
    queryKey: queryKeys.ipActivity(ip),
    queryFn: () => api.ipActivity(ip),
    enabled: !!ip,
  })
}

export function useAccountIdentity(accountId: string, query: IdentityQuery = {}) {
  return useQuery({
    queryKey: queryKeys.accountIdentity(accountId, query),
    queryFn: () => api.accountIdentity(accountId, query),
    enabled: !!accountId,
  })
}

export function useEndpointIdentity(endpointId: string, query: IdentityQuery = {}) {
  return useQuery({
    queryKey: queryKeys.endpointIdentity(endpointId, query),
    queryFn: () => api.endpointIdentity(endpointId, query),
    enabled: !!endpointId,
  })
}

export function useUpdateEndpointRegistration() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({
      endpointId,
      payload,
    }: {
      endpointId: string
      payload: UpdateEndpointRegistrationRequest
    }) => api.updateEndpointRegistration(endpointId, payload),
    onSuccess: (_, variables) => {
      void client.invalidateQueries({ queryKey: ['endpoint-identity', variables.endpointId] })
      void client.invalidateQueries({ queryKey: ['devices'] })
      void client.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })
}

export function useIpDevices(ip: string, query: DeviceQuery = { window: '1h' }) {
  return useQuery({
    queryKey: queryKeys.ipDevices(ip, query),
    queryFn: () => api.ipDevices(ip, query),
    enabled: !!ip,
  })
}

export function useIpEvents(ip: string, limit = 20) {
  return useQuery({
    queryKey: queryKeys.ipEvents(ip, limit),
    queryFn: () => api.ipEvents(ip, limit),
    enabled: !!ip,
  })
}

export function useEvents(query: EventQuery) {
  return useQuery({ queryKey: queryKeys.events(query), queryFn: () => api.events(query) })
}

export function useEvent(eventId: string) {
  return useQuery({ queryKey: queryKeys.event(eventId), queryFn: () => api.event(eventId), enabled: !!eventId })
}

export function useIngestStatus() {
  return useQuery({ queryKey: queryKeys.ingestStatus, queryFn: api.ingestStatus })
}

export function useIngestRuns(query: ListQuery = { limit: 20 }) {
  return useQuery({ queryKey: queryKeys.ingestRuns(query), queryFn: () => api.ingestRuns(query) })
}

export function useIngestDiagnostics(query: ListQuery = { limit: 20 }) {
  return useQuery({ queryKey: queryKeys.ingestDiagnostics(query), queryFn: () => api.ingestDiagnostics(query) })
}

export function useIngestEventTypes() {
  return useQuery({ queryKey: queryKeys.ingestEventTypes, queryFn: api.ingestEventTypes })
}

export function useIngestErrors(query: ListQuery = { limit: 20 }) {
  return useQuery({ queryKey: queryKeys.ingestErrors(query), queryFn: () => api.ingestErrors(query) })
}

export function useCreateLabel() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (payload: CreateLabelRequest) => api.createLabel(payload),
    onSuccess: (_, variables) => {
      void client.invalidateQueries({ queryKey: ['audit-logs'] })
      void client.invalidateQueries({ queryKey: ['overview'] })
      void client.invalidateQueries({ queryKey: ['risks'] })
      void client.invalidateQueries({ queryKey: ['proxy-reviews'] })
      void client.invalidateQueries({ queryKey: queryKeys.shadowEvaluation })
      if (variables.target_type === 'ip') {
        void client.invalidateQueries({ queryKey: queryKeys.ipRisk(variables.target_id) })
      }
    },
  })
}

export function useShadowRuns(query: ListQuery = { limit: 20 }) {
  return useQuery({ queryKey: queryKeys.shadowRuns(query), queryFn: () => api.shadowRuns(query) })
}

export function useShadowRun(runId: string) {
  return useQuery({ queryKey: queryKeys.shadowRun(runId), queryFn: () => api.shadowRun(runId), enabled: !!runId })
}

export function useShadowEvaluation() {
  return useQuery({ queryKey: queryKeys.shadowEvaluation, queryFn: api.shadowEvaluation })
}

export function useAuditLogs(query: ListQuery = { limit: 20 }) {
  return useQuery({ queryKey: queryKeys.auditLogs(query), queryFn: () => api.auditLogs(query) })
}

export function useAuditLog(auditId: string) {
  return useQuery({ queryKey: queryKeys.auditLog(auditId), queryFn: () => api.auditLog(auditId), enabled: !!auditId })
}

export function useIngestDiagnostic(diagnosticId: string) {
  return useQuery({ queryKey: queryKeys.ingestDiagnostic(diagnosticId), queryFn: () => api.ingestDiagnostic(diagnosticId), enabled: !!diagnosticId })
}

export function useDeviceFingerprintLibrary() {
  return useQuery({ queryKey: queryKeys.deviceFingerprintLibrary, queryFn: api.deviceFingerprintLibrary })
}

export function useUpdateDeviceFingerprintLibrary() {
  const client = useQueryClient()
  return useMutation({ mutationFn: api.updateDeviceFingerprintLibrary, onSuccess: () => {
    void client.invalidateQueries({ queryKey: queryKeys.deviceFingerprintLibrary })
    void client.invalidateQueries({ queryKey: ['devices'] })
  } })
}

export function useValidateDeviceFingerprintBundle() { return useMutation({ mutationFn: api.validateDeviceFingerprintBundle }) }
export function useImportDeviceFingerprintBundle() { const client=useQueryClient();return useMutation({mutationFn:api.importDeviceFingerprintBundle,onSuccess:()=>{void client.invalidateQueries({queryKey:queryKeys.deviceFingerprintLibrary});void client.invalidateQueries({queryKey:['devices']})}}) }

export function useReloadRules() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: api.reloadRules,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })
}

export function useCases(query: ListQuery & {status?:string;assignee_id?:string;campus_id?:string;window?:string} = {}) { return useQuery({queryKey:queryKeys.cases(query),queryFn:()=>api.cases(query)}) }
export function useCase(caseId:string) { return useQuery({queryKey:queryKeys.caseDetail(caseId),queryFn:()=>api.caseDetail(caseId),enabled:!!caseId}) }
export function useCaseMutation() { const client=useQueryClient(); return useMutation({mutationFn:async (request:{caseId:string;operation:'assign'|'status'|'disposition'|'comment';value:string;reason?:string})=>{switch(request.operation){case'assign':return api.assignCase(request.caseId,request.value);case'status':return api.updateCaseStatus(request.caseId,request.value);case'disposition':return api.resolveCase(request.caseId,request.value,request.reason??'人工复核');default:return api.commentCase(request.caseId,request.value)}},onSuccess:(item)=>{client.setQueryData(queryKeys.caseDetail(item.case_id),item);void client.invalidateQueries({queryKey:['cases']});void client.invalidateQueries({queryKey:['overview']})}}) }
export function useOrganization() { return useQuery({queryKey:queryKeys.organization,queryFn:api.organization}) }
export function useActionConnectors() { return useQuery({queryKey:queryKeys.actionConnectors,queryFn:api.actionConnectors}) }
export function useActions(query:ListQuery={}) { return useQuery({queryKey:queryKeys.actions(query),queryFn:()=>api.actions(query)}) }
export function useActionMutation() { const client=useQueryClient(); return useMutation({mutationFn:(request:{payload:{case_id?:string;connector_id:string;action_type:string;ip:string;campus_id?:string;duration_seconds?:number};idempotencyKey:string})=>api.executeAction(request.payload,request.idempotencyKey),onSuccess:()=>void client.invalidateQueries({queryKey:['actions']})}) }
export function useUsers() { return useQuery({queryKey:queryKeys.users,queryFn:api.users}) }
export function useUserMutation() { const client=useQueryClient();return useMutation({mutationFn:(request:{userId?:string;operation?:'profile'|'password'|'disable'|'enable';payload:import('./types').UserMutation})=>request.userId&&request.operation?api.updateUser(request.userId,request.operation,request.payload):api.createUser(request.payload),onSuccess:()=>void client.invalidateQueries({queryKey:queryKeys.users})}) }
export function useCampusExceptions() { return useQuery({queryKey:queryKeys.campusExceptions,queryFn:api.campusExceptions}) }
export function useCampusExceptionMutation() { const client=useQueryClient();return useMutation({mutationFn:(request:{exceptionId?:string;payload?:import('./types').CampusException})=>request.exceptionId?api.disableCampusException(request.exceptionId):api.createCampusException(request.payload!),onSuccess:()=>{void client.invalidateQueries({queryKey:queryKeys.campusExceptions});void client.invalidateQueries({queryKey:['risks']});void client.invalidateQueries({queryKey:['cases']})}}) }
