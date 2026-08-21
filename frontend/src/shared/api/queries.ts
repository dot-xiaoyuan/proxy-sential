import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type {
  ActivityOverviewQuery,
  CreateLabelRequest,
  DeviceQuery,
  EventQuery,
  EvidenceQuery,
  IdentityQuery,
  ProxyReviewQuery,
  RiskQuery,
  UpdateEndpointRegistrationRequest,
} from './types'

export const queryKeys = {
  session: ['session'] as const,
  overview: ['overview'] as const,
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
  ingestRuns: ['ingest-runs'] as const,
  ingestDiagnostics: ['ingest-diagnostics'] as const,
  ingestEventTypes: ['ingest-event-types'] as const,
  ingestErrors: ['ingest-errors'] as const,
  shadowRuns: ['shadow-runs'] as const,
  shadowEvaluation: ['shadow-evaluation'] as const,
  auditLogs: ['audit-logs'] as const,
}

export function useSession() {
  return useQuery({ queryKey: queryKeys.session, queryFn: api.session })
}

export function useOverview() {
  return useQuery({ queryKey: queryKeys.overview, queryFn: api.overview })
}

export function useActivityOverview(query: ActivityOverviewQuery) {
  return useQuery({
    queryKey: queryKeys.activityOverview(query),
    queryFn: () => api.activityOverview(query),
  })
}

export function useProxyReviews(query: ProxyReviewQuery) {
  return useQuery({ queryKey: queryKeys.proxyReviews(query), queryFn: () => api.proxyReviews(query) })
}

export function useDpiOverview(query: ActivityOverviewQuery) {
  return useQuery({ queryKey: queryKeys.dpiOverview(query), queryFn: () => api.dpiOverview(query) })
}

export function useDpiTrends(query: ActivityOverviewQuery) {
  return useQuery({ queryKey: queryKeys.dpiTrends(query), queryFn: () => api.dpiTrends(query) })
}

export function useDpiProtocolFlows(query: ActivityOverviewQuery) {
  return useQuery({
    queryKey: queryKeys.dpiProtocolFlows(query),
    queryFn: () => api.dpiProtocolFlows(query),
  })
}

export function useDpiFingerprintConflicts(query: ActivityOverviewQuery) {
  return useQuery({
    queryKey: queryKeys.dpiFingerprintConflicts(query),
    queryFn: () => api.dpiFingerprintConflicts(query),
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

export function useIngestStatus() {
  return useQuery({ queryKey: queryKeys.ingestStatus, queryFn: api.ingestStatus })
}

export function useIngestRuns() {
  return useQuery({ queryKey: queryKeys.ingestRuns, queryFn: api.ingestRuns })
}

export function useIngestDiagnostics(limit = 50) {
  return useQuery({ queryKey: queryKeys.ingestDiagnostics, queryFn: () => api.ingestDiagnostics(limit) })
}

export function useIngestEventTypes() {
  return useQuery({ queryKey: queryKeys.ingestEventTypes, queryFn: api.ingestEventTypes })
}

export function useIngestErrors(limit = 50) {
  return useQuery({ queryKey: queryKeys.ingestErrors, queryFn: () => api.ingestErrors(limit) })
}

export function useCreateLabel() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (payload: CreateLabelRequest) => api.createLabel(payload),
    onSuccess: (_, variables) => {
      void client.invalidateQueries({ queryKey: queryKeys.auditLogs })
      void client.invalidateQueries({ queryKey: queryKeys.overview })
      void client.invalidateQueries({ queryKey: ['risks'] })
      void client.invalidateQueries({ queryKey: ['proxy-reviews'] })
      void client.invalidateQueries({ queryKey: queryKeys.shadowEvaluation })
      if (variables.target_type === 'ip') {
        void client.invalidateQueries({ queryKey: queryKeys.ipRisk(variables.target_id) })
      }
    },
  })
}

export function useShadowRuns() {
  return useQuery({ queryKey: queryKeys.shadowRuns, queryFn: api.shadowRuns })
}

export function useShadowEvaluation() {
  return useQuery({ queryKey: queryKeys.shadowEvaluation, queryFn: api.shadowEvaluation })
}

export function useAuditLogs() {
  return useQuery({ queryKey: queryKeys.auditLogs, queryFn: () => api.auditLogs() })
}

export function useReloadRules() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: api.reloadRules,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.auditLogs })
    },
  })
}
