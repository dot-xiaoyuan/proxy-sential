import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { CreateLabelRequest, EventQuery, RiskQuery } from './types'

export const queryKeys = {
  session: ['session'] as const,
  overview: ['overview'] as const,
  risks: (query: RiskQuery) => ['risks', query] as const,
  ipRisk: (ip: string) => ['ip-risk', ip] as const,
  ipEvidence: (ip: string) => ['ip-evidence', ip] as const,
  ipEvents: (ip: string) => ['ip-events', ip] as const,
  events: (query: EventQuery) => ['events', query] as const,
  ingestStatus: ['ingest-status'] as const,
  ingestRuns: ['ingest-runs'] as const,
  ingestDiagnostics: ['ingest-diagnostics'] as const,
  ingestEventTypes: ['ingest-event-types'] as const,
  ingestErrors: ['ingest-errors'] as const,
  shadowRuns: ['shadow-runs'] as const,
  auditLogs: ['audit-logs'] as const,
}

export function useSession() {
  return useQuery({ queryKey: queryKeys.session, queryFn: api.session })
}

export function useOverview() {
  return useQuery({ queryKey: queryKeys.overview, queryFn: api.overview })
}

export function useRisks(query: RiskQuery) {
  return useQuery({ queryKey: queryKeys.risks(query), queryFn: () => api.risks(query) })
}

export function useIpRisk(ip: string) {
  return useQuery({ queryKey: queryKeys.ipRisk(ip), queryFn: () => api.ipRisk(ip), enabled: !!ip })
}

export function useIpEvidence(ip: string) {
  return useQuery({
    queryKey: queryKeys.ipEvidence(ip),
    queryFn: () => api.ipEvidence(ip),
    enabled: !!ip,
  })
}

export function useIpEvents(ip: string) {
  return useQuery({
    queryKey: queryKeys.ipEvents(ip),
    queryFn: () => api.ipEvents(ip),
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
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.auditLogs })
      void client.invalidateQueries({ queryKey: queryKeys.overview })
    },
  })
}

export function useShadowRuns() {
  return useQuery({ queryKey: queryKeys.shadowRuns, queryFn: api.shadowRuns })
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
