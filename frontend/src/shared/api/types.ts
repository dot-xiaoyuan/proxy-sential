import type { components } from './generated'

export type Permission = components['schemas']['Permission']
export type Role = components['schemas']['Role']
export type Session = components['schemas']['Session']
export type RiskLevel = components['schemas']['RiskLevel']
export type RecommendedAction = components['schemas']['RecommendedAction']
export type RiskSnapshot = components['schemas']['RiskSnapshot']
export type RiskListResponse = components['schemas']['RiskListResponse']
export type Evidence = components['schemas']['Evidence']
export type NormalizedEventSummary = components['schemas']['NormalizedEventSummary']
export type ActivityCount = components['schemas']['ActivityCount']
export type ActivityAccess = components['schemas']['ActivityAccess']
export type IpActivityProfile = components['schemas']['IpActivityProfile']
export type ActivityIpSummary = components['schemas']['ActivityIpSummary']
export type ActivityOverview = components['schemas']['ActivityOverview']
export type Collector = components['schemas']['Collector']
export type IngestDiagnostic = components['schemas']['IngestDiagnostic']
export type IngestStatus = components['schemas']['IngestStatus']
export type EventTypeCount = components['schemas']['EventTypeCount']
export type LabelKind = components['schemas']['LabelKind']
export type CreateLabelRequest = components['schemas']['CreateLabelRequest']
export type Label = components['schemas']['Label']
export type ShadowRun = components['schemas']['ShadowRun']
export type AuditLog = components['schemas']['AuditLog']
export type Overview = components['schemas']['Overview']
export type RuleReloadResult = components['schemas']['RuleReloadResult']

export type RiskQuery = {
  level?: RiskLevel
  q?: string
  sensor_id?: string
  from?: string
  to?: string
  limit?: number
  cursor?: string
}

export type EventQuery = {
  q?: string
  type?: string
  sensor_id?: string
  limit?: number
}

export type ActivityOverviewQuery = {
  sensor_id?: string
  window?: '10m' | '1h' | '24h'
  limit?: number
}
