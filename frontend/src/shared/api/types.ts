import type { components } from './generated'

export type Permission = components['schemas']['Permission']
export type Role = components['schemas']['Role']
export type Session = components['schemas']['Session']
export type RiskLevel = components['schemas']['RiskLevel']
export type RecommendedAction = components['schemas']['RecommendedAction']
export type RiskSnapshot = components['schemas']['RiskSnapshot']
export type NegativeEvidence = components['schemas']['NegativeEvidence']
export type RiskListResponse = components['schemas']['RiskListResponse']
export type EventListResponse = components['schemas']['EventListResponse']
export type Evidence = components['schemas']['Evidence']
export type NormalizedEventSummary = components['schemas']['NormalizedEventSummary']
export type ActivityCount = components['schemas']['ActivityCount']
export type ActivityAccess = components['schemas']['ActivityAccess']
export type IpActivityProfile = components['schemas']['IpActivityProfile']
export type ActivityIpSummary = components['schemas']['ActivityIpSummary']
export type ActivityOverview = components['schemas']['ActivityOverview']
export type ProxyReviewResponse = components['schemas']['ProxyReviewResponse']
export type ProxyReviewCase = components['schemas']['ProxyReviewCase']
export type ProxyRuleMatch = components['schemas']['ProxyRuleMatch']
export type Collector = components['schemas']['Collector']
export type IngestDiagnostic = components['schemas']['IngestDiagnostic']
export type IngestStatus = components['schemas']['IngestStatus']
export type EventTypeCount = components['schemas']['EventTypeCount']
export type LabelKind = components['schemas']['LabelKind']
export type CreateLabelRequest = components['schemas']['CreateLabelRequest']
export type Label = components['schemas']['Label']
export type ShadowRun = components['schemas']['ShadowRun']
export type ShadowEvaluation = components['schemas']['ShadowEvaluation']
export type AuditLog = components['schemas']['AuditLog']
export type Overview = components['schemas']['Overview']
export type RuleReloadResult = components['schemas']['RuleReloadResult']
export type DpiOverview = components['schemas']['DpiOverview']
export type DpiTrendPoint = components['schemas']['DpiTrendPoint']
export type DpiProtocolFlowItem = components['schemas']['DpiProtocolFlow']
export type FingerprintConflictItem = components['schemas']['DpiFingerprintConflict']
export type DpiFlowSample = components['schemas']['DpiFlowSample']
export type DpiFlowListResponse = components['schemas']['DpiFlowListResponse']
export type DpiFlowDetail = components['schemas']['DpiFlowDetail']
export type DeviceSignal = components['schemas']['DeviceSignal']
export type ObservedDevice = components['schemas']['ObservedDevice']
export type DeviceConflict = components['schemas']['DeviceConflict']
export type IpDeviceInventory = components['schemas']['IpDeviceInventory']
export type DeviceListResponse = components['schemas']['DeviceListResponse']
export type EndpointDeviceInventory = components['schemas']['EndpointDeviceInventory']
export type EndpointEntity = components['schemas']['EndpointEntity']
export type UpdateEndpointRegistrationRequest =
  components['schemas']['UpdateEndpointRegistrationRequest']
export type AccountSession = components['schemas']['AccountSession']
export type IdentityIPMACHistory = components['schemas']['IdentityIPMACHistory']
export type IdentityAccessHistory = components['schemas']['IdentityAccessHistory']
export type AccountIdentityProfile = components['schemas']['AccountIdentityProfile']
export type EndpointIdentityProfile = components['schemas']['EndpointIdentityProfile']

export type RiskQuery = {
  level?: RiskLevel
  q?: string
  sensor_id?: string
  from?: string
  to?: string
  limit?: number
  cursor?: string
}

export type EvidenceQuery = {
  limit?: number
}

export type EventQuery = {
  q?: string
  type?: string
  sensor_id?: string
  from?: string
  to?: string
  window?: '10m' | '1h' | '24h'
  src_ip?: string
  dst_ip?: string
  domain?: string
  user_agent?: string
  fingerprint?: string
  port?: number
  proto?: string
  limit?: number
  cursor?: string
}

export type ActivityOverviewQuery = {
  sensor_id?: string
  window?: '10m' | '1h' | '24h' | '7d'
}

export type ProxyReviewQuery = {
  sensor_id?: string
  window?: '24h' | '7d'
  limit?: number
}

export type DeviceQuery = {
  sensor_id?: string
  window?: '10m' | '1h' | '24h'
  ip?: string
  q?: string
  limit?: number
  cursor?: string
  include_weak?: boolean
}

export type IdentityQuery = {
  sensor_id?: string
  window?: '10m' | '1h' | '24h'
  from?: string
  to?: string
  limit?: number
}
