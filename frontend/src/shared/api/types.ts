import type { components } from './generated'

export type Permission = components['schemas']['Permission'] | 'cases:read' | 'cases:write' | 'identity:read' | 'organization:read' | 'organization:write' | 'actions:read' | 'actions:execute' | 'actions:revoke' | 'integrations:write' | 'users:manage'
export type Role = components['schemas']['Role']
export type Session = Omit<components['schemas']['Session'],'permissions'> & { permissions: Permission[]; csrf_token?: string }

export type LoginRequest = { username: string; password: string }
export type RiskCase = {
  case_id: string
  subject_type: string
  subject_id: string
  ip?: string
  account_id?: string
  endpoint_id?: string
  campus_id?: string
  department?: string
  person_type?: string
  building_id?: string
  network_zone_id?: string
  ssid?: string
  vlan?: string
  ap?: string
  nas_ip?: string
  auth_session_id?: string
  identity_conflict?: boolean
  identity_blocker?: string
  status: 'new' | 'assigned' | 'investigating' | 'waiting_data' | 'resolved' | 'closed' | 'reopened'
  disposition?: 'confirmed_proxy' | 'false_positive' | 'benign' | 'needs_more_data'
  priority: 'high' | 'medium' | 'low'
  assignee_id?: string
  risk_score: number
  risk_confidence: number
  assessment_level: string
  due_at: string
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
  comments?: Array<{ comment_id: string; author_id: string; body: string; created_at: string }>
  timeline?: Array<{ event_id: string; actor_id: string; type: string; created_at: string }>
  evidence_snapshot?: ProxyReviewCase
}
export type RiskCaseListResponse = { items: RiskCase[]; page: Page }
export type Organization = {
  campuses: Array<{ campus_id: string; code: string; name: string; enabled: boolean }>
  buildings: Array<{ building_id: string; campus_id: string; code: string; name: string; enabled: boolean }>
  network_zones: Array<{ network_zone_id: string; campus_id: string; building_id?: string; name: string; cidrs: string[]; ssids: string[]; vlans: string[]; enabled: boolean }>
  access_points: Array<{ access_point_id: string; campus_id: string; building_id?: string; network_zone_id?: string; kind: string; name: string; management_ip?: string; enabled: boolean }>
}
export type ActionConnector = { connector_id: string; name: string; endpoint_url: string; action_mapping: Record<string,string>; mode: 'shadow'|'active'; enabled: boolean; shadow_ready: boolean; circuit_open_until?:string; consecutive_failures?:number; shadow_started_at?:string; shadow_validation_since?:string; shadow_candidate_count?:number; shadow_reviewed_count?:number; shadow_accuracy?:number; updated_at: string }
export type EnforcementAction = { action_id:string; idempotency_key:string; case_id?:string; connector_id:string; action_type:string; subject_id:string; ip?:string; account_id?:string; endpoint_id?:string; campus_id?:string; session_id?:string; ruleset_version?:string; remote_action_id?:string; parent_action_id?:string; retry_count?:number; next_attempt_at?:string; cooldown_until?:string; expires_at?:string; status:string; mode:string; blockers?:string[]; last_error?:string; created_at:string; updated_at:string }
export type LocalUser = components['schemas']['LocalUser']
export type UserMutation = components['schemas']['UserMutation']
export type CampusException = components['schemas']['CampusException']
export type RiskLevel = components['schemas']['RiskLevel']
export type RecommendedAction = components['schemas']['RecommendedAction']
export type RiskSnapshot = components['schemas']['RiskSnapshot'] & { assessment_level?: RiskLevel; review_disposition?: string; automation_eligible?: boolean; automation_blockers?: string[] }
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
export type ProxyReviewResponse = components['schemas']['ProxyReviewResponse'] & { page: Page }
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
export type Overview = components['schemas']['Overview'] & { window?:string; sensor_id?:string; as_of?:string; first_seen?:string; last_seen?:string; data_source?:string; active_ip_count?:number; open_case_count?:number; overdue_case_count?:number }
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
  campus_id?: string
  window?: '10m' | '1h' | '24h'
  department?: string
  person_type?: string
  ssid?: string
  vlan?: string
  ap?: string
  nas_ip?: string
  as_of?: string
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
  campus_id?: string
  department?: string
  person_type?: string
  ssid?: string
  vlan?: string
  ap?: string
  nas_ip?: string
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
  campus_id?: string
  as_of?: string
  window?: '10m' | '1h' | '24h' | '7d'
}

export type ProxyReviewQuery = {
  sensor_id?: string
  window?: '24h' | '7d'
  limit?: number
  cursor?: string
  q?: string
  view?: 'summary' | 'full'
}

export type Page = { limit: number; next_cursor: string | null; total: number }
export type ListQuery = { limit?: number; cursor?: string; q?: string }
export type ShadowRunListResponse = { runs: ShadowRun[]; page: Page }
export type AuditLogListResponse = { logs: AuditLog[]; page: Page }
export type IngestDiagnosticListResponse = { diagnostics: IngestDiagnostic[]; page: Page }
export type DeviceFingerprintLibraryStatus = {
  version: string
  status: 'ready' | 'checking' | 'degraded'
  source: string
  checksum: string
  updated_at?: string
  last_checked_at?: string
  last_error?: string
	 offline_mode: boolean
	 rule_count: number
	 oui_count: number
	 dhcp_rule_count: number
	 sources?: DeviceFingerprintBundleSource[]
	 licenses?: string[]
	 backfill_status?: string
	 backfill_processed?: number
}
export type DeviceFingerprintBundleSource = { name: string; version: string; url: string; license: string }
export type DeviceFingerprintBundleManifest = { schema_version: string; version: string; created_at: string; sources: DeviceFingerprintBundleSource[]; files: Record<string,{size:number;sha256:string}> }

export type DeviceQuery = {
  sensor_id?: string
  campus_id?: string
  department?: string
  person_type?: string
  ssid?: string
  vlan?: string
  ap?: string
  nas_ip?: string
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
