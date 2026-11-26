// V2 hardware facts are scoped to a trusted identity. Legacy endpoint summaries
// are not a fallback once this projection has supplied a status.
export type HardwareView = {
  hardware_type?: string
  candidate_device_type?: string
  type_evidence_state?: string
  hardware_type_status?: string
  hardware_model?: string
  hardware_model_status?: string
  hardware_conflicting_types?: string[]
  hardware_conflicting_models?: string[]
  type_evidence_at?: string
  type_rule_version?: string
  type_sources?: {source: string; rule_id: string; rule_version: string; evidence_id: string; observed_at: string}[]
  activity_status?: string
  classification_version?: string
}

export const hardwareStates: Record<string, string> = {
  identified: '已知硬件类型', candidate: '缺少硬件类型证据', conflict: '硬件类型冲突', revoked: '硬件结论已撤销',
}
export const activityStates: Record<string, string> = {active: '近期有观测记录', stale: '最近活动线索已过期'}

export function confirmedDeviceType(item: HardwareView & {classification_status?: string; device_type?: string}): string {
  if (item.hardware_type_status) return item.hardware_type_status === 'identified' ? item.hardware_type ?? '' : ''
  return item.classification_status === 'identified' ? item.device_type ?? '' : ''
}

export const typeEvidenceLabels: Record<string, string> = {
  identified: '硬件规则确认',
  profile_typed: '画像识别',
  ip_product_only: 'IP 产品自报',
  no_type_clue: '缺少类型线索',
  conflict: '类型证据冲突',
  revoked: '硬件结论已撤销',
  expired: '历史证据已过期',
}

export function deviceTypeEvidenceState(item: HardwareView & {product_clues?: {type?: string}[]}): string {
  if (item.type_evidence_state) return item.type_evidence_state
  if (item.hardware_type_status !== 'candidate') return item.hardware_type_status ?? ''
  if (item.candidate_device_type) return 'profile_typed'
  if (item.product_clues?.some(clue => clue.type)) return 'ip_product_only'
  return 'no_type_clue'
}
