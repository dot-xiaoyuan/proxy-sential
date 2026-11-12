// V2 hardware facts are scoped to a trusted identity. Legacy endpoint summaries
// are not a fallback once this projection has supplied a status.
export type HardwareView = {
  hardware_type?: string
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
export const activityStates: Record<string, string> = {active: '近期有有效观测', stale: '最近活动线索已过期'}

export function confirmedDeviceType(item: HardwareView & {classification_status?: string; device_type?: string}): string {
  if (item.hardware_type_status) return item.hardware_type_status === 'identified' ? item.hardware_type ?? '' : ''
  return item.classification_status === 'identified' ? item.device_type ?? '' : ''
}
