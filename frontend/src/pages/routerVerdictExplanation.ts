import type { RouterAssessment } from '../shared/api/types'

type VerdictFacts = Pick<RouterAssessment, 'status' | 'role' | 'confidence' | 'independent_sources' | 'infrastructure' | 'ambiguous' | 'conflicts'>

export function routerVerdictExplanation(item: VerdictFacts): string {
  if (item.status === 'confirmed') return '路由角色、独立证据与设备关联均满足确认条件'
  const reasons: string[] = []
  if (item.role === 'ap') reasons.push('识别为接入点，路由器确认不适用')
  else if (item.role !== 'router') reasons.push('尚无明确路由角色')
  if (item.infrastructure) reasons.push('标记为基础设施设备')
  if (item.ambiguous) reasons.push('设备关联不唯一')
  if (item.conflicts.some(value => ['infrastructure_ap', 'infrastructure_switch', 'infrastructure_firewall'].includes(value))) reasons.push('存在设备角色排除证据')
  if (item.confidence < 80) reasons.push('证据匹配分未达确认线')
  if (item.independent_sources < 2) reasons.push('独立证据来源不足')
  if (!reasons.length) reasons.push('强证据或其他确认条件仍不足')
  return reasons.join('；')
}
