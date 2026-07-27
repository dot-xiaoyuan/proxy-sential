import type { RiskLevel } from '../../shared/api/types'

export const levelMeta: Record<RiskLevel, { color: string; label: string }> = {
  normal: { color: 'green', label: '正常' },
  suspicious: { color: 'gold', label: '可疑' },
  high: { color: 'volcano', label: '高风险' },
  confirmed: { color: 'red', label: '基本确认' },
}

export function riskLevelLabel(level: RiskLevel) {
  return levelMeta[level].label
}
