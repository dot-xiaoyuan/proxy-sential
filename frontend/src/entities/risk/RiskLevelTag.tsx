import { Tag } from 'antd'

import type { RiskLevel } from '../../shared/api/types'
import { levelMeta } from './riskMeta'

export function RiskLevelTag({ level }: { level: RiskLevel }) {
  const meta = levelMeta[level]
  return <Tag color={meta.color}>{meta.label}</Tag>
}
