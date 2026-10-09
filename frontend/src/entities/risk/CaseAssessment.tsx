import { Space, Tag, Typography } from 'antd'
import type { RiskCase, RiskLevel } from '../../shared/api/types'
import { RiskLevelTag } from './RiskLevelTag'

export function CaseAssessment({ item, showConfidence = false }: { item: RiskCase; showConfidence?: boolean }) {
  const historical = item.assessment_current === false
  const specializedLabel = item.risk_kind === 'shared_access'
    ? '已确认共享'
    : item.risk_kind === 'router_observation'
      ? item.assessment_level === 'confirmed' ? '已确认路由器' : item.assessment_level === 'likely' ? '路由器观察' : '路由器线索'
      : ''
  return <Space className="case-assessment" size={4} wrap>
    {historical ? <Tag>历史评估</Tag> : specializedLabel ? <Tag color={item.risk_kind === 'shared_access' ? 'red' : 'blue'}>{specializedLabel}</Tag> : <RiskLevelTag level={item.assessment_level as RiskLevel} />}
    <Typography.Text type={historical ? 'secondary' : undefined}>{item.risk_score} 分{showConfidence ? ` / ${Math.round(item.risk_confidence * 100)}%` : ''}</Typography.Text>
  </Space>
}
