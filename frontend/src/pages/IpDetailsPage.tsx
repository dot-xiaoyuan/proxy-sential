import { useParams } from 'react-router-dom'
import { Alert, Descriptions, Skeleton, Space, Typography } from 'antd'

import { EvidenceList } from '../entities/evidence/EvidenceList'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { LabelPanel } from '../features/labels/LabelPanel'
import { useIpEvidence, useIpEvents, useIpRisk, useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'

export function IpDetailsPage() {
  const rawIp = useParams().ip ?? ''
  const ip = decodeURIComponent(rawIp)
  const session = useSession()
  const risk = useIpRisk(ip)
  const evidence = useIpEvidence(ip)
  const events = useIpEvents(ip)
  const canLabel = can(session.data, 'labels:create')

  if (risk.isLoading || evidence.isLoading || events.isLoading) {
    return <Skeleton active />
  }

  if (risk.isError || evidence.isError || events.isError || !risk.data) {
    return <Alert message="IP 详情加载失败" showIcon type="error" />
  }

  const evidenceItems = evidence.data?.evidence ?? []

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title mono" level={3}>
            {ip}
          </Typography.Title>
          <Typography.Text type="secondary">风险解释、证据时间线、标准事件样本和人工标注。</Typography.Text>
        </div>
        <Space>
          <RiskLevelTag level={risk.data.level} />
          <RiskScore score={risk.data.score} />
        </Space>
      </div>

      <section className="details-grid">
        <div className="surface">
          <Typography.Title level={4}>风险摘要</Typography.Title>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="置信度">{Math.round(risk.data.confidence * 100)}%</Descriptions.Item>
            <Descriptions.Item label="窗口">{risk.data.window}</Descriptions.Item>
            <Descriptions.Item label="建议动作">{risk.data.recommended_action}</Descriptions.Item>
            <Descriptions.Item label="更新时间">
              {new Date(risk.data.updated_at).toLocaleString()}
            </Descriptions.Item>
            <Descriptions.Item label="解释">
              <Typography.Text className="wrap-text">{risk.data.summary}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        </div>
        <div className="surface">
          <Typography.Title level={4}>人工标注</Typography.Title>
          {!canLabel && <Alert showIcon title="当前会话没有 labels:create 权限" type="warning" />}
          <LabelPanel
            disabled={!canLabel}
            evidenceIds={risk.data.evidence_ids}
            targetId={risk.data.ip}
          />
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>证据时间线</Typography.Title>
        <EvidenceList evidence={evidenceItems} />
      </section>

      <section className="surface">
        <Typography.Title level={4}>标准事件样本</Typography.Title>
        {(events.data?.events ?? []).length === 0 ? (
          <Typography.Text type="secondary">暂无标准事件样本</Typography.Text>
        ) : (
          (events.data?.events ?? []).map((event) => (
            <div className="event-row" key={event.event_id}>
              <Space wrap>
                <Typography.Text className="mono">{event.type}</Typography.Text>
                <Typography.Text>{new Date(event.timestamp).toLocaleString()}</Typography.Text>
                <Typography.Text>confidence {Math.round(event.confidence * 100)}%</Typography.Text>
              </Space>
              <Typography.Text className="mono wrap-text">
                {JSON.stringify({ subject: event.subject, flow: event.flow, payload: event.payload })}
              </Typography.Text>
            </div>
          ))
        )}
      </section>
    </main>
  )
}
