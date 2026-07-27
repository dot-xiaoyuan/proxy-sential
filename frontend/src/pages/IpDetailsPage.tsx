import { useParams } from 'react-router-dom'
import { Alert, Descriptions, Skeleton, Space, Statistic, Table, Tag, Typography } from 'antd'

import { EvidenceList } from '../entities/evidence/EvidenceList'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { LabelPanel } from '../features/labels/LabelPanel'
import { useIpActivity, useIpEvidence, useIpEvents, useIpRisk, useSession } from '../shared/api/queries'
import type { ActivityAccess, ActivityCount } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

export function IpDetailsPage() {
  const rawIp = useParams().ip ?? ''
  const ip = decodeURIComponent(rawIp)
  const session = useSession()
  const risk = useIpRisk(ip)
  const evidence = useIpEvidence(ip)
  const activity = useIpActivity(ip)
  const events = useIpEvents(ip)
  const canLabel = can(session.data, 'labels:create')

  if (risk.isLoading || evidence.isLoading || activity.isLoading || events.isLoading) {
    return <Skeleton active />
  }

  if (risk.isError || evidence.isError || activity.isError || events.isError || !risk.data) {
    return <Alert message="IP 详情加载失败" showIcon type="error" />
  }

  const evidenceItems = evidence.data?.evidence ?? []
  const profile = activity.data

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title mono" level={3}>
            {ip}
          </Typography.Title>
          <Typography.Text type="secondary">风险解释、访问画像、客户端特征、证据时间线和人工标注。</Typography.Text>
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
        <Typography.Title level={4}>访问画像</Typography.Title>
        {!profile || profile.event_count === 0 ? (
          <Typography.Text type="secondary">暂无该 IP 的标准事件画像</Typography.Text>
        ) : (
          <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
            <div className="metric-grid">
              <div className="surface metric-card">
                <Statistic title="样本事件" value={profile.event_count} />
              </div>
              <div className="surface metric-card">
                <Statistic title="访问域名" value={profile.top_domains.length} />
              </div>
              <div className="surface metric-card">
                <Statistic title="目的 IP" value={profile.top_dst_ips.length} />
              </div>
              <div className="surface metric-card">
                <Statistic title="目的端口" value={profile.top_dst_ports.length} />
              </div>
            </div>

            <section className="details-grid">
              <div>
                <Typography.Title level={5}>访问了什么</Typography.Title>
                {renderCountList(profile.top_domains, '暂无 DNS/HTTP Host/SNI')}
              </div>
              <div>
                <Typography.Title level={5}>目的端口 / 协议</Typography.Title>
                {renderCountList([...profile.top_dst_ports, ...profile.protocol_counts], '暂无端口或协议分布')}
              </div>
            </section>

            <section className="details-grid">
              <div>
                <Typography.Title level={5}>客户端特征</Typography.Title>
                <Typography.Text type="secondary">User-Agent</Typography.Text>
                {renderCountList(profile.top_user_agents, '暂无 User-Agent')}
                <Typography.Text type="secondary">TLS 指纹</Typography.Text>
                {renderCountList(profile.top_tls_fingerprints, '暂无 JA3/JA4')}
              </div>
              <div>
                <Typography.Title level={5}>分协议访问对象</Typography.Title>
                <Typography.Text type="secondary">HTTP Host</Typography.Text>
                {renderCountList(profile.top_http_hosts, '暂无 HTTP Host')}
                <Typography.Text type="secondary">TLS SNI</Typography.Text>
                {renderCountList(profile.top_tls_sni, '暂无 TLS SNI')}
              </div>
            </section>

            <div>
              <Typography.Title level={5}>最近访问明细</Typography.Title>
              <Table<ActivityAccess>
                columns={[
                  {
                    title: '时间',
                    dataIndex: 'timestamp',
                    width: 180,
                    render: (value: string) => new Date(value).toLocaleString(),
                  },
                  {
                    title: '类型',
                    dataIndex: 'type',
                    width: 90,
                    render: (value: string) => <Tag>{value}</Tag>,
                  },
                  {
                    title: '访问对象',
                    dataIndex: 'target',
                    render: (value: string, row) => (
                      <Space orientation="vertical" size={0}>
                        <Typography.Text className="mono wrap-text">{value}</Typography.Text>
                        <Typography.Text type="secondary">{row.target_kind}</Typography.Text>
                      </Space>
                    ),
                  },
                  {
                    title: '目的',
                    width: 180,
                    render: (_, row) => (
                      <Typography.Text className="mono">
                        {row.dst_ip ?? '-'}
                        {row.dst_port ? `:${row.dst_port}` : ''}
                      </Typography.Text>
                    ),
                  },
                  {
                    title: 'UA / 方法',
                    render: (_, row) => (
                      <Typography.Text className="wrap-text">
                        {[row.method, row.user_agent].filter(Boolean).join(' / ') || '-'}
                      </Typography.Text>
                    ),
                  },
                ]}
                dataSource={profile.recent_accesses}
                pagination={false}
                rowKey="event_id"
                size="small"
              />
            </div>
          </Space>
        )}
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

function renderCountList(items: ActivityCount[], empty: string) {
  if (items.length === 0) {
    return <Typography.Paragraph type="secondary">{empty}</Typography.Paragraph>
  }
  return (
    <div className="sample-list">
      {items.map((item) => (
        <span className="sample-token" key={`${item.value}-${item.count}`}>
          <Typography.Text className="mono wrap-text">{item.value}</Typography.Text>
          <Typography.Text type="secondary"> ×{item.count}</Typography.Text>
        </span>
      ))}
    </div>
  )
}
