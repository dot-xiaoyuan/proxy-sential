import { useParams } from 'react-router-dom'
import { Alert, Descriptions, Progress, Skeleton, Space, Statistic, Table, Tag, Typography } from 'antd'

import { EvidenceList } from '../entities/evidence/EvidenceList'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { LabelPanel } from '../features/labels/LabelPanel'
import { useIpActivity, useIpDevices, useIpEvidence, useIpEvents, useIpRisk, useSession } from '../shared/api/queries'
import type { ActivityAccess, ActivityCount, DeviceConflict, DeviceSignal, IpDeviceInventory, ObservedDevice } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

export function IpDetailsPage() {
  const rawIp = useParams().ip ?? ''
  const ip = decodeURIComponent(rawIp)
  const session = useSession()
  const risk = useIpRisk(ip)
  const evidence = useIpEvidence(ip)
  const activity = useIpActivity(ip)
  const devices = useIpDevices(ip, { window: '1h' })
  const events = useIpEvents(ip)
  const canLabel = can(session.data, 'labels:create')

  if (risk.isLoading || evidence.isLoading || activity.isLoading || devices.isLoading || events.isLoading) {
    return <Skeleton active />
  }

  if (risk.isError || evidence.isError || activity.isError || devices.isError || events.isError || !risk.data) {
    return <Alert showIcon title="IP 详情加载失败" type="error" />
  }

  const evidenceItems = evidence.data?.evidence ?? []
  const profile = activity.data
  const deviceInventory = devices.data

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title mono" level={3}>
            {ip}
          </Typography.Title>
          <Typography.Text type="secondary">风险解释、设备识别、访问画像、证据时间线和人工标注。</Typography.Text>
        </div>
        <Space wrap>
          <RiskLevelTag level={risk.data.level} />
          <RiskScore score={risk.data.score} />
        </Space>
      </div>

      <section className="details-grid">
        <div className="surface">
          <Typography.Title level={4}>风险摘要与置信度</Typography.Title>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="置信度">
              <Typography.Text strong style={{ color: '#38bdf8' }}>
                {Math.round(risk.data.confidence * 100)}%
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="窗口">{risk.data.window}</Descriptions.Item>
            <Descriptions.Item label="建议动作">
              <Tag color="cyan">{risk.data.recommended_action}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="更新时间">
              {new Date(risk.data.updated_at).toLocaleString()}
            </Descriptions.Item>
            <Descriptions.Item label="证据解释">
              <Typography.Text className="wrap-text" style={{ color: '#f8fafc' }}>
                {risk.data.summary}
              </Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        </div>
        <div className="surface">
          <Typography.Title level={4}>人工标注控制台</Typography.Title>
          {!canLabel && <Alert showIcon style={{ marginBottom: 16 }} title="当前会话没有 labels:create 权限" type="warning" />}
          <LabelPanel
            disabled={!canLabel}
            evidenceIds={risk.data.evidence_ids}
            targetId={risk.data.ip}
          />
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>IP 维度设备识别</Typography.Title>
        {deviceInventory ? renderDeviceInventory(deviceInventory) : (
          <Typography.Text type="secondary">暂无设备识别结果</Typography.Text>
        )}
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
                <Typography.Text type="secondary">User-Agent 弱信号</Typography.Text>
                {renderCountList(profile.top_user_agents, '暂无 User-Agent 弱信号')}
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
              <div className="desktop-only">
                <Table<ActivityAccess>
                  columns={[
                    {
                      title: '时间',
                      dataIndex: 'timestamp',
                      width: 170,
                      render: (value: string) => new Date(value).toLocaleString(),
                    },
                    {
                      title: '类型',
                      dataIndex: 'type',
                      width: 80,
                      render: (value: string) => <Tag style={{ margin: 0 }}>{value}</Tag>,
                    },
                    {
                      title: '访问对象',
                      dataIndex: 'target',
                      render: (value: string, row) => (
                        <Space orientation="vertical" size={0}>
                          <Typography.Text className="mono wrap-text">{value}</Typography.Text>
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>{row.target_kind}</Typography.Text>
                        </Space>
                      ),
                    },
                    {
                      title: '目的',
                      width: 160,
                      render: (_, row) => (
                        <Typography.Text className="mono">
                          {row.dst_ip ?? '-'}
                          {row.dst_port ? `:${row.dst_port}` : ''}
                        </Typography.Text>
                      ),
                    },
                    {
                      title: 'UA 弱信号 / 方法',
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
                  scroll={{ x: 720 }}
                  size="small"
                />
              </div>

              <div className="mobile-only">
                <div className="mobile-access-list">
                  {profile.recent_accesses.map((acc) => (
                    <div className="mobile-access-card" key={acc.event_id}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                        <Tag color="blue" style={{ margin: 0 }}>{acc.type}</Tag>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {new Date(acc.timestamp).toLocaleString()}
                        </Typography.Text>
                      </div>
                      <Typography.Text className="mono wrap-text" strong style={{ fontSize: 13 }}>
                        {acc.target}
                      </Typography.Text>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {acc.target_kind} · {acc.dst_ip ?? '-'}:{acc.dst_port ?? ''}
                      </Typography.Text>
                      {acc.user_agent && (
                        <Typography.Text className="wrap-text" type="secondary" style={{ fontSize: 11 }}>
                          {acc.user_agent}
                        </Typography.Text>
                      )}
                    </div>
                  ))}
                </div>
              </div>
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
                <Tag color="blue" style={{ margin: 0 }}>{event.type}</Tag>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {new Date(event.timestamp).toLocaleString()}
                </Typography.Text>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  confidence {Math.round(event.confidence * 100)}%
                </Typography.Text>
              </Space>
              <div style={{ marginTop: 6, minWidth: 0 }}>
                <pre className="wrap-code mono" style={{ margin: 0 }}>
                  {JSON.stringify({ subject: event.subject, flow: event.flow, payload: event.payload }, null, 2)}
                </pre>
              </div>
            </div>
          ))
        )}
      </section>
    </main>
  )
}

function renderDeviceInventory(inventory: IpDeviceInventory) {
  const confidencePercent = Math.round(inventory.confidence * 100)
  return (
    <Space className="full-width" direction="vertical" size="middle">
      <Alert
        showIcon
        description={inventory.summary}
        message={deviceStatusText(inventory.status)}
        type={inventory.status === 'multi_candidate' ? 'warning' : inventory.status === 'weak_signals_only' ? 'info' : 'success'}
      />
      <div className="metric-grid">
        <div className="surface metric-card">
          <Statistic title="疑似设备数" value={inventory.suspected_device_count} />
        </div>
        <div className="surface metric-card">
          <Statistic suffix="%" title="设备置信度" value={confidencePercent} />
        </div>
        <div className="surface metric-card">
          <Statistic title="识别信号" value={inventory.signals.length} />
        </div>
        <div className="surface metric-card">
          <Statistic title="冲突信号" value={inventory.conflicts.length} />
        </div>
      </div>

      {inventory.devices.length === 0 ? (
        <Typography.Text type="secondary">当前 IP 没有足够信号生成设备候选。</Typography.Text>
      ) : (
        <div className="device-card-grid">
          {inventory.devices.map((device) => renderObservedDevice(device))}
        </div>
      )}

      {inventory.conflicts.length > 0 && (
        <div>
          <Typography.Title level={5}>冲突信号</Typography.Title>
          <div className="device-conflict-list">
            {inventory.conflicts.map((conflict) => renderDeviceConflict(conflict))}
          </div>
        </div>
      )}
    </Space>
  )
}

function renderObservedDevice(device: ObservedDevice) {
  return (
    <div className="device-card" key={device.device_id}>
      <div className="device-card-header">
        <div className="device-card-title">
          <Typography.Text className="wrap-text" strong>{device.label}</Typography.Text>
          <Typography.Text className="mono device-card-id" type="secondary">{device.device_id}</Typography.Text>
        </div>
        <Progress className="device-confidence" percent={Math.round(device.confidence * 100)} size="small" />
      </div>
      <div className="device-attribute-grid">
        <DeviceAttribute label="品牌" value={device.brand} />
        <DeviceAttribute label="厂商" value={device.vendor} />
        <DeviceAttribute label="系统" value={device.os_family} />
        <DeviceAttribute label="类型" value={device.device_type} />
        <DeviceAttribute label="型号" value={device.model} />
      </div>
      <Typography.Paragraph className="device-summary" type="secondary">
        {device.summary}
      </Typography.Paragraph>
      <div className="device-signal-stats">
        <Tag color="green">强 {device.strong_signal_count}</Tag>
        <Tag color="blue">中 {device.medium_signal_count}</Tag>
        <Tag color="default">弱 {device.weak_signal_count}</Tag>
      </div>
      <div className="device-signal-list">
        {device.signals.map((signal) => renderDeviceSignal(signal))}
      </div>
    </div>
  )
}

function DeviceAttribute({ label, value }: { label: string; value: string }) {
  return (
    <div className="device-attribute">
      <Typography.Text type="secondary">{label}</Typography.Text>
      <Typography.Text className="wrap-text">{value || 'unknown'}</Typography.Text>
    </div>
  )
}

function renderDeviceSignal(signal: DeviceSignal) {
  return (
    <span className="device-signal-token" key={signal.signal_id}>
      <Tag color={signalStrengthColor(signal.strength)}>{signal.strength}</Tag>
      <Typography.Text className="mono wrap-text">
        {signal.source}/{signal.kind}: {signal.value}
      </Typography.Text>
    </span>
  )
}

function renderDeviceConflict(conflict: DeviceConflict) {
  return (
    <div className="device-conflict-card" key={conflict.conflict_id}>
      <Space wrap>
        <Tag color={signalStrengthColor(conflict.strength)}>{conflict.strength}</Tag>
        <Tag>{conflict.type}</Tag>
        <Typography.Text type="secondary">confidence {Math.round(conflict.confidence * 100)}%</Typography.Text>
      </Space>
      <Typography.Paragraph className="device-summary">
        {conflict.summary}
      </Typography.Paragraph>
      <div className="device-signal-list">
        {conflict.samples.map((sample) => (
          <span className="sample-token" key={`${conflict.conflict_id}-${sample}`}>
            <Typography.Text className="mono wrap-text">{sample}</Typography.Text>
          </span>
        ))}
      </div>
    </div>
  )
}

function signalStrengthColor(strength: string) {
  if (strength === 'strong') return 'green'
  if (strength === 'medium') return 'blue'
  return 'default'
}

function deviceStatusText(status: string) {
  switch (status) {
    case 'multi_candidate':
      return '发现多个设备候选'
    case 'single_candidate':
      return '单设备候选'
    case 'weak_signals_only':
      return '仅有弱信号'
    default:
      return '设备信号不足'
  }
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
