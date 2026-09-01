import { useParams } from 'react-router-dom'
import { Alert, Descriptions, Progress, Skeleton, Space, Statistic, Table, Tabs, Tag, Typography } from 'antd'

import { EvidenceList } from '../entities/evidence/EvidenceList'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { ReviewStatusTag } from '../entities/risk/ReviewStatusTag'
import { LabelPanel } from '../features/labels/LabelPanel'
import { useIpActivity, useIpDevices, useIpEvidence, useIpEvents, useIpRisk, useSession } from '../shared/api/queries'
import type { ActivityAccess, ActivityCount, DeviceConflict, DeviceSignal, IpDeviceInventory, NegativeEvidence, NormalizedEventSummary, ObservedDevice } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

export function IpDetailsPage() {
  const rawIp = useParams().ip ?? ''
  const ip = decodeURIComponent(rawIp)
  const session = useSession()
  const risk = useIpRisk(ip)
  const evidence = useIpEvidence(ip, { limit: 20 })
  const activity = useIpActivity(ip)
  const devices = useIpDevices(ip, { window: '24h' })
  const events = useIpEvents(ip)
  const canLabel = can(session.data, 'labels:create')

  if (risk.isLoading) {
    return <Skeleton active />
  }

  if (risk.isError || !risk.data) {
    return <Alert showIcon title="IP 详情加载失败" type="error" />
  }

  const evidenceItems = evidence.data?.evidence ?? []
  const eventItems = events.data?.events ?? []
  const profile = activity.data
  const deviceInventory = devices.data
  const recentAccesses = profile?.recent_accesses.slice(0, 8) ?? []

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
              <Typography.Text strong className="text-light-blue">
                {Math.round(risk.data.confidence * 100)}%
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="窗口">{risk.data.window}</Descriptions.Item>
            {(risk.data.raw_score || risk.data.raw_level) && (
              <Descriptions.Item label="原始风险">
                <Space wrap>
                  {risk.data.raw_level && <RiskLevelTag level={risk.data.raw_level} />}
                  {typeof risk.data.raw_score === 'number' && <RiskScore score={risk.data.raw_score} />}
                </Space>
              </Descriptions.Item>
            )}
            <Descriptions.Item label="建议动作">
              <Tag color="cyan">{risk.data.recommended_action}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="复核状态">
              <Space wrap>
                <ReviewStatusTag reason={risk.data.review_reason} status={risk.data.review_status} />
                {risk.data.reviewed_by && (
                  <Typography.Text type="secondary">
                    {risk.data.reviewed_by}
                    {risk.data.reviewed_at ? ` / ${new Date(risk.data.reviewed_at).toLocaleString()}` : ''}
                  </Typography.Text>
                )}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="更新时间">
              {new Date(risk.data.updated_at).toLocaleString()}
            </Descriptions.Item>
            <Descriptions.Item label="证据解释">
              <Typography.Text className="wrap-text text-white-bg">
                {risk.data.summary}
              </Typography.Text>
            </Descriptions.Item>
          </Descriptions>
          {renderNegativeEvidence(risk.data.negative_evidence ?? [])}
        </div>
        <div className="surface">
          <Typography.Title level={4}>人工标注控制台</Typography.Title>
          {!canLabel && <Alert showIcon className="margin-bottom-md" title="当前会话没有 labels:create 权限" type="warning" />}
          <LabelPanel
            disabled={!canLabel}
            evidenceIds={risk.data.evidence_ids}
            targetId={risk.data.ip}
          />
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>IP 维度设备识别</Typography.Title>
        {devices.isLoading ? (
          <Skeleton active paragraph={{ rows: 4 }} />
        ) : devices.isError ? (
          <Alert showIcon title="设备识别加载失败" type="warning" />
        ) : deviceInventory ? renderDeviceInventory(deviceInventory) : (
          <Typography.Text type="secondary">暂无设备识别结果</Typography.Text>
        )}
      </section>

      <section className="surface">
        <Typography.Title level={4}>访问画像</Typography.Title>
        {activity.isLoading ? (
          <Skeleton active paragraph={{ rows: 4 }} />
        ) : activity.isError ? (
          <Alert showIcon title="访问画像加载失败" type="warning" />
        ) : !profile || profile.event_count === 0 ? (
          <Typography.Text type="secondary">暂无该 IP 的标准事件画像</Typography.Text>
        ) : (
          <Space className="full-width" orientation="vertical" size="middle">
            <div className="metric-grid">
              <div className="surface metric-card">
                <Statistic title="分析样本" value={profile.event_count} />
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

            <section className="activity-insight-grid">
              <div className="activity-insight-panel">
                <div className="section-title-row">
                  <Typography.Title level={5}>主要访问对象</Typography.Title>
                  <Typography.Text type="secondary">Top {Math.min(profile.top_domains.length, 8)}</Typography.Text>
                </div>
                {renderRankList(profile.top_domains, '暂无 DNS/HTTP Host/SNI')}
              </div>
              <div className="activity-insight-panel">
                <div className="section-title-row">
                  <Typography.Title level={5}>目的分布</Typography.Title>
                  <Typography.Text type="secondary">端口 / 协议</Typography.Text>
                </div>
                {renderRankList([...profile.top_dst_ports, ...profile.protocol_counts], '暂无端口或协议分布', 6)}
              </div>
              <div className="activity-insight-panel">
                <div className="section-title-row">
                  <Typography.Title level={5}>客户端特征</Typography.Title>
                  <Typography.Text type="secondary">UA / TLS</Typography.Text>
                </div>
                <Typography.Text className="activity-subtitle" type="secondary">User-Agent 弱信号</Typography.Text>
                {renderRankList(profile.top_user_agents, '暂无 User-Agent 弱信号', 4)}
                <Typography.Text className="activity-subtitle" type="secondary">TLS 指纹</Typography.Text>
                {renderRankList(profile.top_tls_fingerprints, '暂无 JA3/JA4', 4)}
              </div>
              <div className="activity-insight-panel">
                <div className="section-title-row">
                  <Typography.Title level={5}>分协议对象</Typography.Title>
                  <Typography.Text type="secondary">HTTP / TLS</Typography.Text>
                </div>
                <Typography.Text className="activity-subtitle" type="secondary">HTTP Host</Typography.Text>
                {renderRankList(profile.top_http_hosts, '暂无 HTTP Host', 4)}
                <Typography.Text className="activity-subtitle" type="secondary">TLS SNI</Typography.Text>
                {renderRankList(profile.top_tls_sni, '暂无 TLS SNI', 4)}
              </div>
            </section>

            <div>
              <div className="section-title-row">
                <Typography.Title level={5}>最近访问样本</Typography.Title>
                <Typography.Text type="secondary">仅展示最近 {recentAccesses.length} 条，完整明细见标准事件样本</Typography.Text>
              </div>
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
                      render: (value: string) => <Tag className="compact-tag">{value}</Tag>,
                    },
                    {
                      title: '访问对象',
                      dataIndex: 'target',
                      render: (value: string, row) => (
                        <Space orientation="vertical" size={0}>
                          <Typography.Text className="mono wrap-text">{value}</Typography.Text>
                          <Typography.Text type="secondary" className="font-size-sm">{row.target_kind}</Typography.Text>
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
                  dataSource={recentAccesses}
                  pagination={false}
                  rowKey="event_id"
                  scroll={{ x: 720 }}
                  size="small"
                />
              </div>

              <div className="mobile-only">
                <div className="mobile-access-list">
                  {recentAccesses.map((acc) => (
                    <div className="mobile-access-card" key={acc.event_id}>
                      <div className="flex-between-center">
                        <Tag color="blue" className="tag-margin-zero">{acc.type}</Tag>
                        <Typography.Text type="secondary" className="font-size-sm">
                          {new Date(acc.timestamp).toLocaleString()}
                        </Typography.Text>
                      </div>
                      <Typography.Text className="mono wrap-text font-size-md" strong>
                        {acc.target}
                      </Typography.Text>
                      <Typography.Text type="secondary" className="font-size-sm">
                        {acc.target_kind} · {acc.dst_ip ?? '-'}:{acc.dst_port ?? ''}
                      </Typography.Text>
                      {acc.user_agent && (
                        <Typography.Text className="wrap-text font-size-xs" type="secondary">
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
        <Typography.Text type="secondary">默认展示摘要，完整原始字段请进入事件检索按 event_id 下钻。</Typography.Text>
        <Tabs
          className="audit-sample-tabs"
          items={[
            {
              key: 'evidence',
              label: `证据摘要 ${evidenceItems.length}`,
              children: evidence.isLoading ? (
                <Skeleton active paragraph={{ rows: 4 }} />
              ) : evidence.isError ? (
                <Alert showIcon title="证据摘要加载失败" type="warning" />
              ) : (
                <EvidenceList evidence={evidenceItems} />
              ),
            },
            {
              key: 'events',
              label: `标准事件 ${eventItems.length}`,
              children: events.isLoading ? (
                <Skeleton active paragraph={{ rows: 4 }} />
              ) : events.isError ? (
                <Alert showIcon title="标准事件样本加载失败" type="warning" />
              ) : (
                renderEventSamples(eventItems)
              ),
            },
          ]}
        />
      </section>
    </main>
  )
}

function renderNegativeEvidence(items: NegativeEvidence[]) {
  if (items.length === 0) {
    return null
  }
  return (
    <div className="negative-evidence-list">
      <Typography.Text className="negative-evidence-title" strong>
        负证据命中
      </Typography.Text>
      {items.map((item) => (
        <div className="negative-evidence-item" key={`${item.source}-${item.type}`}>
          <Space wrap>
            <Tag className="table-tag" color="green">
              {negativeEvidenceLabel(item.type)}
            </Tag>
            <Typography.Text className="mono" type="secondary">
              {item.score_delta}
            </Typography.Text>
            {item.level_cap && (
              <Typography.Text type="secondary">
                上限 {item.level_cap}
              </Typography.Text>
            )}
          </Space>
          <Typography.Text className="wrap-text" type="secondary">
            {item.reason}
          </Typography.Text>
        </div>
      ))}
    </div>
  )
}

function negativeEvidenceLabel(type: NegativeEvidence['type']) {
  const labels: Record<NegativeEvidence['type'], string> = {
    manual_false_positive: '人工误报',
    manual_benign: '人工良性',
    needs_more_data: '需补数据',
    whitelist: '白名单',
    test_device: '测试设备',
    infrastructure: '基础设施',
    known_application: '已知应用',
  }
  return labels[type] ?? type
}

function renderDeviceInventory(inventory: IpDeviceInventory) {
  const confidencePercent = Math.round(inventory.confidence * 100)
  const hasDHCPStrongSignal = inventory.signals.some(
    (signal) => signal.strength === 'strong' && signal.source === 'dhcp',
  )
  return (
    <Space className="full-width" orientation="vertical" size="middle">
      <Alert
        showIcon
        description={inventory.summary}
        title={deviceStatusText(inventory.status)}
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

      {!hasDHCPStrongSignal && (
        <Alert
          className="zeek-status-alert"
          description="当前设备候选主要来自 UA、TLS 或 TCP 栈推断，UA 可伪造，建议等待 Zeek DHCP、mDNS、NBNS 等局域网强信号后再确认。"
          showIcon
          title="缺少 DHCP 强设备信号"
          type="info"
        />
      )}

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
      <Tag color={signalStrengthColor(signal.strength)}>{signalStrengthText(signal.strength)}</Tag>
      <Tag>{signalSourceText(signal.source)}</Tag>
      {signal.seen_count ? <Tag>出现 {signal.seen_count} 次</Tag> : null}
      <Typography.Text className="mono wrap-text">
        {signal.kind}: {signal.value}
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

function renderEventSamples(events: NormalizedEventSummary[]) {
  if (events.length === 0) {
    return <Typography.Text type="secondary">暂无标准事件样本。</Typography.Text>
  }
  const visibleEvents = events.slice(0, 6)
  const hiddenCount = events.length - visibleEvents.length
  return (
    <div className="event-compact-list">
      {visibleEvents.map((event) => (
        <article className="event-compact-card" key={event.event_id}>
          <div className="event-compact-head">
            <Tag className="compact-tag" color="blue">{event.type}</Tag>
            <Typography.Text type="secondary">{new Date(event.timestamp).toLocaleString()}</Typography.Text>
            <Typography.Text type="secondary">confidence {Math.round(event.confidence * 100)}%</Typography.Text>
          </div>
          <div className="event-compact-grid">
            <EventField label="访问对象" value={eventTarget(event)} />
            <EventField label="目的" value={eventDestination(event)} />
            <EventField label="来源" value={eventSource(event)} />
          </div>
          <Typography.Text className="mono wrap-text evidence-meta-text">{event.event_id}</Typography.Text>
        </article>
      ))}
      {hiddenCount > 0 && (
        <Typography.Text className="compact-muted-row" type="secondary">
          已收起 {hiddenCount} 条标准事件样本，完整字段请在事件检索中查看。
        </Typography.Text>
      )}
    </div>
  )
}

function EventField({ label, value }: { label: string; value: string }) {
  return (
    <div className="event-compact-field">
      <Typography.Text type="secondary">{label}</Typography.Text>
      <Typography.Text className="mono wrap-text">{value || '-'}</Typography.Text>
    </div>
  )
}

function eventTarget(event: NormalizedEventSummary) {
  return firstString(event.payload, ['query', 'host', 'sni', 'url', 'device_hint']) || firstString(event.flow, ['dst_ip'])
}

function eventDestination(event: NormalizedEventSummary) {
  const ip = firstString(event.flow, ['dst_ip'])
  const port = firstString(event.flow, ['dst_port'])
  if (!ip) {
    return '-'
  }
  return port ? `${ip}:${port}` : ip
}

function eventSource(event: NormalizedEventSummary) {
  const ip = firstString(event.flow, ['src_ip']) || firstString(event.subject, ['ip'])
  const port = firstString(event.flow, ['src_port'])
  if (!ip) {
    return '-'
  }
  return port ? `${ip}:${port}` : ip
}

function firstString(values: Record<string, unknown> | undefined, keys: string[]) {
  if (!values) {
    return ''
  }
  for (const key of keys) {
    const value = values[key]
    if (typeof value === 'string' && value !== '') {
      return value
    }
    if (typeof value === 'number') {
      return String(value)
    }
  }
  return ''
}

function signalStrengthColor(strength: string) {
  if (strength === 'strong') return 'green'
  if (strength === 'medium') return 'blue'
  return 'default'
}

function signalStrengthText(strength: string) {
  if (strength === 'strong') return '强'
  if (strength === 'medium') return '中'
  return '弱'
}

function signalSourceText(source: string) {
  if (source === 'dhcp' || source === 'device') return 'DHCP'
  if (source === 'http_ua') return 'UA'
  if (source === 'tls_fingerprint') return 'TLS'
  if (source === 'tcp_stack') return 'TCP'
  return source.toUpperCase()
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

function renderRankList(items: ActivityCount[], empty: string, limit = 8) {
  if (items.length === 0) {
    return <Typography.Paragraph type="secondary">{empty}</Typography.Paragraph>
  }
  const visibleItems = items.slice(0, limit)
  const hiddenCount = items.length - visibleItems.length
  return (
    <div className="rank-compact-list">
      {visibleItems.map((item, index) => (
        <div className="rank-compact-row" key={`${item.value}-${item.count}`}>
          <span className="rank-compact-index">{index + 1}</span>
          <Typography.Text className="mono rank-compact-value" ellipsis={{ tooltip: item.value }}>{item.value}</Typography.Text>
          <Typography.Text className="rank-compact-count">×{item.count}</Typography.Text>
        </div>
      ))}
      {hiddenCount > 0 && (
        <Typography.Text className="compact-muted-row" type="secondary">已收起 {hiddenCount} 项长尾对象</Typography.Text>
      )}
    </div>
  )
}
