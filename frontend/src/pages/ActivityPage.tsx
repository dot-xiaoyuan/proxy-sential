import { useState } from 'react'
import { Link } from 'react-router-dom'
import { SearchOutlined } from '@ant-design/icons'
import { Button, Card, Col, Progress, Row, Table, Tabs, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { EChartsDualAxisTrend } from '../features/charts/EChartsDualAxisTrend'
import { EChartsSankeyFlow } from '../features/charts/EChartsSankeyFlow'
import { FingerprintConflictMatrix } from '../features/dpi/FingerprintConflictMatrix'
import { FlowInspectorDrawer } from '../features/dpi/FlowInspectorDrawer'
import {
  useActivityOverview,
  useDpiFingerprintConflicts,
  useDpiProtocolFlows,
  useDpiTrends,
} from '../shared/api/queries'
import type { ActivityCount, ActivityIpSummary } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  type QuickWindow,
} from '../shared/ui'

type DrilldownKind = 'domain' | 'user_agent' | 'fingerprint' | 'port' | 'proto' | 'dst_ip' | 'src_ip'

export function ActivityPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const [tabKey, setTabKey] = useState<'sankey' | 'matrix' | 'domains' | 'fingerprints' | 'network'>('sankey')
  const [inspectIp, setInspectIp] = useState<string | null>(null)

  const activity = useActivityOverview({ window: quickWindow })
  const dpiTrends = useDpiTrends({ window: quickWindow })
  const dpiProtocolFlows = useDpiProtocolFlows({ window: quickWindow })
  const fingerprintConflicts = useDpiFingerprintConflicts({ window: quickWindow })

  if (activity.isLoading) {
    return <AppLoadingState rows={8} />
  }

  if (activity.isError || !activity.data) {
    return <AppErrorAlert title="DPI 访问态势加载失败" />
  }

  const data = activity.data

  const riskColumns: ColumnsType<ActivityIpSummary> = [
    {
      title: 'IP 地址',
      dataIndex: 'ip',
      width: 160,
      render: (value: string) => (
        <Link className="mono wrap-text" to={`/ips/${encodeURIComponent(value)}`}>
          {value}
        </Link>
      ),
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      width: 100,
      render: (value: ActivityIpSummary['risk_level']) => <RiskLevelTag level={value} />,
    },
    {
      title: '综合评分',
      dataIndex: 'score',
      width: 90,
      render: (value: number) => <RiskScore score={value} />,
    },
    { title: 'DPI 事件数', dataIndex: 'event_count', width: 100 },
    {
      title: 'Top 访问对象 (DNS/SNI/Host)',
      dataIndex: 'top_domains',
      render: (items: ActivityCount[]) => renderCountTokens(items, '暂无域名对象'),
    },
    {
      title: '最后抓包时间',
      dataIndex: 'last_seen',
      width: 170,
      render: (value?: string) => (value ? new Date(value).toLocaleString() : '-'),
    },
    {
      title: '快捷追查',
      key: 'action',
      width: 110,
      render: (_, record) => (
        <Button
          className="dpi-badge-tag"
          icon={<SearchOutlined />}
          onClick={() => setInspectIp(record.ip)}
          size="small"
          type="link"
        >
          DPI Flow 样本
        </Button>
      ),
    },
  ]

  const renderActiveTabContent = () => {
    switch (tabKey) {
      case 'sankey':
        return (
          <div className="activity-tab-panel">
            <EChartsSankeyFlow items={dpiProtocolFlows.data?.items ?? []} />
          </div>
        )
      case 'matrix':
        return (
          <div className="activity-tab-panel">
            <FingerprintConflictMatrix
              items={fingerprintConflicts.data?.items ?? []}
              onInspectIp={(ip) => setInspectIp(ip)}
            />
          </div>
        )
      case 'domains':
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col span={24}>
              <RankCard drilldown="domain" items={data.top_domains} title="Top Domains 访问域名 (DNS / HTTP Host / TLS SNI)" />
            </Col>
            <Col xs={24} md={12}>
              <RankCard drilldown="domain" items={data.top_http_hosts} title="HTTP Host 明细" />
            </Col>
            <Col xs={24} md={12}>
              <RankCard drilldown="domain" items={data.top_tls_sni} title="TLS SNI 明细" />
            </Col>
          </Row>
        )
      case 'fingerprints':
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col xs={24} md={12}>
              <RankCard drilldown="user_agent" empty="暂无 User-Agent 采样" items={data.top_user_agents} title="User-Agent 客户端分布" />
            </Col>
            <Col xs={24} md={12}>
              <RankCard drilldown="fingerprint" empty="暂无 JA3/JA4 指纹" items={data.top_tls_fingerprints} title="TLS JA3 / JA4 客户端指纹" />
            </Col>
          </Row>
        )
      case 'network':
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col xs={24} md={12}>
              <RankCard drilldown="port" items={data.top_dst_ports} title="目的端口排行" />
            </Col>
            <Col xs={24} md={12}>
              <RankCard drilldown="proto" items={data.protocol_counts} title="传输协议分布" />
            </Col>
            <Col xs={24} md={12}>
              <RankCard drilldown="dst_ip" items={data.top_dst_ips} title="目的 IP 排行" />
            </Col>
            <Col xs={24} md={12}>
              <RankCard drilldown="src_ip" items={data.top_source_ips} title="活跃源 IP 排行" />
            </Col>
          </Row>
        )
    }
  }

  const tabItems = [
    { key: 'sankey', label: 'DPI 协议与应用桑基拓扑' },
    { key: 'matrix', label: '终端指纹冲突矩阵' },
    { key: 'domains', label: '访问对象 (Domains)' },
    { key: 'fingerprints', label: '客户端指纹 (UA/JA3)' },
    { key: 'network', label: '网络与端口分布' },
  ]

  return (
    <main className="page">
      <AppPageHeader
        loading={activity.isFetching || dpiTrends.isFetching || dpiProtocolFlows.isFetching || fingerprintConflicts.isFetching}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => {
          void activity.refetch()
          void dpiTrends.refetch()
          void dpiProtocolFlows.refetch()
          void fingerprintConflicts.refetch()
        }}
        quickWindow={quickWindow}
        subtitle="基于标准事件元数据呈现 L7 协议流向、终端指纹碰撞与访问对象排行"
        title="DPI 观测与访问态势"
      />

      <section className="metric-grid">
        <AppMetricCard
          statusColor="blue"
          statusText="标准格式"
          title="DPI 标准事件数"
          value={data.event_count}
        />
        <AppMetricCard
          statusColor="green"
          statusText="当前 sensor"
          title="观测域活跃 IP"
          value={data.active_ip_count}
        />
        <AppMetricCard
          statusColor="purple"
          statusText="SaaS/Web 目标"
          title="L7 访问目标数"
          value={data.access_object_count}
        />
        <AppMetricCard
          statusColor="red"
          statusText="多重指纹碰撞"
          title="活跃共享风险 IP"
          value={data.active_risk_ip_count}
        />
      </section>

      <section className="activity-trend-section">
        <EChartsDualAxisTrend points={dpiTrends.data?.points ?? []} />
      </section>

      <section className="surface">
        <Tabs activeKey={tabKey} items={tabItems} onChange={(k) => setTabKey(k as typeof tabKey)} />
        {renderActiveTabContent()}
      </section>

      <section className="surface">
        <div className="surface-title-row">
          <Typography.Title className="surface-title" level={4}>
            活跃共享风险 IP 监控 (Observed Risk IPs)
          </Typography.Title>
          <Typography.Text className="surface-subtitle" type="secondary">
            点击“DPI Flow 样本”可展开标准化会话追查抽屉
          </Typography.Text>
        </div>
        <Table<ActivityIpSummary>
          columns={riskColumns}
          dataSource={data.top_active_risk_ips}
          pagination={false}
          rowKey="ip"
          scroll={{ x: 960 }}
          size="middle"
        />
      </section>

      <FlowInspectorDrawer
        ip={inspectIp}
        onClose={() => setInspectIp(null)}
        open={Boolean(inspectIp)}
      />
    </main>
  )
}

function RankCard({
  title,
  items,
  empty = '暂无数据',
  drilldown,
}: {
  title: string
  items: ActivityCount[]
  empty?: string
  drilldown?: DrilldownKind
}) {
  const maxCount = items.length > 0 ? Math.max(...items.map((i) => i.count)) : 1
  const totalCount = items.reduce((acc, curr) => acc + curr.count, 0)

  return (
    <Card className="rank-card-container rank-card-full-height" size="small">
      <div className="rank-card-header">
        <span className="rank-card-title">{title}</span>
        <Tag className="rank-card-badge">{items.length} 项</Tag>
      </div>
      {items.length === 0 ? (
        <Typography.Text className="rank-card-empty" type="secondary">
          {empty}
        </Typography.Text>
      ) : (
        <div className="rank-card-list">
          {items.slice(0, 7).map((item, idx) => {
            const percent = Math.round((item.count / maxCount) * 100)
            const sharePercent = totalCount > 0 ? ((item.count / totalCount) * 100).toFixed(1) : '0.0'
            const badgeClass = idx === 0 ? 'badge-rank-1' : idx === 1 ? 'badge-rank-2' : idx === 2 ? 'badge-rank-3' : 'badge-rank-other'
            const badgeText = idx === 0 ? '1' : idx === 1 ? '2' : idx === 2 ? '3' : `${idx + 1}`

            return (
              <div className="rank-item-capsule" key={`${title}-${item.value}`}>
                <Row align="middle" className="rank-item-row" justify="space-between">
                  <Col className="rank-item-main" flex="auto">
                    <div className="rank-item-value">
                      <span className={`rank-pill-badge ${badgeClass}`}>{badgeText}</span>
                      {drilldown ? (
                        <Link className="mono wrap-text rank-item-link" to={eventSearchPath(drilldown, item.value)}>
                          {item.value}
                        </Link>
                      ) : (
                        <Typography.Text className="mono wrap-text rank-item-text">{item.value}</Typography.Text>
                      )}
                    </div>
                  </Col>
                  <Col className="rank-item-count">
                    <div className="rank-item-count-inner">
                      <span className="mono rank-item-count-value">
                        {item.count}
                      </span>
                      <Typography.Text className="rank-item-count-share" type="secondary">
                        ({sharePercent}%)
                      </Typography.Text>
                    </div>
                  </Col>
                </Row>
                <Progress
                  percent={percent}
                  railColor="#f1f5f9"
                  showInfo={false}
                  size="small"
                  strokeColor={{
                    '0%': '#0284c7',
                    '100%': '#38bdf8',
                  }}
                />
              </div>
            )
          })}
        </div>
      )}
    </Card>
  )
}

function eventSearchPath(kind: DrilldownKind, value: string) {
  const params = new URLSearchParams({ window: '1h' })
  if (kind === 'port') {
    params.set('port', value)
  } else if (kind === 'proto') {
    params.set('proto', value)
  } else {
    params.set(kind, value)
  }
  return `/events?${params.toString()}`
}

function renderCountTokens(items: ActivityCount[], empty: string) {
  if (items.length === 0) {
    return <Typography.Text type="secondary">{empty}</Typography.Text>
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
