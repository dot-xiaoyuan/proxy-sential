import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Alert, Card, Col, Row, Segmented, Skeleton, Space, Statistic, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { useActivityOverview } from '../shared/api/queries'
import type { ActivityCount, ActivityIpSummary, ActivityOverviewQuery } from '../shared/api/types'

const windowOptions: Array<NonNullable<ActivityOverviewQuery['window']>> = ['10m', '1h', '24h']

const riskColumns: ColumnsType<ActivityIpSummary> = [
  {
    title: 'IP',
    dataIndex: 'ip',
    width: 190,
    render: (value: string) => (
      <Link className="mono" to={`/ips/${encodeURIComponent(value)}`}>
        {value}
      </Link>
    ),
  },
  {
    title: '等级',
    dataIndex: 'risk_level',
    width: 120,
    render: (value: ActivityIpSummary['risk_level']) => <RiskLevelTag level={value} />,
  },
  {
    title: '分数',
    dataIndex: 'score',
    width: 120,
    render: (value: number) => <RiskScore score={value} />,
  },
  { title: '事件数', dataIndex: 'event_count', width: 110 },
  {
    title: 'Top 访问对象',
    dataIndex: 'top_domains',
    render: (items: ActivityCount[]) => renderCountTokens(items, '暂无域名对象'),
  },
  {
    title: '最后出现',
    dataIndex: 'last_seen',
    width: 190,
    render: (value?: string) => (value ? new Date(value).toLocaleString() : '-'),
  },
]

export function ActivityPage() {
  const [windowValue, setWindowValue] = useState<NonNullable<ActivityOverviewQuery['window']>>('1h')
  const activity = useActivityOverview({ window: windowValue })

  if (activity.isLoading) {
    return <Skeleton active />
  }

  if (activity.isError || !activity.data) {
    return <Alert showIcon title="访问态势加载失败" type="error" />
  }

  const data = activity.data

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            访问态势
          </Typography.Title>
          <Typography.Text type="secondary">
            当前 sensor 在指定窗口内的访问对象、客户端特征、网络分布和活跃风险 IP。
          </Typography.Text>
        </div>
        <Segmented
          onChange={(value) => setWindowValue(value as NonNullable<ActivityOverviewQuery['window']>)}
          options={windowOptions}
          value={windowValue}
        />
      </div>

      <section className="metric-grid">
        <Card className="metric-card">
          <Statistic title="标准事件" value={data.event_count} />
        </Card>
        <Card className="metric-card">
          <Statistic title="活跃 IP" value={data.active_ip_count} />
        </Card>
        <Card className="metric-card">
          <Statistic title="访问对象" value={data.access_object_count} />
        </Card>
        <Card className="metric-card">
          <Statistic title="活跃风险 IP" value={data.active_risk_ip_count} />
        </Card>
      </section>

      <section className="surface">
        <Space wrap>
          <Typography.Text>sensor</Typography.Text>
          <Typography.Text className="mono">{data.sensor_id}</Typography.Text>
          <Typography.Text type="secondary">window {data.window}</Typography.Text>
          {data.last_seen && <Typography.Text type="secondary">last seen {new Date(data.last_seen).toLocaleString()}</Typography.Text>}
        </Space>
      </section>

      <section className="content-grid">
        <div className="surface">
          <Typography.Title level={4}>访问对象排行</Typography.Title>
          <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, domain: value })} items={data.top_domains} title="Top domains（DNS/HTTP Host/TLS SNI 合并）" />
          <section className="details-grid">
            <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, type: 'http', domain: value })} items={data.top_http_hosts} title="HTTP Host" />
            <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, type: 'tls', domain: value })} items={data.top_tls_sni} title="TLS SNI" />
          </section>
        </div>
        <div className="surface">
          <Typography.Title level={4}>客户端特征排行</Typography.Title>
          <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, type: 'http', user_agent: value })} empty="暂无 User-Agent" items={data.top_user_agents} title="User-Agent" />
          <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, type: 'tls', fingerprint: value })} empty="暂无 JA3/JA4" items={data.top_tls_fingerprints} title="JA3 / JA4" />
        </div>
      </section>

      <section className="content-grid">
        <div className="surface">
          <Typography.Title level={4}>网络分布</Typography.Title>
          <section className="details-grid">
            <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, port: value })} items={data.top_dst_ports} title="目的端口" />
            <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, proto: value })} items={data.protocol_counts} title="协议分布" />
          </section>
          <section className="details-grid">
            <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, dst_ip: value })} items={data.top_dst_ips} title="目的 IP" />
            <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, src_ip: value })} items={data.top_source_ips} title="活跃源 IP" />
          </section>
        </div>
        <div className="surface">
          <Typography.Title level={4}>事件类型分布</Typography.Title>
          <RankBlock drilldown={(value) => eventSearchPath({ window: windowValue, type: value })} items={data.event_type_counts} title="标准事件类型" />
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>活跃风险 IP</Typography.Title>
        <Table<ActivityIpSummary>
          columns={riskColumns}
          dataSource={data.top_active_risk_ips}
          pagination={false}
          rowKey="ip"
          scroll={{ x: 920 }}
        />
      </section>
    </main>
  )
}

function RankBlock({ title, items, empty = '暂无数据', drilldown }: { title: string; items: ActivityCount[]; empty?: string; drilldown?: (value: string) => string }) {
  return (
    <div className="rank-block">
      <Typography.Title level={5}>{title}</Typography.Title>
      {items.length === 0 ? (
        <Typography.Text type="secondary">{empty}</Typography.Text>
      ) : (
        <Space className="rank-block-list" direction="vertical" size={8}>
          {items.slice(0, 10).map((item) => {
            const valueNode = <Typography.Text className="mono wrap-text">{item.value}</Typography.Text>
            return (
              <Row align="middle" gutter={12} key={`${title}-${item.value}`}>
                <Col flex="auto">
                  {drilldown ? <Link to={drilldown(item.value)}>{valueNode}</Link> : valueNode}
                </Col>
                <Col>
                  <Tag>{item.count}</Tag>
                </Col>
              </Row>
            )
          })}
        </Space>
      )}
    </div>
  )
}

function eventSearchPath(params: Record<string, string | number | undefined>) {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') {
      query.set(key, String(value))
    }
  }
  return `/events?${query.toString()}`
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
