import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { SearchOutlined } from '@ant-design/icons'
import { Button, Col, Row, Table, Tabs, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { EChartsDualAxisTrend } from '../features/charts/EChartsDualAxisTrend'
import { EChartsTopReport } from '../features/charts/EChartsTopReport'
import { FingerprintConflictMatrix } from '../features/dpi/FingerprintConflictMatrix'
import { FlowInspectorDrawer } from '../features/dpi/FlowInspectorDrawer'
import {
  useActivityOverview,
	useActivityReport,
  useDpiFingerprintConflicts,
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

export function ActivityPage() {
	const navigate=useNavigate()
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const [tabKey, setTabKey] = useState<'applications' | 'ecosystem' | 'matrix' | 'domains' | 'fingerprints' | 'network'>('applications')
  const [inspectIp, setInspectIp] = useState<string | null>(null)

  const activity = useActivityOverview({ window: quickWindow })
  const dpiTrends = useDpiTrends({ window: quickWindow })
  const fingerprintConflicts = useDpiFingerprintConflicts({ window: quickWindow }, tabKey === 'matrix')
	const applicationReport=useActivityReport({window:quickWindow,dimension:'application',limit:10},tabKey==='applications')
	const protocolReport=useActivityReport({window:quickWindow,dimension:'protocol',limit:10},tabKey==='applications'||tabKey==='network')
	const ecosystemReport=useActivityReport({window:quickWindow,dimension:'ecosystem',limit:10},tabKey==='ecosystem')
	const domainReport=useActivityReport({window:quickWindow,dimension:'domain',limit:10},tabKey==='domains')
	const hostReport=useActivityReport({window:quickWindow,dimension:'http_host',limit:10},tabKey==='domains')
	const sniReport=useActivityReport({window:quickWindow,dimension:'tls_sni',limit:10},tabKey==='domains')
	const uaReport=useActivityReport({window:quickWindow,dimension:'user_agent',limit:10},tabKey==='fingerprints')
	const portReport=useActivityReport({window:quickWindow,dimension:'dst_port',limit:10},tabKey==='network')
  const destinationReport=useActivityReport({window:quickWindow,dimension:'dst_ip',limit:10},tabKey==='network')
	const navigateReport=(dimension:string,key:string)=>navigate(reportSearchPath(dimension,key,quickWindow))

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
      case 'applications':
        return (
			<Row className="activity-tab-panel" gutter={[16,16]}><Col xs={24} md={12}><EChartsTopReport title="应用协议分布" kind="donut" report={applicationReport.data} note="仅使用传感器明确输出的应用协议；无法识别时归入未知。" onSelect={(key)=>navigateReport('application',key)}/></Col><Col xs={24} md={12}><EChartsTopReport title="网络协议分布" kind="donut" report={protocolReport.data} onSelect={(key)=>navigateReport('protocol',key)}/></Col></Row>
        )
	  case 'ecosystem':
		return <div className="activity-tab-panel"><EChartsTopReport title="访问品牌生态" kind="donut" report={ecosystemReport.data} note="访问相关服务不等于确认终端硬件品牌，未归属命中也会计入本报表。" onSelect={(key)=>navigateReport('ecosystem',key)}/></div>
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
			  <EChartsTopReport title="Top 访问域名（DNS / Host / SNI）" kind="bar" report={domainReport.data} onSelect={(key)=>navigateReport('domain',key)}/>
            </Col>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="HTTP Host" kind="bar" report={hostReport.data} onSelect={(key)=>navigateReport('domain',key)}/>
            </Col>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="TLS SNI" kind="bar" report={sniReport.data} onSelect={(key)=>navigateReport('domain',key)}/>
            </Col>
          </Row>
        )
      case 'fingerprints':
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="客户端软件标识（UA）" kind="bar" report={uaReport.data} note="UA 可重复、可伪造，只用于技术检索，不表示设备数量或硬件品牌。" onSelect={(key)=>navigateReport('user_agent',key)}/>
            </Col>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="TLS JA3 / JA4 客户端指纹" kind="bar" report={{dimension:'fingerprint',total:data.top_tls_fingerprints.reduce((sum,item)=>sum+item.count,0),classified_count:data.top_tls_fingerprints.reduce((sum,item)=>sum+item.count,0),unknown_count:0,items:data.top_tls_fingerprints.map(item=>({key:item.value,label:item.value,count:item.count,share:0,last_seen:item.last_seen}))}} onSelect={(key)=>navigateReport('fingerprint',key)}/>
            </Col>
          </Row>
        )
      case 'network':
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="目的端口排行" kind="bar" report={portReport.data} onSelect={(key)=>navigateReport('port',key)}/>
            </Col>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="传输协议分布" kind="donut" report={protocolReport.data} onSelect={(key)=>navigateReport('protocol',key)}/>
            </Col>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="目的 IP 排行" kind="bar" report={destinationReport.data} onSelect={(key)=>navigateReport('dst_ip',key)}/>
            </Col>
            <Col xs={24} md={12}>
			  <EChartsTopReport title="活跃源 IP 排行" kind="bar" report={{dimension:'src_ip',total:data.top_source_ips.reduce((sum,item)=>sum+item.count,0),classified_count:data.top_source_ips.reduce((sum,item)=>sum+item.count,0),unknown_count:0,items:data.top_source_ips.map(item=>({key:item.value,label:item.value,count:item.count,share:0,last_seen:item.last_seen}))}} onSelect={(key)=>navigateReport('src_ip',key)}/>
            </Col>
          </Row>
        )
    }
  }

  const tabItems = [
    { key: 'applications', label: '应用与协议报表' },
	{ key: 'ecosystem', label: '访问生态' },
    { key: 'matrix', label: '多源指纹一致性' },
    { key: 'domains', label: '访问对象 (Domains)' },
    { key: 'fingerprints', label: '客户端指纹 (UA/JA3)' },
    { key: 'network', label: '网络与端口分布' },
  ]

  return (
    <main className="page">
      <AppPageHeader
        loading={activity.isFetching || dpiTrends.isFetching || (tabKey === 'matrix' && fingerprintConflicts.isFetching)}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => {
          void activity.refetch()
          void dpiTrends.refetch()
          if (tabKey === 'matrix') void fingerprintConflicts.refetch()
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
        <EChartsDualAxisTrend loading={dpiTrends.isLoading} points={dpiTrends.data?.points ?? []} />
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

function reportSearchPath(kind: string, value: string, window:string) {
  if(kind==='ecosystem')return `/devices?ecosystem=${encodeURIComponent(value)}`
  const params = new URLSearchParams({ window })
  if (kind === 'port') {
    params.set('port', value)
  } else if (kind === 'protocol') {
    params.set('proto', value)
  } else if(kind==='application') {
	params.set('app_protocol',value)
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
