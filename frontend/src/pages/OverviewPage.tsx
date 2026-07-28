import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  DatabaseOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { Card, Col, Row, Space, Typography } from 'antd'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { EChartsDistributionPie } from '../features/charts/EChartsDistributionPie'
import { useActivityOverview, useOverview } from '../shared/api/queries'
import type { RiskLevel } from '../shared/api/types'
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  type QuickWindow,
} from '../shared/ui'

const levelOrder: RiskLevel[] = ['confirmed', 'high', 'suspicious', 'normal']

const levelColors: Record<RiskLevel, string> = {
  confirmed: '#dc2626',
  high: '#ea580c',
  suspicious: '#d97706',
  normal: '#16a34a',
}

const levelNames: Record<RiskLevel, string> = {
  confirmed: '确诊代理 (Confirmed)',
  high: '高风险 (High Risk)',
  suspicious: '可疑共享 (Suspicious)',
  normal: '正常终端 (Normal)',
}

export function OverviewPage() {
  const [quickWindow, setQuickWindow] = useState<QuickWindow>('1h')
  const overview = useOverview()
  const activity = useActivityOverview({ window: quickWindow })

  if (overview.isLoading) {
    return <AppLoadingState rows={6} />
  }

  if (overview.isError || !overview.data) {
    return <AppErrorAlert title="总览控制塔加载失败" />
  }

  const riskPieData = levelOrder.map((level) => ({
    name: levelNames[level],
    value: overview.data.level_counts[level],
    color: levelColors[level],
  }))

  return (
    <main className="page">
      <AppPageHeader
        loading={overview.isFetching}
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => {
          void overview.refetch()
          void activity.refetch()
        }}
        quickWindow={quickWindow}
        subtitle="影子运行模式下的聚合风险分布、复核队列压力与抓包吞吐大局"
        title="检测运营总览 (Control Tower)"
      />

      <section className="metric-grid">
        <AppMetricCard
          icon={<AlertOutlined style={{ color: '#ef4444' }} />}
          statusColor="red"
          statusText="需复核"
          title="待复核压力"
          trend={12.4}
          value={overview.data.pending_reviews}
        />
        <AppMetricCard
          icon={<DatabaseOutlined style={{ color: '#0284c7' }} />}
          statusColor="blue"
          statusText="AF_XDP 吞吐"
          title="DPI 标准事件"
          trend={5.8}
          value={overview.data.throughput.events}
        />
        <AppMetricCard
          icon={<SafetyCertificateOutlined style={{ color: '#8b5cf6' }} />}
          statusColor="purple"
          statusText="多重指纹"
          title="聚合证据数"
          value={overview.data.throughput.evidence}
        />
        <AppMetricCard
          icon={<CheckCircleOutlined style={{ color: '#059669' }} />}
          statusColor="green"
          statusText="影子评估"
          title="全网风险快照"
          value={overview.data.throughput.risks}
        />
      </section>

      <section className="content-grid">
        <EChartsDistributionPie
          data={riskPieData}
          subtext="基于 10m/1h/24h 时间窗口下引擎聚合的设备风险评分"
          title="全网风险等级分布 (Risk Level Distribution)"
        />

        <Card className="surface-card" size="small" style={{ height: '100%' }}>
          <div className="dpi-card-header">
            <div className="dpi-card-title">
              <span>Top Evidence (热点证据贡献排行)</span>
            </div>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              多重 UA、JA3/JA4 错配与 TTL 步进占比
            </Typography.Text>
          </div>
          <Space orientation="vertical" size={10} style={{ width: '100%', marginTop: 8 }}>
            {overview.data.top_evidence.map((item) => (
              <Row align="middle" className="overview-top-item" justify="space-between" key={item.type}>
                <Col>
                  <Typography.Text className="mono overview-top-type">{item.type}</Typography.Text>
                </Col>
                <Col>
                  <Typography.Text className="overview-top-count">{item.count} 项</Typography.Text>
                </Col>
              </Row>
            ))}
          </Space>
        </Card>
      </section>

      <div className="details-grid">
        <section className="surface">
          <Row align="middle" justify="space-between" gutter={[16, 16]}>
            <Col>
              <Typography.Title level={4} style={{ margin: 0 }}>
                DPI 访问态势实时联动
              </Typography.Title>
              <Typography.Text type="secondary" style={{ fontSize: 13 }}>
                Sensor 在指定窗口 ({quickWindow}) 内抓取到 {activity.data?.active_ip_count ?? 0} 个识别终端、
                {activity.data?.access_object_count ?? 0} 个访问目标。
              </Typography.Text>
            </Col>
            <Col>
              <Space wrap size="large">
                <div>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>标准事件数</Typography.Text>
                  <div style={{ fontSize: 18, fontWeight: 700, color: '#0284c7' }}>
                    {activity.data?.event_count ?? 0}
                  </div>
                </div>
                <div>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>活跃共享 IP</Typography.Text>
                  <div style={{ fontSize: 18, fontWeight: 700, color: '#ef4444' }}>
                    {activity.data?.active_risk_ip_count ?? 0}
                  </div>
                </div>
                <Link to="/activity" style={{ fontWeight: 600, color: '#0284c7' }}>
                  进入深度 DPI 态势矩阵 ➔
                </Link>
              </Space>
            </Col>
          </Row>
        </section>

        <section className="surface">
          <div className="dpi-card-header">
            <Typography.Title level={4} style={{ margin: 0 }}>
              最近影子运行 (Latest Shadow Execution)
            </Typography.Title>
          </div>
          <Space wrap size="middle">
            <Typography.Text className="mono" style={{ color: '#0284c7', fontWeight: 600 }}>
              <ClockCircleOutlined style={{ marginRight: 6 }} />
              {overview.data.latest_shadow_run.run_id}
            </Typography.Text>
            <Typography.Text type="secondary">Sensor: {overview.data.latest_shadow_run.sensor_id}</Typography.Text>
            <Typography.Text type="secondary">评估快照数: {overview.data.latest_shadow_run.risk_list_count}</Typography.Text>
            {overview.data.latest_shadow_run.truncated && <RiskLevelTag level="suspicious" />}
          </Space>
        </section>
      </div>
    </main>
  )
}
