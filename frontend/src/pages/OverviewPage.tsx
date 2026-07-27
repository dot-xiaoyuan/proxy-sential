import { Alert, Card, Col, Row, Skeleton, Space, Statistic, Typography } from 'antd'

import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { riskLevelLabel } from '../entities/risk/riskMeta'
import { useOverview } from '../shared/api/queries'
import type { RiskLevel } from '../shared/api/types'

const levelOrder: RiskLevel[] = ['confirmed', 'high', 'suspicious', 'normal']

export function OverviewPage() {
  const overview = useOverview()

  if (overview.isLoading) {
    return <Skeleton active />
  }

  if (overview.isError || !overview.data) {
    return <Alert showIcon title="总览加载失败" type="error" />
  }

  const totalRisks = levelOrder.reduce((sum, level) => sum + overview.data.level_counts[level], 0)

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            检测运营总览
          </Typography.Title>
          <Typography.Text type="secondary">影子模式下的风险分布、复核压力和运行吞吐。</Typography.Text>
        </div>
      </div>

      <section className="metric-grid">
        <Card className="metric-card">
          <Statistic title="待复核" value={overview.data.pending_reviews} />
        </Card>
        <Card className="metric-card">
          <Statistic title="标准事件" value={overview.data.throughput.events} />
        </Card>
        <Card className="metric-card">
          <Statistic title="证据数" value={overview.data.throughput.evidence} />
        </Card>
        <Card className="metric-card">
          <Statistic title="风险快照" value={overview.data.throughput.risks} />
        </Card>
      </section>

      <section className="content-grid">
        <div className="surface">
          <Typography.Title level={4}>风险等级分布</Typography.Title>
          <div className="risk-bars" role="list">
            {levelOrder.map((level) => {
              const count = overview.data.level_counts[level]
              const percent = totalRisks === 0 ? 0 : Math.round((count / totalRisks) * 100)
              return (
                <div className="risk-bar-row" key={level} role="listitem">
                  <div className="risk-bar-row__label">
                    <RiskLevelTag level={level} />
                    <Typography.Text>{riskLevelLabel(level)}</Typography.Text>
                    <Typography.Text strong>{count}</Typography.Text>
                  </div>
                  <div className="risk-bar">
                    <div className={`risk-bar__fill risk-bar__fill--${level}`} style={{ width: `${percent}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
        <div className="surface">
          <Typography.Title level={4}>Top Evidence</Typography.Title>
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            {overview.data.top_evidence.map((item) => (
              <Row align="middle" justify="space-between" key={item.type}>
                <Col>
                  <Typography.Text className="mono">{item.type}</Typography.Text>
                </Col>
                <Col>
                  <Typography.Text strong>{item.count}</Typography.Text>
                </Col>
              </Row>
            ))}
          </Space>
        </div>
      </section>

      <section className="surface">
        <Typography.Title level={4}>最近影子运行</Typography.Title>
        <Space wrap>
          <Typography.Text className="mono">{overview.data.latest_shadow_run.run_id}</Typography.Text>
          <Typography.Text>sensor {overview.data.latest_shadow_run.sensor_id}</Typography.Text>
          <Typography.Text>risk list {overview.data.latest_shadow_run.risk_list_count}</Typography.Text>
          {overview.data.latest_shadow_run.truncated && <RiskLevelTag level="suspicious" />}
        </Space>
      </section>
    </main>
  )
}
