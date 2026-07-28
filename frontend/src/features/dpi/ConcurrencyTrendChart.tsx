import { LineChartOutlined } from '@ant-design/icons'
import { Card, Col, Progress, Row, Tag, Typography } from 'antd'

import type { DpiTrendPoint } from '../../shared/api/types'

interface ConcurrencyTrendChartProps {
  points: DpiTrendPoint[]
  windowValue: string
}

export function ConcurrencyTrendChart({ points, windowValue }: ConcurrencyTrendChartProps) {
  const maxDevices = points.length > 0 ? Math.max(...points.map((p) => p.active_devices)) : 1
  const maxPps = points.length > 0 ? Math.max(...points.map((p) => p.pps ?? 0)) : 1

  return (
    <Card className="surface-card" size="small">
      <div className="dpi-card-header">
        <div className="dpi-card-title">
          <LineChartOutlined className="dpi-card-title-icon" />
          <span>24h 设备并发与流量吞吐双轴趋势 (Concurrency & Throughput)</span>
          <Tag className="dpi-badge-tag" color="blue">
            窗口: {windowValue}
          </Tag>
        </div>
        <Typography.Text className="dpi-card-hint" type="secondary">
          结合双轴时间序列监测共享上网峰值与并发异常
        </Typography.Text>
      </div>

      <Row gutter={[12, 12]}>
        {points.map((point) => {
          const devicePercent = Math.round((point.active_devices / maxDevices) * 100)
          const pps = point.pps ?? 0
          const bps = point.bps_mbps
          const ppsPercent = maxPps > 0 ? Math.round((pps / maxPps) * 100) : 0

          return (
            <Col key={point.time} xs={12} sm={8} md={4}>
              <div className="concurrency-point-card">
                <div className="concurrency-point-time">
                  {point.time}
                </div>

                <div className="concurrency-point-devices">
                  {point.active_devices} <span className="concurrency-point-unit">台</span>
                </div>
                <Typography.Text className="concurrency-point-subtext" type="secondary">
                  风险 IP: {point.risk_ips}
                </Typography.Text>

                <div className="concurrency-point-progress">
                  <Progress
                    percent={devicePercent}
                    railColor="#e2e8f0"
                    showInfo={false}
                    size="small"
                    strokeColor="#0284c7"
                  />
                </div>

                <div className="concurrency-point-pps">
                  {(pps / 1000).toFixed(1)}k PPS
                </div>
                <Typography.Text className="concurrency-point-subtext" type="secondary">
                  {bps == null ? 'Mbps 缺失' : `${bps} Mbps`}
                </Typography.Text>

                <div className="concurrency-point-progress-tight">
                  <Progress
                    percent={ppsPercent}
                    railColor="#e2e8f0"
                    showInfo={false}
                    size="small"
                    strokeColor="#059669"
                  />
                </div>
              </div>
            </Col>
          )
        })}
      </Row>
    </Card>
  )
}
