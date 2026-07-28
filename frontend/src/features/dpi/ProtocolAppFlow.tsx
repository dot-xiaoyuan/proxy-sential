import { CloudServerOutlined, NodeIndexOutlined } from '@ant-design/icons'
import { Card, Col, Progress, Row, Tag, Typography } from 'antd'

import type { DpiProtocolFlowItem } from '../../shared/api/types'

interface ProtocolAppFlowProps {
  items: DpiProtocolFlowItem[]
}

const categoryColors: Record<string, string> = {
  'Web/API': 'blue',
  'Encrypted Security': 'purple',
  'Core Infrastructure': 'cyan',
  'Proxy/Tethering': 'red',
  Other: 'default',
}

export function ProtocolAppFlow({ items }: ProtocolAppFlowProps) {
  return (
    <Card className="surface-card" size="small">
      <div className="dpi-card-header">
        <div className="dpi-card-title">
          <NodeIndexOutlined className="dpi-card-title-icon" />
          <span>DPI L7 应用与协议分层拓扑 (Protocol & App Flow)</span>
        </div>
        <Typography.Text className="dpi-card-hint" type="secondary">
          L7 Deep Packet Inspection 流量深度分级
        </Typography.Text>
      </div>

      <Row gutter={[16, 16]}>
        {items.map((item) => {
          const bpsFormatted = item.bps_mbps == null ? '吞吐字段缺失' : `${item.bps_mbps.toFixed(2)} Mbps`

          return (
            <Col key={item.protocol} xs={24} sm={12} md={6}>
              <div className="protocol-flow-card">
                <div className="protocol-flow-head">
                  <span className="protocol-flow-protocol">{item.protocol}</span>
                  <Tag className="dpi-badge-tag" color={categoryColors[item.category] ?? 'default'}>
                    {item.category}
                  </Tag>
                </div>

                <div className="protocol-flow-metric">
                  <span className="protocol-flow-percent">
                    {item.share_percent.toFixed(1)}%
                  </span>
                  <Typography.Text className="protocol-flow-rate" type="secondary">
                    ({bpsFormatted})
                  </Typography.Text>
                </div>

                <Progress percent={Math.min(100, Math.round(item.share_percent))} showInfo={false} size="small" />

                <div className="protocol-flow-apps">
                  <Typography.Text className="protocol-flow-app-label" type="secondary">
                    <CloudServerOutlined className="protocol-flow-app-icon" />
                    Top 应用/目标域:
                  </Typography.Text>
                  {item.top_apps.map((app, idx) => (
                    <span className="dpi-sample-pill" key={`${item.protocol}-app-${idx}`}>
                      {app}
                    </span>
                  ))}
                </div>
              </div>
            </Col>
          )
        })}
      </Row>
    </Card>
  )
}
