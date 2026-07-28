import { AlertOutlined, ApartmentOutlined, SafetyCertificateOutlined, SearchOutlined } from '@ant-design/icons'
import { Button, Card, Col, Progress, Row, Tag, Typography } from 'antd'

import { RiskLevelTag } from '../../entities/risk/RiskLevelTag'
import type { FingerprintConflictItem } from '../../shared/api/types'

interface FingerprintConflictMatrixProps {
  items: FingerprintConflictItem[]
  onInspectIp?: (ip: string) => void
}

export function FingerprintConflictMatrix({ items, onInspectIp }: FingerprintConflictMatrixProps) {
  const totalConflicts = items.length

  return (
    <Card className="surface-card" size="small">
      <div className="dpi-card-header">
        <div className="dpi-card-title">
          <ApartmentOutlined className="dpi-card-title-icon" />
          <span>终端指纹冲突矩阵 (Fingerprint Conflict Matrix)</span>
          <Tag className="dpi-badge-tag" color="purple">
            {totalConflicts} 组设备冲突
          </Tag>
        </div>
        <Typography.Text className="dpi-card-hint" type="secondary">
          DPI 聚合: UA 浏览器/OS 碰撞 + TLS JA3 栈错配 + IP TTL 步进
        </Typography.Text>
      </div>

      {items.length === 0 ? (
        <Typography.Text className="rank-card-empty" type="secondary">
          当前窗口下暂未捕获终端指纹冲突项
        </Typography.Text>
      ) : (
        <div className="dpi-matrix-container">
          {items.map((item) => {
            const conflictColor =
              item.conflict_type === 'ua_conflict'
                ? '#ef4444'
                : item.conflict_type === 'ja3_mismatch'
                  ? '#8b5cf6'
                  : '#f59e0b'

            return (
              <div className="dpi-conflict-item" key={item.id}>
                <Row align="middle" className="dpi-conflict-row" justify="space-between">
                  <Col flex="auto">
                    <div className="dpi-conflict-tags">
                      <span className="mono wrap-text dpi-conflict-ip">
                        {item.ip}
                      </span>
                      <RiskLevelTag level={item.risk_level} />
                      <Tag className="dpi-badge-tag" color={item.conflict_type === 'ua_conflict' ? 'red' : 'purple'}>
                        {item.type_label}
                      </Tag>
                      <Tag className="dpi-badge-tag" icon={<SafetyCertificateOutlined />} color="blue">
                        置信度 {(item.confidence * 100).toFixed(0)}%
                      </Tag>
                      <Tag className="dpi-badge-tag" icon={<AlertOutlined />} color="orange">
                        估计设备数 ×{item.device_count}
                      </Tag>
                    </div>
                  </Col>
                  <Col className="dpi-conflict-action">
                    <Button
                      icon={<SearchOutlined />}
                      onClick={() => onInspectIp?.(item.ip)}
                      size="small"
                      type="primary"
                      ghost
                      className="dpi-badge-tag"
                    >
                      下钻追查
                    </Button>
                  </Col>
                </Row>

                <Typography.Paragraph className="dpi-conflict-reason">
                  {item.reason}
                </Typography.Paragraph>

                <div className="dpi-sample-row">
                  <span className="dpi-sample-label">
                    指纹采样:
                  </span>
                  {item.detected_samples.map((sample, idx) => (
                    <span className="dpi-sample-pill" key={`${item.id}-sample-${idx}`}>
                      {sample}
                    </span>
                  ))}
                </div>

                <div className="dpi-conflict-progress">
                  <Progress
                    percent={Math.min(100, Math.round(item.confidence * 100))}
                    railColor="#f1f5f9"
                    showInfo={false}
                    size="small"
                    strokeColor={conflictColor}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </Card>
  )
}
