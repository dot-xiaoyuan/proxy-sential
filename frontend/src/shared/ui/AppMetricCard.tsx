import type { ReactNode } from 'react'
import { ArrowDownOutlined, ArrowUpOutlined } from '@ant-design/icons'
import { Card, Tag, Typography } from 'antd'

interface AppMetricCardProps {
  title: string
  value: string | number
  unit?: string
  icon?: ReactNode
  trend?: number // 百分比变化（正为升，负为降）
  statusText?: string
  statusColor?: 'blue' | 'green' | 'orange' | 'red' | 'purple'
}

export function AppMetricCard({
  title,
  value,
  unit,
  icon,
  trend,
  statusText,
  statusColor = 'blue',
}: AppMetricCardProps) {
  return (
    <Card className="metric-card" size="small">
      <div className="metric-card-head">
        <Typography.Text className="metric-card-label" type="secondary">
          {title}
        </Typography.Text>
        {icon && <span className="metric-card-icon">{icon}</span>}
      </div>

      <div className="metric-card-value-row">
        <Typography.Title className="metric-card-value" level={3}>
          {value}
        </Typography.Title>
        {unit && (
          <Typography.Text className="metric-card-unit" type="secondary">
            {unit}
          </Typography.Text>
        )}
      </div>

      {(trend !== undefined || statusText) && (
        <div className="metric-card-footer">
          {trend !== undefined && (
            <span
              className={trend >= 0 ? 'metric-card-trend metric-card-trend-up' : 'metric-card-trend metric-card-trend-down'}
            >
              {trend >= 0 ? <ArrowUpOutlined /> : <ArrowDownOutlined />}
              {Math.abs(trend)}%
            </span>
          )}
          {statusText && (
            <Tag className="dpi-badge-tag" color={statusColor}>
              {statusText}
            </Tag>
          )}
        </div>
      )}
    </Card>
  )
}
