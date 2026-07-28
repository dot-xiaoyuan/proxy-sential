import type { ReactNode } from 'react'
import { ReloadOutlined } from '@ant-design/icons'
import { Button, Select, Space, Typography } from 'antd'

import { AppTimePicker, type QuickWindow } from './AppTimePicker'

interface AppPageHeaderProps {
  title: string
  subtitle?: string
  extra?: ReactNode
  sensorId?: string
  onSensorChange?: (sensorId: string) => void
  quickWindow?: QuickWindow
  onQuickWindowChange?: (window: QuickWindow) => void
  onRefresh?: () => void
  loading?: boolean
}

export function AppPageHeader({
  title,
  subtitle,
  extra,
  sensorId = 'current-sensor',
  onSensorChange,
  quickWindow = '1h',
  onQuickWindowChange,
  onRefresh,
  loading = false,
}: AppPageHeaderProps) {
  return (
    <div className="page-header page-header-spaced">
      <div>
        <Typography.Title className="page-title" level={3}>
          {title}
        </Typography.Title>
        {subtitle && (
          <Typography.Text className="page-subtitle" type="secondary">
            {subtitle}
          </Typography.Text>
        )}
      </div>

      <Space size="middle" wrap>
        {onSensorChange && (
          <Select
            className="sensor-select"
            onChange={onSensorChange}
            options={[
              { label: '当前 sensor', value: sensorId },
              { label: 'Sensor: datacenter-01', value: 'datacenter-01' },
              { label: 'Sensor: edge-gateway-05', value: 'edge-gateway-05' },
            ]}
            value={sensorId}
          />
        )}

        {onQuickWindowChange && (
          <AppTimePicker
            onQuickWindowChange={onQuickWindowChange}
            quickWindow={quickWindow}
          />
        )}

        {extra}

        {onRefresh && (
          <Button
            className="dpi-badge-tag"
            icon={<ReloadOutlined spin={loading} />}
            loading={loading}
            onClick={onRefresh}
          >
            刷新数据
          </Button>
        )}
      </Space>
    </div>
  )
}
