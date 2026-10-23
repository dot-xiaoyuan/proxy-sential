import type { ReactNode } from 'react'
import { Select, Space, Typography } from 'antd'

import { AppTimePicker, type QuickWindow, type ReportWindow } from './AppTimePicker'

interface AppPageHeaderProps<T extends ReportWindow> {
  title?: string
  subtitle?: string
  extra?: ReactNode
  sensorId?: string
  onSensorChange?: (sensorId: string) => void
  quickWindow?: T
  onQuickWindowChange?: (window: T) => void
  quickWindows?: T[]
}

export function AppPageHeader<T extends ReportWindow = QuickWindow>({
  title,
  subtitle,
  extra,
  sensorId = 'current-sensor',
  onSensorChange,
  quickWindow,
  onQuickWindowChange,
  quickWindows,
}: AppPageHeaderProps<T>) {
  const hasActions = Boolean(onSensorChange || onQuickWindowChange || extra)
  if (!title && !subtitle && !hasActions) return null
  return (
    <div className={`page-header page-header-spaced${title ? '' : ' page-header-actions-only'}`}>
      {title && (
        <div className="page-header-main">
          <Typography.Title className="page-title" level={3}>
            {title}
          </Typography.Title>
          {subtitle && (
            <Typography.Text className="page-subtitle" type="secondary">
              {subtitle}
            </Typography.Text>
          )}
        </div>
      )}

      <Space className="page-header-actions" size="small" wrap>
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
            quickWindow={(quickWindow ?? '1h') as T}
            windows={quickWindows}
          />
        )}

        {extra}

      </Space>
    </div>
  )
}
