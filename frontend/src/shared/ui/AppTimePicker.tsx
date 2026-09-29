import { ClockCircleOutlined } from '@ant-design/icons'
import { DatePicker, Segmented, Space, Tag } from 'antd'

export type QuickWindow = '10m' | '1h' | '24h'
export type ReportWindow = QuickWindow | '7d' | '30d'

interface AppTimePickerProps<T extends ReportWindow> {
  quickWindow: T
  onQuickWindowChange: (window: T) => void
  onCustomRangeChange?: (range: unknown) => void
  windows?: T[]
}

const allWindowOptions = [
  { label: '10 分钟', value: '10m' },
  { label: '1 小时', value: '1h' },
  { label: '24 小时', value: '24h' },
  { label: '7 天', value: '7d' },
  { label: '30 天', value: '30d' },
]

export function AppTimePicker<T extends ReportWindow>({
  quickWindow,
  onQuickWindowChange,
  onCustomRangeChange,
  windows,
}: AppTimePickerProps<T>) {
  const enabledWindows = windows ?? (['10m', '1h', '24h'] as T[])
  return (
    <Space size="small" wrap>
      <Segmented
        onChange={(val) => onQuickWindowChange(val as T)}
        options={allWindowOptions.filter((item) => enabledWindows.includes(item.value as T))}
        value={quickWindow}
      />
      {onCustomRangeChange && (
        <DatePicker.RangePicker
          allowClear
          onChange={(dates) => {
            if (!dates) {
              onCustomRangeChange(null)
            } else {
              onCustomRangeChange([dates[0], dates[1]])
            }
          }}
          placeholder={['开始时间', '结束时间']}
          showTime
          size="middle"
          className="time-range-picker"
        />
      )}
      <Tag className="dpi-badge-tag" icon={<ClockCircleOutlined />} color="blue">
        窗口: {quickWindow}
      </Tag>
    </Space>
  )
}
