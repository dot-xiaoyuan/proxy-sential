import { ClockCircleOutlined } from '@ant-design/icons'
import { DatePicker, Segmented, Space, Tag } from 'antd'

export type QuickWindow = '10m' | '1h' | '24h'

interface AppTimePickerProps {
  quickWindow: QuickWindow
  onQuickWindowChange: (window: QuickWindow) => void
  onCustomRangeChange?: (range: unknown) => void
}

const windowOptions = [
  { label: '10 分钟', value: '10m' },
  { label: '1 小时', value: '1h' },
  { label: '24 小时', value: '24h' },
]

export function AppTimePicker({
  quickWindow,
  onQuickWindowChange,
  onCustomRangeChange,
}: AppTimePickerProps) {
  return (
    <Space size="small" wrap>
      <Segmented
        onChange={(val) => onQuickWindowChange(val as QuickWindow)}
        options={windowOptions}
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
