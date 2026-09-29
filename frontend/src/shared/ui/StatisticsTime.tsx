import { Tag } from 'antd'

export interface DataFreshness {
  status: 'warming' | 'fresh' | 'delayed' | 'stale'
  as_of?: string
  lag_seconds: number
  available_from?: string
  partial: boolean
}

export function StatisticsTime({ value, freshness }: { value?: string; freshness?: DataFreshness }) {
  const stamp = freshness?.as_of || value
  const validStamp = stamp && !Number.isNaN(Date.parse(stamp))
  if (!validStamp && !freshness) return null
  const state = freshness?.status
  const label = state === 'warming'
    ? '数据积累中'
    : state === 'delayed'
      ? '数据延迟'
      : state === 'stale'
        ? '当前展示最近成功快照'
        : '数据正常'
  const color = state === 'stale' ? 'red' : state === 'delayed' || state === 'warming' ? 'gold' : 'green'
  return (
    <div className="statistics-time">
      {freshness && <Tag color={color}>{label}</Tag>}
      {validStamp && <>数据统计于：<time dateTime={stamp}>{new Date(stamp).toLocaleString('zh-CN', { hour12: false })}</time></>}
      {freshness?.partial && freshness.available_from && (
        <span>，本窗口数据从 {new Date(freshness.available_from).toLocaleString('zh-CN', { hour12: false })} 起积累</span>
      )}
    </div>
  )
}
