import ReactECharts from 'echarts-for-react'

import type { components } from '../../shared/api/generated'

type Bucket = components['schemas']['SharedDecisionTrend']['buckets'][number]

const clock = new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })

const series = [
  { name: '策略命中', field: 'matched', color: '#08755a' },
  { name: '证据不足', field: 'insufficient', color: '#b66911' },
  { name: '证据过期', field: 'expired', color: '#7591a9' },
] as const

export function SharedTrendChart({ buckets }: { buckets: Bucket[] }) {
  return (
    <ReactECharts className="defense-trend-chart" option={{
      animation: false,
      aria: { enabled: true, label: { description: '按时间桶展示策略命中、证据不足和证据过期的判定记录数' } },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { top: 12, right: 10, bottom: 50, left: 44 },
      legend: { bottom: 0, itemWidth: 10, itemHeight: 10 },
      xAxis: { type: 'category', data: buckets.map((bucket) => clock.format(new Date(bucket.from))) },
      yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#e2e8f0' } } },
      series: series.map(({ name, field, color }) => ({
        name, type: 'bar', stack: 'decisions', barMaxWidth: 32, data: buckets.map((bucket) => bucket[field]),
        itemStyle: { color },
      })),
    }} />
  )
}
