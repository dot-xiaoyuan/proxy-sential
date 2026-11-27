import { useMemo } from 'react'

import type { components } from '../../shared/api/generated'
import { AppChart, type AppChartOption } from '../../shared/ui/AppChart'

type Bucket = components['schemas']['SharedDecisionTrend']['buckets'][number]

const clock = new Intl.DateTimeFormat('zh-CN', {
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
})

const seriesMeta = [
  { name: '策略命中', field: 'matched', color: '#2257a7' },
  { name: '证据不足', field: 'insufficient', color: '#d97706' },
  { name: '证据过期', field: 'expired', color: '#94a3b8' },
] as const

export function SharedTrendChart({ buckets }: { buckets: Bucket[] }) {
  const option = useMemo<AppChartOption>(
    () => ({
      animation: false,
      aria: {
        enabled: true,
        label: { description: '按时间桶展示策略命中、证据不足和证据过期的判定记录数' },
      },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { top: 12, right: 10, bottom: 48, left: 44 },
      legend: { bottom: 0, itemWidth: 10, itemHeight: 10, textStyle: { color: '#475569' } },
      xAxis: {
        type: 'category',
        data: buckets.map((bucket) => clock.format(new Date(bucket.from))),
        axisLine: { lineStyle: { color: '#cbd5e1' } },
        axisLabel: { color: '#475569' },
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        axisLabel: { color: '#475569' },
        splitLine: { lineStyle: { color: '#e2e8f0' } },
      },
      series: seriesMeta.map(({ name, field, color }) => ({
        name,
        type: 'bar',
        stack: 'decisions',
        barMaxWidth: 32,
        data: buckets.map((bucket) => bucket[field]),
        itemStyle: { color, borderRadius: [2, 2, 0, 0] },
      })),
    }),
    [buckets],
  )

  return (
    <AppChart
      ariaLabel="按时间桶展示策略命中、证据不足和证据过期的判定记录数"
      className="defense-trend-chart"
      option={option}
    />
  )
}
