import ReactECharts from 'echarts-for-react'
import { Card, Tag, Typography } from 'antd'

import type { DpiTrendPoint } from '../../shared/api/types'

interface EChartsDualAxisTrendProps {
  points: DpiTrendPoint[]
  title?: string
}

export function EChartsDualAxisTrend({
  points,
  title = '24h 设备并发与 PPS/BPS 吞吐双轴趋势 (Concurrency & Throughput)',
}: EChartsDualAxisTrendProps) {
  const times = points.map((p) => p.time)
  const activeDevices = points.map((p) => p.active_devices)
  const riskIps = points.map((p) => p.risk_ips)
  const pps = points.map((p) => p.pps ?? 0)
  const bps = points.map((p) => p.bps_mbps ?? 0)
  const events = points.map((p) => p.event_count)

  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'cross', crossStyle: { color: '#94a3b8' } },
    },
    legend: {
      data: ['估计并发设备数', '活跃风险 IP 数', '事件数', '吞吐 rate (Mbps)', '包速率 (kPPS)'],
      bottom: 0,
      textStyle: { color: '#475569', fontSize: 12 },
    },
    grid: {
      top: 30,
      left: 50,
      right: 50,
      bottom: 40,
    },
    xAxis: [
      {
        type: 'category',
        data: times,
        axisPointer: { type: 'shadow' },
        axisLine: { lineStyle: { color: '#cbd5e1' } },
      },
    ],
    yAxis: [
      {
        type: 'value',
        name: '设备 / IP 数',
        min: 0,
        axisLine: { lineStyle: { color: '#0284c7' } },
        splitLine: { lineStyle: { color: '#f1f5f9' } },
      },
      {
        type: 'value',
        name: '速率 (Mbps / kPPS)',
        min: 0,
        axisLine: { lineStyle: { color: '#059669' } },
        splitLine: { show: false },
      },
    ],
    series: [
      {
        name: '估计并发设备数',
        type: 'line',
        smooth: true,
        data: activeDevices,
        itemStyle: { color: '#0284c7' },
        lineStyle: { width: 3 },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(2, 132, 199, 0.25)' },
              { offset: 1, color: 'rgba(2, 132, 199, 0.0)' },
            ],
          },
        },
      },
      {
        name: '活跃风险 IP 数',
        type: 'line',
        smooth: true,
        data: riskIps,
        itemStyle: { color: '#ef4444' },
        lineStyle: { width: 2.5, type: 'dashed' },
      },
      {
        name: '事件数',
        type: 'bar',
        yAxisIndex: 1,
        data: events,
        itemStyle: { color: '#38bdf8', opacity: 0.55, borderRadius: [4, 4, 0, 0] },
      },
      {
        name: '吞吐 rate (Mbps)',
        type: 'bar',
        yAxisIndex: 1,
        data: bps,
        itemStyle: { color: '#38bdf8', opacity: 0.7, borderRadius: [4, 4, 0, 0] },
      },
      {
        name: '包速率 (kPPS)',
        type: 'bar',
        yAxisIndex: 1,
        data: pps.map((v) => Number((v / 1000).toFixed(1))),
        itemStyle: { color: '#10b981', opacity: 0.6, borderRadius: [4, 4, 0, 0] },
      },
    ],
  }

  return (
    <Card className="surface-card" size="small">
      <div className="dpi-card-header">
        <div className="dpi-card-title">
          <span>{title}</span>
          <Tag className="dpi-badge-tag" color="cyan">
            双轴时序引擎
          </Tag>
        </div>
        <Typography.Text className="dpi-card-hint" type="secondary">
          结合设备数、风险 IP 与事件速率洞察共享上网突发；缺少 packets/bytes 时 PPS/BPS 置空
        </Typography.Text>
      </div>

      {points.length === 0 ? (
        <Typography.Text className="chart-empty-state" type="secondary">
          当前窗口暂无 DPI 趋势点，缺少实时事件入库或聚合接口暂不可用。
        </Typography.Text>
      ) : (
        <ReactECharts className="dpi-echart" option={option} />
      )}
    </Card>
  )
}
