import ReactECharts from 'echarts-for-react'
import { Card, Tag, Typography } from 'antd'

import type { DpiProtocolFlowItem } from '../../shared/api/types'

interface EChartsSankeyFlowProps {
  items: DpiProtocolFlowItem[]
  loading?: boolean
  title?: string
}

export function EChartsSankeyFlow({
  items,
  loading = false,
  title = 'DPI L7 协议与应用流量流向桑基拓扑 (Sankey Flow Topology)',
}: EChartsSankeyFlowProps) {
  const nodes = new Map<string, { name: string; value?: number }>()
  const links: { source: string; target: string; value: number }[] = []
  for (const item of items) {
    const source = '当前 sensor'
    const protocol = item.app_protocol || item.protocol
    const value = item.event_count || 1
    nodes.set(source, { name: source })
    nodes.set(protocol, { name: protocol, value })
    links.push({ source, target: protocol, value })
    for (const app of item.top_apps.slice(0, 4)) {
      nodes.set(app, { name: app, value: Math.max(1, Math.round(value / Math.max(1, item.top_apps.length))) })
      links.push({
        source: protocol,
        target: app,
        value: Math.max(1, Math.round(value / Math.max(1, item.top_apps.length))),
      })
    }
  }

  const option = {
    tooltip: {
      trigger: 'item',
      triggerOn: 'mousemove',
      formatter: (params: any) => {
        if (params.dataType === 'edge') {
          return `${params.data.source} ➔ ${params.data.target}<br/><b>标准事件数:</b> ${params.data.value}`
        }
        return `<b>节点:</b> ${params.name}<br/><b>聚合事件:</b> ${params.value ?? '-'}`
      },
    },
    series: [
      {
        type: 'sankey',
        layout: 'none',
        emphasis: { focus: 'adjacency' },
        lineStyle: { color: 'gradient', curveness: 0.5, opacity: 0.4 },
        label: {
          color: '#334155',
          fontFamily: 'sans-serif',
          fontSize: 12,
          fontWeight: 500,
        },
        data: Array.from(nodes.values()),
        links,
      },
    ],
  }

  return (
    <Card className="surface-card" size="small">
      <div className="dpi-card-header">
        <div className="dpi-card-title">
          <span>{title}</span>
          <Tag className="dpi-badge-tag" color="blue">
            Apache ECharts
          </Tag>
        </div>
        <Typography.Text className="dpi-card-hint" type="secondary">
          鼠标悬停节点可查看标准事件聚合拓扑，当前不展示原始 EVE/payload
        </Typography.Text>
      </div>

      {loading ? (
        <Typography.Text className="chart-empty-state" type="secondary">
          DPI 协议流聚合查询中…
        </Typography.Text>
      ) : items.length === 0 ? (
        <Typography.Text className="chart-empty-state" type="secondary">
          当前窗口暂无可聚合的协议流数据，或 DPI 聚合接口暂不可用。
        </Typography.Text>
      ) : (
        <ReactECharts
          className="dpi-echart"
          option={option}
        />
      )}
    </Card>
  )
}
