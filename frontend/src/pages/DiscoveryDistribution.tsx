import { lazy, Suspense, useState } from 'react'
import { Button, Segmented, Typography } from 'antd'
import type { EChartsOption } from 'echarts'
import type { components } from '../shared/api/generated'

type Metadata = components['schemas']['DiscoveryDeviceMetadata']
const ReactECharts = lazy(() => import('echarts-for-react'))

export function DiscoveryDistribution({data, vlanOnly = false, onSelect}: {
  data: Metadata
  vlanOnly?: boolean
  onSelect: (kind: 'vlan' | 'subnet', value: string) => void
}) {
  const [kind, setKind] = useState<'vlan' | 'subnet'>('vlan')
  const [open, setOpen] = useState(false)
  const groups = kind === 'vlan'
    ? (data.vlans ?? []).map(item => ({name: item.vlan, value: item.count}))
    : (data.overview?.subnets ?? []).map(item => ({name: item.subnet, value: item.count}))
  const chartGroups = [...groups].sort((a, b) => b.value - a.value || a.name.localeCompare(b.name)).slice(0, 30)
  const max = chartGroups[0]?.value ?? 1
  const columns = Math.max(1, Math.min(6, Math.ceil(Math.sqrt(chartGroups.length))))
  const rows = Math.ceil(chartGroups.length / columns)
  const option: EChartsOption = vlanOnly ? {
    animation: false,
    tooltip: {trigger: 'item', formatter: '{b}'},
    grid: {left: 12, right: 12, top: 12, bottom: 12},
    xAxis: {type: 'value', show: false, min: -0.5, max: columns - 0.5},
    yAxis: {type: 'value', show: false, min: -0.5, max: rows - 0.5, inverse: true},
    series: [{
      type: 'scatter', label: {show: true, formatter: '{b}', color: '#0f172a'},
      itemStyle: {color: '#93c5fd', opacity: 1},
      symbolSize: value => Math.max(24, Math.sqrt(Number(value[2]) / max) * (columns > 4 ? 34 : 52)),
      data: chartGroups.map((group, index) => ({name: group.name, value: [index % columns, Math.floor(index / columns), group.value]})),
    }],
  } : {
    animation: false, tooltip: {trigger: 'item'},
    series: [{
      type: 'treemap', roam: false, nodeClick: false, breadcrumb: {show: false},
      label: {formatter: '{b}'}, data: chartGroups,
    }],
  }
  return <details className="discovery-distribution" open={open} onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>{vlanOnly ? '哑终端 VLAN 分布' : 'VLAN 与网段设备分布'}</summary>
    {open && <>
      {!vlanOnly && <Segmented aria-label="分布维度" value={kind} onChange={setKind}
        options={[{label: 'VLAN', value: 'vlan'}, {label: '网段', value: 'subnet'}]} />}
      {chartGroups.length ? <>
        <Suspense fallback={<Typography.Text type="secondary">加载分布图</Typography.Text>}>
        <ReactECharts className={vlanOnly?'discovery-distribution-chart discovery-distribution-bubbles':'discovery-distribution-chart'} option={option} notMerge
          onEvents={{click: (point: {name?: string}) => {
            if (point.name && groups.some(group => group.name === point.name)) onSelect(kind, point.name)
          }}} />
        </Suspense>
        <div className="discovery-distribution-keys" aria-label="分组筛选">
          {chartGroups.map(group => <Button key={group.name} size="small" onClick={() => onSelect(kind, group.name)}>
            {kind === 'vlan' ? 'VLAN ' : ''}{group.name} · {group.value}
          </Button>)}
        </div>
      </> : <Typography.Text type="secondary">当前范围内没有可分组的身份</Typography.Text>}
      <Typography.Text type="secondary">按可信作用域身份计数，展示前 30 个分组。{!vlanOnly&&'网段按当前有效观测地址分组。'}</Typography.Text>
    </>}
  </details>
}
