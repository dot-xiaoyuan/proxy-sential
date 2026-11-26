import { ArrowRightOutlined } from '@ant-design/icons'
import { Button, Segmented } from 'antd'
import type { EChartsOption } from 'echarts'
import { lazy, Suspense, useMemo, useState } from 'react'
import { Link, useInRouterContext, useNavigate } from 'react-router-dom'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'

const ReactECharts = lazy(() => import('echarts-for-react'))

export type BrandTypeRow = { brand: string; device_type: string; count: number }
export type DailyNewRow = { date: string; count: number }
export type SubnetCountRow = { subnet: string; count: number }
export type VlanCountRow = { vlan: string; count: number }
export type PlannedRangeRow = { range: string; device_type: string; visible_ipv4: number }

const countFormat = (value: number) => value.toLocaleString('zh-CN')

// 与覆盖报表保持一致的设备大类归属与中性色阶
const categoryMeta = [
  { key: 'network', label: '网络设备', color: '#0f766e', types: ['access_point', 'router', 'switch', 'firewall', 'gateway', 'wireless_host', 'wireless_controller', 'voice_gateway'] },
  { key: 'dumb', label: '哑终端', color: '#0284c7', types: ['printer', 'scanner', 'camera', 'recorder', 'nvr', 'access_control', 'voip_phone', 'media_player', 'media_device', 'display', 'tv', 'ups', 'pdu', 'environment_monitor'] },
  { key: 'computer', label: '电脑与移动终端', color: '#4f46e5', types: ['laptop', 'desktop', 'mobile', 'tablet', 'server', 'virtual_machine'] },
  { key: 'other', label: '其他', color: '#64748b', types: [] as string[] },
] as const

function categoryKeyFor(deviceType: string): (typeof categoryMeta)[number]['key'] {
  const matched = categoryMeta.find(cat => cat.key !== 'other' && (cat.types as readonly string[]).includes(deviceType))
  return matched ? matched.key : 'other'
}

export function ReportLink({ to, className, children, ariaLabel }: {
  to: string
  className?: string
  children: React.ReactNode
  ariaLabel?: string
}) {
  const inRouter = useInRouterContext()
  if (inRouter) {
    return <Link to={to} className={className} aria-label={ariaLabel}>{children}</Link>
  }
  return <a href={to} className={className} aria-label={ariaLabel}>{children}</a>
}

function BrandEChartWithRouter({ option, validBrands, brandUrl }: {
  option: EChartsOption
  validBrands: Set<string>
  brandUrl: (brand: string) => string
}) {
  const navigate = useNavigate()
  return (
    <ReactECharts
      className="report-echart report-echart-brand"
      option={option}
      notMerge
      onEvents={{
        click: (point: { name?: string }) => {
          if (point.name && validBrands.has(point.name)) {
            void navigate(brandUrl(point.name))
          }
        },
      }}
    />
  )
}

export function BrandTypeChart({ brands, windowKey }: { brands: BrandTypeRow[]; windowKey: string }) {
  const inRouter = useInRouterContext()

  const summary = useMemo(() => {
    const grouped = new Map<string, { total: number; byCategory: Record<string, number>; details: { type: string; count: number }[] }>()
    for (const row of brands) {
      const brand = row.brand.trim()
      if (!brand || row.count <= 0) continue
      const entry = grouped.get(brand) ?? { total: 0, byCategory: {}, details: [] }
      entry.total += row.count
      const cat = categoryKeyFor(row.device_type)
      entry.byCategory[cat] = (entry.byCategory[cat] ?? 0) + row.count
      entry.details.push({ type: deviceTypeLabel(row.device_type), count: row.count })
      grouped.set(brand, entry)
    }
    const top = [...grouped.entries()]
      .sort((a, b) => b[1].total - a[1].total || a[0].localeCompare(b[0], 'zh-CN'))
      .slice(0, 8)
    for (const [, entry] of top) {
      entry.details.sort((a, b) => b.count - a.count || a.type.localeCompare(b.type, 'zh-CN'))
    }
    return top
  }, [brands])

  if (summary.length === 0) return null

  const brandNames = summary.map(([name]) => name)
  const activeCategories = categoryMeta.filter(cat => summary.some(([, item]) => (item.byCategory[cat.key] ?? 0) > 0))
  const detailByBrand = new Map(summary.map(([name, item]) => [name, item]))

  const option: EChartsOption = {
    animation: false,
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: unknown) => {
        const list = Array.isArray(params) ? params : [params]
        const brand = (list[0] as { axisValue?: string } | undefined)?.axisValue
        if (!brand) return ''
        const item = detailByBrand.get(brand)
        if (!item) return brand
        const lines = item.details.slice(0, 6).map(row => `${row.type}：${countFormat(row.count)}`)
        return `<strong>${brand}</strong>（${countFormat(item.total)} 个）<br/>${lines.join('<br/>')}`
      },
    },
    legend: {
      top: 0,
      left: 0,
      itemWidth: 10,
      itemHeight: 10,
      textStyle: { color: '#475569', fontSize: 12 },
    },
    grid: { left: 8, right: 20, top: 32, bottom: 8, containLabel: true },
    xAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#64748b', fontSize: 11 },
      splitLine: { lineStyle: { color: '#f1f5f9' } },
    },
    yAxis: {
      type: 'category',
      inverse: true,
      data: brandNames,
      axisLine: { lineStyle: { color: '#e2e8f0' } },
      axisTick: { show: false },
      axisLabel: { color: '#1e293b', fontSize: 12, width: 96, overflow: 'truncate' },
    },
    series: activeCategories.map(cat => ({
      name: cat.label,
      type: 'bar',
      stack: 'brand',
      barMaxWidth: 18,
      itemStyle: { color: cat.color, borderRadius: [0, 2, 2, 0] },
      data: summary.map(([, item]) => item.byCategory[cat.key] ?? 0),
    })),
  }

  const brandUrl = (brand: string) =>
    `/devices?${new URLSearchParams({ tab: 'discovery', discovery_window: windowKey, discovery_state: 'identified', discovery_search: brand })}`

  return (
    <section className="coverage-panel report-chart-panel" aria-labelledby="report-brand-heading">
      <header className="coverage-panel-heading">
        <div>
          <h4 id="report-brand-heading">已确认设备品牌分布</h4>
          <p>按硬件规则确认的厂商与大类堆叠，点击品牌可查看设备明细</p>
        </div>
        <span className="report-panel-badge">前 {summary.length} 品牌</span>
      </header>
      <Suspense fallback={<p className="coverage-empty">正在加载品牌分布图…</p>}>
        {inRouter ? (
          <BrandEChartWithRouter option={option} validBrands={new Set(brandNames)} brandUrl={brandUrl} />
        ) : (
          <ReactECharts className="report-echart report-echart-brand" option={option} notMerge />
        )}
      </Suspense>
      <ul className="report-chip-links" aria-label="按品牌筛选已确认设备">
        {summary.map(([brand, item]) => (
          <li key={brand}>
            <ReportLink to={brandUrl(brand)} className="report-chip-link">
              <span>{brand}</span>
              <strong>{countFormat(item.total)}</strong>
            </ReportLink>
          </li>
        ))}
      </ul>
    </section>
  )
}

export function DailyNewTrendChart({ days, totalSevenDays }: { days: DailyNewRow[]; totalSevenDays?: number }) {
  const ordered = useMemo(
    () => [...days].filter(row => row.date).sort((a, b) => a.date.localeCompare(b.date)),
    [days],
  )
  if (ordered.length === 0) return null

  const total = totalSevenDays ?? ordered.reduce((sum, row) => sum + row.count, 0)
  const option: EChartsOption = {
    animation: false,
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: unknown) => {
        const list = Array.isArray(params) ? params : [params]
        const first = list[0] as { axisValue?: string; value?: number } | undefined
        if (!first) return ''
        return `${first.axisValue}<br/>新发现身份：<strong>${countFormat(Number(first.value ?? 0))}</strong> 个`
      },
    },
    grid: { left: 10, right: 14, top: 18, bottom: 8, containLabel: true },
    xAxis: {
      type: 'category',
      data: ordered.map(row => row.date.slice(5)),
      axisLine: { lineStyle: { color: '#e2e8f0' } },
      axisTick: { show: false },
      axisLabel: { color: '#475569', fontSize: 11 },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#64748b', fontSize: 11 },
      splitLine: { lineStyle: { color: '#f1f5f9' } },
    },
    series: [
      {
        name: '新发现身份',
        type: 'bar',
        barMaxWidth: 26,
        itemStyle: { color: '#0284c7', borderRadius: [4, 4, 0, 0] },
        data: ordered.map(row => row.count),
      },
      {
        name: '趋势',
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        itemStyle: { color: '#0f766e' },
        lineStyle: { color: '#0f766e', width: 2 },
        data: ordered.map(row => row.count),
      },
    ],
  }

  return (
    <section className="coverage-panel report-chart-panel" aria-labelledby="report-trend-heading">
      <header className="coverage-panel-heading">
        <div>
          <h4 id="report-trend-heading">近 7 天每日新发现</h4>
          <p>按首次纳入发现投影的日期统计新增设备身份</p>
        </div>
        <span className="report-panel-badge">合计 {countFormat(total)} 个</span>
      </header>
      <Suspense fallback={<p className="coverage-empty">正在加载趋势图…</p>}>
        <ReactECharts className="report-echart report-echart-trend" option={option} notMerge />
      </Suspense>
    </section>
  )
}

export function NetworkHotspotsPanel({
  subnets,
  vlans,
  plannedRanges,
  windowKey,
  onOpenNetworks,
}: {
  subnets?: SubnetCountRow[]
  vlans?: VlanCountRow[]
  plannedRanges?: PlannedRangeRow[]
  windowKey: string
  onOpenNetworks?: () => void
}) {
  const ipv4Subnets = useMemo(
    () => (subnets ?? []).filter(row => !row.subnet.includes(':') && row.count > 0)
      .sort((a, b) => b.count - a.count || a.subnet.localeCompare(b.subnet)),
    [subnets],
  )
  const vlanRows = useMemo(
    () => (vlans ?? []).filter(row => row.vlan && row.count > 0)
      .sort((a, b) => b.count - a.count || a.vlan.localeCompare(b.vlan)),
    [vlans],
  )
  const planned = useMemo(
    () => (plannedRanges ?? []).filter(row => row.visible_ipv4 > 0)
      .sort((a, b) => b.visible_ipv4 - a.visible_ipv4 || a.range.localeCompare(b.range)),
    [plannedRanges],
  )

  const modes = [
    ...(ipv4Subnets.length > 0 ? [{ label: 'IPv4 网段', value: 'subnet' as const }] : []),
    ...(vlanRows.length > 0 ? [{ label: 'VLAN', value: 'vlan' as const }] : []),
    ...(planned.length > 0 ? [{ label: '规划网段', value: 'planned' as const }] : []),
  ]
  const [selected, setSelected] = useState<'subnet' | 'vlan' | 'planned'>(modes[0]?.value ?? 'subnet')
  const mode = modes.some(item => item.value === selected) ? selected : (modes[0]?.value ?? 'subnet')

  if (modes.length === 0) return null

  const items = mode === 'subnet'
    ? ipv4Subnets.slice(0, 8).map(row => ({
      key: row.subnet,
      label: row.subnet,
      sublabel: undefined as string | undefined,
      count: row.count,
      unit: '个身份',
      to: `/devices?${new URLSearchParams({ tab: 'discovery', discovery_window: windowKey, discovery_subnet: row.subnet })}`,
    }))
    : mode === 'vlan'
      ? vlanRows.slice(0, 8).map(row => ({
        key: row.vlan,
        label: `VLAN ${row.vlan}`,
        sublabel: undefined as string | undefined,
        count: row.count,
        unit: '个身份',
        to: `/devices?${new URLSearchParams({ tab: 'discovery', discovery_window: windowKey, discovery_vlan: row.vlan })}`,
      }))
      : planned.slice(0, 8).map(row => ({
        key: `${row.range}|${row.device_type}`,
        label: row.range,
        sublabel: row.device_type,
        count: row.visible_ipv4,
        unit: '个地址',
        to: undefined as string | undefined,
      }))

  const max = Math.max(1, ...items.map(item => item.count))

  return (
    <section className="coverage-panel report-hotspots-panel" aria-labelledby="report-hotspots-heading">
      <header className="coverage-panel-heading">
        <div>
          <h4 id="report-hotspots-heading">网段与 VLAN 热点</h4>
          <p>{mode === 'planned' ? '规划设备网段内的镜像可见 IPv4 排行' : '按发现身份数排序，点击可筛选对应列表'}</p>
        </div>
        {modes.length > 1 && (
          <Segmented<'subnet' | 'vlan' | 'planned'>
            size="small"
            aria-label="热点维度"
            value={mode}
            onChange={setSelected}
            options={modes}
          />
        )}
      </header>
      <ol className="report-hotspot-list">
        {items.map(item => (
          <li key={item.key}>
            <div className="report-hotspot-head">
              {item.to ? (
                <ReportLink to={item.to} className="report-hotspot-link">{item.label}</ReportLink>
              ) : (
                <span className="report-hotspot-name">
                  {item.label}
                  {item.sublabel && <small>{item.sublabel}</small>}
                </span>
              )}
              <strong>{countFormat(item.count)} <small>{item.unit}</small></strong>
            </div>
            <progress className="coverage-progress" value={item.count} max={max} aria-hidden="true" />
          </li>
        ))}
      </ol>
      {onOpenNetworks && (
        <footer className="report-hotspots-footer">
          <Button type="link" size="small" onClick={onOpenNetworks} icon={<ArrowRightOutlined />} iconPlacement="end">
            查看全部网段与 VLAN
          </Button>
        </footer>
      )}
    </section>
  )
}
