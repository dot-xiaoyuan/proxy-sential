import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Input, Segmented, Select, Tabs, Typography } from 'antd'
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { Link, useSearchParams } from 'react-router-dom'
import { ApiError, request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { AppLoadingState } from '../shared/ui'
import { DiscoveryCoverageReport, DiscoveryMirrorCoverage, type CoverageReport } from './DiscoveryCoverageReport'
import { DiscoveryCoverageDiagnostics } from './DiscoveryCoverageDiagnostics'
import { CensusPanel } from './CensusPanel'

const windows = [
  { value: '15m', label: '近 15 分钟' },
  { value: '24h', label: '近 24 小时' },
  { value: '168h', label: '近 7 天' },
  { value: '720h', label: '近 30 天' },
]
const sections = [
  { key: 'overview', label: '覆盖总览' },
  { key: 'networks', label: '网段与 VLAN' },
  { key: 'mirror', label: '镜像与配对' },
  { key: 'history', label: '历史核查' },
] as const

type Metadata = components['schemas']['DiscoveryDeviceMetadata']

function CoverageNetworks({ data, window }: { data: Metadata; window: string }) {
  const [kind, setKind] = useState<'subnet' | 'vlan'>('subnet')
  const [search, setSearch] = useState('')
  const groups = kind === 'subnet'
    ? (data.overview?.subnets ?? []).map(row => ({ value: row.subnet, count: row.count }))
    : (data.vlans ?? []).map(row => ({ value: row.vlan, count: row.count }))
  const rows = groups.filter(row => row.value.toLowerCase().includes(search.trim().toLowerCase()))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
  return <section className="coverage-content" aria-label="网段与 VLAN 分布">
    <div className="coverage-timestamps"><span>发现处理水位 {observedTimeTitle(data.as_of)}</span></div>
    <section className="coverage-panel">
      <header className="coverage-panel-heading">
        <div><h4>有记录的分组</h4><p>{kind === 'subnet' ? '按有效设备地址归入 IPv4 /24、IPv6 /64' : '按发现记录中保留的采集 VLAN 分组'} · 最多显示 100 组</p></div>
        <Segmented<'subnet' | 'vlan'> aria-label="分布维度" value={kind} onChange={value => { setKind(value); setSearch('') }}
          options={[{ label: '网段', value: 'subnet' }, { label: 'VLAN', value: 'vlan' }]} />
      </header>
      <Input className="coverage-network-search" aria-label={kind === 'subnet' ? '搜索网段' : '搜索 VLAN'} placeholder={kind === 'subnet' ? '搜索网段' : '搜索 VLAN'}
        prefix={<SearchOutlined aria-hidden="true"/>} value={search} onChange={event => setSearch(event.target.value)} allowClear />
      {rows.length > 0 ? <table className="coverage-network-table">
        <thead><tr><th scope="col">{kind === 'subnet' ? '网段' : 'VLAN'}</th><th scope="col">发现身份</th><th scope="col">操作</th></tr></thead>
        <tbody>{rows.map(row => <tr key={row.value}>
          <th scope="row">{row.value}</th><td>{row.count.toLocaleString('zh-CN')}</td>
          <td><Link aria-label={`查看 ${row.value} 的发现记录`}
            to={`/devices?${new URLSearchParams({ tab: 'discovery', discovery_window: window, [`discovery_${kind}`]: row.value })}`}>查看记录</Link></td>
        </tr>)}</tbody>
      </table> : <p className="coverage-empty">{search ? '没有匹配的分组。' : '当前范围暂无可分组的发现身份。'}</p>}
      <p className="coverage-footnote">一个身份可能横跨多个地址组。分组数量来自设备观测，实际网络范围以现场配置为准。</p>
    </section>
  </section>
}

export function DiscoveryCoveragePage() {
  const [params, setParams] = useSearchParams()
  const [censusOpened, setCensusOpened] = useState(false)
  const requested = params.get('window') || '24h'
  const window = windows.some(item => item.value === requested) ? requested : '24h'
  const section = sections.find(item => item.key === params.get('section'))?.key ?? 'overview'
  const coverage = useQuery({
    queryKey: ['discovery-coverage-report', window],
    queryFn: ({ signal }) => request<CoverageReport>(`/discovery/devices/coverage-report?window=${window}`, { signal }),
    enabled: section === 'overview' || section === 'mirror', staleTime: 60_000, retry: false,
  })
  const distribution = useQuery({
    queryKey: ['discovery-coverage-distribution', window],
    queryFn: ({ signal }) => request<Metadata>(`/discovery/devices/metadata?mode=passive&identity_scope=devices&window=${window}`, { signal }),
    enabled: section === 'networks', staleTime: 60_000, retry: false,
  })
  const activeQuery = section === 'networks' ? distribution : coverage
  function changeParam(key: string, value: string) {
    setParams(current => {
      const next = new URLSearchParams(current)
      next.set(key, value)
      return next
    })
  }
  function feedback(label: string) {
    if (activeQuery.isFetching && !activeQuery.data) return <AppLoadingState label={`正在读取${label}…`} rows={4} />
    if (activeQuery.isError) return <p role="alert" className="coverage-empty">
      {label}{activeQuery.error instanceof ApiError && activeQuery.error.status === 504 ? '读取超时。' : '读取失败。'}
      {activeQuery.data ? '当前显示上次成功读取的数据。' : '可用顶部的刷新按钮重试。'}
    </p>
    return null
  }

  return <main className="page device-center-page discovery-coverage-page">
    <header className="discovery-report-page-header">
      <Typography.Title level={3}>设备发现覆盖报表</Typography.Title>
      {section !== 'history' && <div className="discovery-report-page-actions">
        <Select aria-label="统计时间范围" value={window} options={windows} onChange={value => changeParam('window', value)} />
        <Button icon={<ReloadOutlined aria-hidden="true"/>} onClick={() => void activeQuery.refetch()} loading={activeQuery.isFetching}>刷新</Button>
      </div>}
    </header>
    <Tabs className="coverage-tabs" aria-busy={section !== 'history' && activeQuery.isFetching} activeKey={section} onChange={value => changeParam('section', value)} items={sections.map(item => ({
      ...item,
      children: item.key === 'overview' ? <>
        {section === 'overview' && feedback('覆盖总览')}
        {coverage.data && <DiscoveryCoverageReport report={coverage.data} />}
      </> : item.key === 'networks' ? <>
        {section === 'networks' && feedback('网段和 VLAN')}
        {distribution.data && <CoverageNetworks data={distribution.data} window={window} />}
      </> : item.key === 'mirror' ? <>
        {section === 'mirror' && feedback('镜像与配对')}
        {coverage.data && <DiscoveryMirrorCoverage funnel={coverage.data.mirror_funnel} />}
        <details className="coverage-census" onToggle={event => { if (event.currentTarget.open) setCensusOpened(true) }}>
          <summary>镜像明细与台账对照</summary>
          {censusOpened && <CensusPanel />}
        </details>
      </> : <section className="coverage-content" aria-label="历史现场核查">
        <p className="coverage-empty">这是 11 月 15 日的核查快照，日期和范围固定。</p>
        <DiscoveryCoverageDiagnostics />
      </section>,
    }))} />
  </main>
}
