import { ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Button, Input, Segmented, Tabs, Typography } from 'antd'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ApiError, request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { useSession } from '../shared/api/queries'
import { AppLoadingState } from '../shared/ui'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { CensusPanel } from './CensusPanel'
import { DiscoveryCoverageReport, DiscoveryMirrorCoverage, type CoverageReport } from './DiscoveryCoverageReport'
import { DiscoverySupplementaryPanels } from './DiscoverySupplementaryPanels'
import { TruthReviewPanel } from './TruthReviewPanel'
import { AssetLedgerPanel } from './AssetLedgerPanel'

const windows = [
  { value: '15m', label: '近 15 分钟' },
  { value: '24h', label: '近 24 小时' },
  { value: '168h', label: '近 7 天' },
  { value: '720h', label: '近 30 天' },
] as const
const sections = [
  { key: 'overview', label: '覆盖总览' },
  { key: 'networks', label: '网段与 VLAN' },
  { key: 'mirror', label: '镜像与配对' },
  { key: 'review', label: '人工核实' },
] as const

type Metadata = components['schemas']['DiscoveryDeviceMetadata']
const networkChartLimit = 10

function isLinkLocalSubnet(value: string) {
  return /^fe[89ab][0-9a-f]:/i.test(value)
}

function CoverageNetworks({ data, window }: { data: Metadata; window: string }) {
  const [kind, setKind] = useState<'ipv4' | 'ipv6' | 'vlan'>('ipv4')
  const [search, setSearch] = useState('')
  const groups = kind === 'vlan'
    ? (data.vlans ?? []).map(row => ({ value: row.vlan, count: row.count }))
    : (data.overview?.subnets ?? []).filter(row => row.subnet.includes(':') === (kind === 'ipv6'))
      .map(row => ({ value: row.subnet, count: row.count }))
  const rows = groups.filter(row => row.value.toLowerCase().includes(search.trim().toLowerCase()))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
  const ranked = rows.slice(0, networkChartLimit)
  const remaining = rows.slice(networkChartLimit)
  const max = ranked[0]?.count ?? 0
  const title = kind === 'vlan' ? 'VLAN' : kind === 'ipv6' ? 'IPv6 网段' : 'IPv4 网段'
  const searchLabel = kind === 'vlan' ? '搜索 VLAN' : '搜索网段'
  const detailUrl = (value: string) => `/devices?${new URLSearchParams({
    tab: 'discovery', discovery_window: window, [kind === 'vlan' ? 'discovery_vlan' : 'discovery_subnet']: value,
  })}`
  return <section className="coverage-content" aria-label="网段与 VLAN 分布">
    <div className="coverage-timestamps"><span>发现处理水位 {observedTimeTitle(data.as_of)}</span></div>
    <section className="coverage-panel">
      <header className="coverage-panel-heading">
        <div><h4>{title}分布</h4><p>{kind === 'vlan' ? '按发现记录中的采集 VLAN 分组' : `按有效设备地址的 ${kind === 'ipv4' ? '/24' : '/64'} 前缀分组`}</p></div>
        <Segmented<'ipv4' | 'ipv6' | 'vlan'> aria-label="分布维度" value={kind} onChange={value => { setKind(value); setSearch('') }}
          options={[{ label: 'IPv4', value: 'ipv4' }, { label: 'IPv6', value: 'ipv6' }, { label: 'VLAN', value: 'vlan' }]} />
      </header>
      <Input className="coverage-network-search" aria-label={searchLabel} placeholder={searchLabel}
        prefix={<SearchOutlined aria-hidden="true"/>} value={search} onChange={event => setSearch(event.target.value)} allowClear />
      {ranked.length > 0 ? <>
        <figure className="coverage-network-chart" aria-label={`${title}按发现身份排序`}>
          <figcaption><span>发现身份数</span><span>{remaining.length > 0 ? `前 ${ranked.length} 组 / 共 ${rows.length} 组` : `${ranked.length} 组`}</span></figcaption>
          <ol>
            {ranked.map(row => <li key={row.value}>
              <Link className="coverage-network-bar" aria-label={`查看 ${row.value} 的发现记录`} to={detailUrl(row.value)}>
                <span className="coverage-network-name">{row.value}{kind === 'ipv6' && isLinkLocalSubnet(row.value) && <small>链路本地</small>}</span>
                <progress className="coverage-progress" value={row.count} max={max || 1} aria-hidden="true" />
                <strong>{row.count.toLocaleString('zh-CN')}</strong>
              </Link>
            </li>)}
          </ol>
          <div className="coverage-network-axis" aria-hidden="true"><span>0</span><span>{max.toLocaleString('zh-CN')}</span></div>
        </figure>
        {remaining.length > 0 && <details className="coverage-details">
          <summary>查看其余 {remaining.length} 组</summary>
          <ul className="coverage-network-details">
            {remaining.map(row => <li key={row.value}><Link to={detailUrl(row.value)}>{row.value}</Link><span>{row.count.toLocaleString('zh-CN')} 个发现身份</span></li>)}
          </ul>
        </details>}
      </> : <p className="coverage-empty">{search ? '没有匹配的分组。' : '当前范围暂无可分组的发现身份。'}</p>}
      <p className="coverage-footnote">同一身份可能出现在多个分组。接口最多返回 100 组观测分组。
        {kind === 'ipv6' && ' 链路本地地址用于本地链路通信，图中会汇总不同采集范围内的同一前缀。'}
      </p>
    </section>
  </section>
}

export function DiscoveryCoveragePage() {
  const [params, setParams] = useSearchParams()
  const [censusOpened, setCensusOpened] = useState(false)
  const { data: session } = useSession()
  const assetSite = session?.site_profile === 'passive_assets'
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
    enabled: section === 'networks' || section === 'overview', staleTime: 60_000, retry: false,
  })
  const activeQuery = section === 'networks' ? distribution : coverage
  function changeParam(key: string, value: string) {
    setParams(current => {
      const next = new URLSearchParams(current)
      next.set(key, value)
      return next
    })
  }
  const isFetching = activeQuery.isFetching || (section === 'overview' && distribution.isFetching)
  function refresh() {
    void activeQuery.refetch()
    if (section === 'overview') void distribution.refetch()
  }
  function feedback(label: string, query = activeQuery) {
    if (query.isFetching && !query.data) return <AppLoadingState label={`正在读取${label}…`} rows={4} />
    if (query.error instanceof ApiError && query.error.status === 503 && query.error.message.includes('discovery_report_preparing')) {
      return <p className="coverage-empty" role="status">正在生成首份统计报表。</p>
    }
    if (query.isError) return <p role="alert" className="coverage-empty">
      {label}{query.error instanceof ApiError && query.error.status === 504 ? '读取超时。' : '读取失败。'}
      {query.data ? '当前显示上次成功读取的数据。' : '可用顶部的刷新按钮重试。'}
    </p>
    const publication = query.data?.publication
    if (publication) return <p className="coverage-timestamps">报表发布于 {observedTimeTitle(publication.published_at)}{publication.delayed && ' · 更新延迟，显示最近一次发布结果'}</p>
    return null
  }

  return <main className="page device-center-page discovery-coverage-page">
    <header className="discovery-report-page-header">
      <div className="discovery-report-title-group">
        {assetSite ? (
          <Typography.Text className="discovery-report-subtitle" type="secondary">
            被动发现覆盖率、设备构成与近 7 天变化
          </Typography.Text>
        ) : (
          <Typography.Title level={3}>设备发现覆盖报表</Typography.Title>
        )}
      </div>
      {section !== 'review' && <div className="discovery-report-page-actions">
        <Segmented
          className="discovery-report-window-switch"
          aria-label="统计时间范围"
          value={window}
          options={windows.map(({ value, label }) => ({ value, label }))}
          onChange={value => changeParam('window', String(value))}
        />
        <Button icon={<ReloadOutlined aria-hidden="true"/>} onClick={refresh} loading={isFetching}>刷新</Button>
      </div>}
    </header>
    <Tabs className="coverage-tabs" aria-busy={section !== 'review' && isFetching} activeKey={section} onChange={value => changeParam('section', value)} items={sections.map(item => ({
      ...item,
      children: item.key === 'overview' ? <>
        {section === 'overview' && feedback('覆盖总览')}
        {coverage.data && (
          <DiscoveryCoverageReport
            report={coverage.data}
            composition={distribution.data}
            compositionFeedback={distribution.isError ? feedback('类型构成', distribution) : undefined}
            windowKey={window}
            onOpenNetworks={() => changeParam('section', 'networks')}
          />
        )}
        {section === 'overview' && <DiscoverySupplementaryPanels window={window} />}
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
      </> : <div className="coverage-review-stack"><AssetLedgerPanel /><TruthReviewPanel /></div>,
    }))} />
  </main>
}
