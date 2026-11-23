import { useQuery } from '@tanstack/react-query'
import { ArrowRightOutlined, LaptopOutlined, RadarChartOutlined, ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { Button, Segmented, Skeleton } from 'antd'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import { ApiError, isDiscoveryReadPathUnsupported, request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { useSession } from '../shared/api/queries'
import type { ActivityOverview, DeviceInventoryMetadataResponse } from '../shared/api/types'
import { can } from '../shared/auth/permissions'
import { AppLoadingState } from '../shared/ui'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { useUrlState } from '../shared/ui/useUrlState'

const windows = [
  { value: '24h', label: '近 24 小时', discovery: '24h' },
  { value: '7d', label: '近 7 天', discovery: '168h' },
  { value: '30d', label: '近 30 天', discovery: '720h' },
] as const
const windowKeys = windows.map(window => window.value)
const number = new Intl.NumberFormat('zh-CN')
const percent = new Intl.NumberFormat('zh-CN', { style: 'percent', maximumFractionDigits: 1 })
const eventLabels: Record<string, string> = {
  dns: 'DNS', tls: 'TLS', http: 'HTTP', flow: '流记录', connection: '连接', arp: 'ARP', ndp: 'NDP',
  dhcp: 'DHCP', mdns: 'mDNS', ssdp: 'SSDP', snmp: 'SNMP', lldp: 'LLDP',
}

type Discovery = components['schemas']['DiscoveryDeviceMetadata']
type Ranking = { key: string; label: string; count: number; to?: string }

function useReportData<T>(path: string, enabled: boolean) {
  return useQuery({
    queryKey: ['data-report', path],
    queryFn: ({ signal }) => request<T>(path, { signal }),
    enabled,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  })
}

function Metric({ label, value, unit, icon, primary, loading }: {
  label: string; value?: number; unit: string; icon: ReactNode; primary?: boolean; loading: boolean
}) {
  return <div className={primary ? 'data-report-metric data-report-metric-primary' : 'data-report-metric'}>
    <dt>{icon}{label}</dt>
    {value !== undefined && <dd><strong>{number.format(value)}</strong><span>{unit}</span></dd>}
    {value === undefined && loading && <dd aria-hidden="true"><Skeleton.Input size="small" active /></dd>}
  </div>
}

function Panel({ id, title, hint, links, asOf, note, message, busy, loadingLabel, children }: {
  id: string; title: string; hint: string; links: { label: string; to: string }[];
  asOf?: string; note?: string; message?: string; busy: boolean; loadingLabel?: string; children: ReactNode
}) {
  const displayedTime = observedTimeTitle(asOf)
  return <section className={`data-report-panel data-report-${id}`} aria-labelledby={`data-report-${id}-title`} aria-busy={busy}>
    <header className="data-report-panel-head">
      <div><h2 id={`data-report-${id}-title`}>{title}</h2><p>{hint}</p></div>
      <div className="data-report-links">
        {links.map(link => <Link key={link.to} to={link.to}>{link.label}<ArrowRightOutlined aria-hidden="true" /></Link>)}
      </div>
    </header>
    {loadingLabel ? <AppLoadingState label={loadingLabel} rows={3} /> : <>
      {note && <p className="data-report-note" role="status">{note}</p>}
      {message ? <p className="data-report-message" role="status">{message}</p> : children}
    </>}
    {displayedTime && <footer className="data-report-time">统计于 <time dateTime={asOf}>{displayedTime}</time></footer>}
  </section>
}

function RankList({ title, rows, scale, empty }: { title: string; rows: Ranking[]; scale?: number; empty: string }) {
  const top = rows.filter(row => row.label && row.count > 0)
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label, 'zh-CN')).slice(0, 5)
  const maximum = Math.max(scale ?? 0, top[0]?.count ?? 0)
  return <div className="data-report-ranking">
    <h3>{title}</h3>
    {top.length > 0 ? <ol>
      {top.map(row => <li key={row.key}>
        {row.to ? <Link to={row.to}>{row.label}</Link> : <span>{row.label}</span>}
        <progress value={row.count} max={maximum} aria-hidden="true" />
        <strong>{number.format(row.count)}</strong>
      </li>)}
    </ol> : <p className="data-report-message">{empty}</p>}
  </div>
}

function Counts({ values }: { values: { label: string; value?: number; unit?: string; to?: string }[] }) {
  return <dl className="data-report-counts">
    {values.filter(item => item.value !== undefined).map(item => <div key={item.label}>
      <dt>{item.to ? <Link to={item.to}>{item.label}</Link> : item.label}</dt>
      <dd>{number.format(item.value!)}{item.unit && <small>{item.unit}</small>}</dd>
    </div>)}
  </dl>
}

function InventoryFacets({ label, values, filter, url }: { label: string; values?: string[]; filter: string; url: string }) {
  const names = (values ?? []).filter(value => value.trim() && !/^(unknown|未知|未识别|未获取|—|-)$/i.test(value.trim()))
  if (!names.length) return null
  return <div className="data-report-facet">
    <h3>{label}</h3>
    <ul>
      {names.slice(0, 6).map(name => <li key={name}><Link to={`${url}&${filter}=${encodeURIComponent(name)}`}>{name}</Link></li>)}
      {names.length > 6 && <li><Link to={url}>全部 {number.format(names.length)} 项</Link></li>}
    </ul>
  </div>
}

export function DataReportPage() {
  const [requested, setWindow] = useUrlState('window', '24h', windowKeys)
  const period = windows.find(window => window.value === requested) ?? windows[0]
  const { data: session } = useSession()
  const readIdentity = can(session, 'identity:read')
  const readTraffic = can(session, 'dpi:read')
  const activity = useReportData<ActivityOverview>(`/activity/overview?window=${period.value}&view=summary`, readTraffic)
  const inventory = useReportData<DeviceInventoryMetadataResponse>(`/device-inventory/metadata?view=recent&window=${period.value}`, readIdentity)
  const discovery = useReportData<Discovery>(`/discovery/devices/metadata?mode=passive&identity_scope=devices&overview=false&window=${period.discovery}`, readIdentity)
  const traffic = activity.data
  const terminals = inventory.data
  const discovered = discovery.data
  const currentInventory = terminals?.read_model_state
  const inventoryPreparing = currentInventory?.available === false ||
    (inventory.error instanceof ApiError && /"inventory_projection_not_ready"/.test(inventory.error.message))
  const activityNote = traffic?.data_freshness
  const networkUrl = `/activity?section=access&tab=network&window=${period.value}`
  const inventoryUrl = `/devices?tab=terminal&view=recent&window=${period.value}`
  const discoveryUrl = `/devices?tab=discovery&discovery_window=${period.discovery}`
  const coverageUrl = `/devices/coverage?window=${period.discovery}`
  const hardware = discovered?.classification_version === 'passive-hardware/v2'
  const confirmedLabel = hardware ? '已确认硬件类型' : '已识别类型'
  const queries = [
    ...(readIdentity ? [discovery, inventory] : []),
    ...(readTraffic ? [activity] : []),
  ]

  return <main className="page data-report-page">
    <header className="data-report-header">
      <div className="data-report-period">
        <span aria-hidden="true">统计范围</span>
        <Segmented aria-label="统计范围" value={period.value}
          options={windows.map(({ value, label }) => ({ value, label }))} onChange={setWindow} />
      </div>
      <Button icon={<ReloadOutlined />} loading={queries.some(query => query.isFetching)}
        onClick={() => { for (const query of queries) void query.refetch({ cancelRefetch: false }) }}>刷新</Button>
    </header>

    <dl className="data-report-metrics" aria-label="核心数据">
      {readTraffic && <Metric label="标准事件" value={traffic?.event_count} unit="条" icon={<ThunderboltOutlined aria-hidden="true" />} loading={activity.isFetching} />}
      {readIdentity && <>
        <Metric label="近期终端" value={inventoryPreparing ? undefined : terminals?.total} unit="个" icon={<LaptopOutlined aria-hidden="true" />} loading={inventory.isFetching} />
        <Metric label="发现记录" value={discovered?.total} unit="条" icon={<RadarChartOutlined aria-hidden="true" />} primary loading={discovery.isFetching} />
      </>}
    </dl>

    {readIdentity && <div className="data-report-grid data-report-assets">
      <Panel id="discovery" title="发现设备" hint="被动发现 · 按采集范围与身份去重"
        links={[{ label: '发现列表', to: discoveryUrl }, { label: '覆盖报表', to: coverageUrl }]}
        asOf={discovered?.as_of} busy={discovery.isFetching}
        loadingLabel={discovery.isFetching && !discovered ? '正在读取发现统计…' : undefined}
        message={isDiscoveryReadPathUnsupported(discovery.error) ? '当前读取路径暂不支持发现统计。' :
          discovery.isError && !discovered ? '发现统计读取失败。' : undefined}
        note={discovery.isError && discovered ? '刷新失败，保留上次统计。' : undefined}>
        {discovered && <div className="data-report-discovery-body">
          <div className="data-report-discovery-status">
            <h3>识别构成</h3>
            <Counts values={[
              { label: confirmedLabel, value: discovered.identified, to: `${discoveryUrl}&discovery_state=identified` },
              { label: '待核实', value: discovered.candidate, to: `${discoveryUrl}&discovery_state=candidate` },
              { label: '类型冲突', value: discovered.conflict, to: `${discoveryUrl}&discovery_state=conflict` },
              { label: hardware ? '硬件结论已撤销' : '证据过期', value: discovered.expired, to: `${discoveryUrl}&discovery_state=expired` },
            ]} />
            {discovered.total > 0 && <p className="data-report-explainer">
              {confirmedLabel}占发现记录 <strong>{percent.format(discovered.identified / discovered.total)}</strong>
            </p>}
          </div>
          <RankList title={`${confirmedLabel}排行`} scale={discovered.identified}
            empty="当前范围暂无可列出的类型。"
            rows={(discovered.types ?? []).map(row => ({
              key: row.device_type, label: deviceTypeLabel(row.device_type), count: row.count,
              to: `${discoveryUrl}&discovery_state=identified&discovery_type=${encodeURIComponent(row.device_type)}`,
            }))} />
        </div>}
      </Panel>
      <Panel id="inventory" title="终端台账" hint="统计窗口内有观测的台账终端"
        links={[{ label: '终端列表', to: inventoryUrl }]} asOf={inventoryPreparing ? undefined : terminals?.as_of}
        busy={inventory.isFetching} loadingLabel={inventory.isFetching && !terminals ? '正在读取终端统计…' : undefined}
        message={inventoryPreparing ? '终端统计仍在生成。' :
          inventory.isError && !terminals ? '终端统计读取失败。' : undefined}
        note={inventory.isError && terminals ? '刷新失败，保留上次统计。' :
          currentInventory?.status === 'failed' ? '终端数据更新异常，当前展示已有统计。' :
          currentInventory?.complete === false ? '终端数据仍在更新，当前统计可能不完整。' : undefined}>
        {terminals && <div className="data-report-inventory-body">
          <InventoryFacets label="台账品牌" values={terminals.facets?.brands} url={inventoryUrl} filter="brand" />
          <InventoryFacets label="台账操作系统" values={terminals.facets?.os_families} url={inventoryUrl} filter="os_family" />
          {terminals.total === 0 && <p className="data-report-message">当前范围没有终端记录。</p>}
        </div>}
      </Panel>
    </div>}

    {readTraffic && <Panel id="traffic" title="网络访问" hint="按标准事件汇总观测地址和访问对象"
      links={[{ label: '访问分析', to: networkUrl }]} asOf={activityNote?.as_of || traffic?.statistics_as_of}
      busy={activity.isFetching} loadingLabel={activity.isFetching && !traffic ? '正在读取网络访问统计…' : undefined}
      message={activity.isError && !traffic
        ? (activity.error instanceof ApiError && activity.error.status === 504 ? '网络访问统计读取超时，请刷新重试。' : '网络访问统计读取失败，请刷新重试。')
        : undefined}
      note={activity.isError && traffic ? '刷新失败，保留上次统计。' :
        activityNote?.status === 'warming' ? '访问统计正在生成，当前统计可能不完整。' :
        activityNote?.status === 'stale' || activityNote?.status === 'delayed' ? '访问统计有延迟。' :
        activityNote?.partial ? '访问统计仅覆盖部分时间范围。' : undefined}>
      {traffic && <>
        <Counts values={[
          { label: '活跃 IP', value: traffic.active_ip_count, unit: '个' },
          { label: '访问对象', value: traffic.access_object_count, unit: '个' },
        ]} />
        <RankList title="事件类型" scale={traffic.event_count} empty="当前范围没有事件记录。"
          rows={(traffic.event_type_counts ?? []).map(row => ({
            key: row.value, label: eventLabels[row.value] ?? row.value, count: row.count,
          }))} />
      </>}
    </Panel>}
    <p className="data-report-footnote">
      各板块独立统计，事件、IP、台账终端和发现记录分别按各自口径计数。
      {hardware && ' 纯地址线索可在发现列表切换查看。'}
    </p>
  </main>
}
