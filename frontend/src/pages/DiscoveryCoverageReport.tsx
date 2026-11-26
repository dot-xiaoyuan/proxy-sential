import { ArrowRightOutlined } from '@ant-design/icons'
import type { ReactNode } from 'react'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { buildCoverageSummary, type CoverageSummary, type Tone } from './discoveryCoverageSummary'
import {
  BrandTypeChart,
  DailyNewTrendChart,
  NetworkHotspotsPanel,
  ReportLink,
  type BrandTypeRow,
  type DailyNewRow,
  type SubnetCountRow,
  type VlanCountRow,
} from './DiscoveryReportCharts'

export type CoverageReport = components['schemas']['DiscoveryCoverageReport']
export type CoverageComposition = {
  count_unit?: string
  total?: number
  identified?: number
  candidate?: number
  profile_typed?: number
  ip_product_only?: number
  no_type_clue?: number
  conflict?: number
  revoked?: number
  expired?: number
  types?: TypeRow[]
  candidate_types?: TypeRow[]
  ip_product_types?: TypeRow[]
  dumb_terminals?: number
  vlans?: VlanCountRow[]
  overview?: {
    active?: number
    previous_active?: number
    dumb_terminals?: number
    new_seven_days?: number
    new_by_day?: DailyNewRow[]
    brands?: BrandTypeRow[]
    subnets?: SubnetCountRow[]
  }
}
type MirrorFunnel = NonNullable<CoverageReport['mirror_funnel']>
type BindingFreshness = components['schemas']['DiscoveryBindingFreshness']
type PendingRow = NonNullable<CoverageReport['ipv4_pending']>[number]
type CoverageRow = { label: string; value: number; color?: 'teal' | 'blue' | 'slate' | 'amber' | 'purple' }

const count = (value: number) => value.toLocaleString('zh-CN')
const percent = (value: number, total: number) => `${(value / total * 100).toFixed(1)}%`

function normalizeWindowKey(raw: string) {
  return raw.replace(/^(\d+h)0m0s$/, '$1').replace(/^(\d+m)0s$/, '$1')
}

function discoveryListUrl(windowKey: string, extra?: Record<string, string>) {
  const params = new URLSearchParams({ tab: 'discovery', discovery_window: windowKey })
  if (extra) {
    for (const [key, value] of Object.entries(extra)) {
      if (value) params.set(key, value)
    }
  }
  return `/devices?${params}`
}

function CoverageDonut({ label, rows, total, unit }: { label: string; rows: CoverageRow[]; total: number; unit: string }) {
  let offset = 0
  return <div className="coverage-donut">
    <svg className="coverage-donut-chart" viewBox="0 0 144 144" role="img" aria-label={`${label} · ${count(total)} ${unit}`}>
      <circle cx="72" cy="72" r="59" className="coverage-donut-track" />
      {rows.filter(row => row.value > 0 && total > 0).map(row => {
        const size = 100 * row.value / total
        const start = offset
        offset += size
        return <circle key={row.label} cx="72" cy="72" r="59" pathLength="100" transform="rotate(-90 72 72)"
          className={`coverage-donut-arc coverage-chart-${row.color ?? 'blue'}`}
          strokeDasharray={`${size} ${100 - size}`} strokeDashoffset={-start} />
      })}
      <text x="72" y="73" textAnchor="middle" className="coverage-donut-value">{count(total)}</text>
      <text x="72" y="92" textAnchor="middle" className="coverage-donut-unit">{unit}</text>
    </svg>
    <ul className="coverage-chart-legend" aria-label={`${label}明细`}>
      {rows.map(row => <li key={row.label}>
        <span className={`coverage-chart-key coverage-chart-${row.color ?? 'blue'}`} aria-hidden="true" />
        <span>{row.label}</span>
        <strong>{count(row.value)}</strong>
        {total > 0 && <small>{percent(row.value, total)}</small>}
      </li>)}
    </ul>
  </div>
}

function CoverageRows({ rows, total, unit }: { rows: CoverageRow[]; total: number; unit: string }) {
  return <ul className="coverage-breakdown">
    {rows.map(({ label, value, color }) => <li key={label}>
      <div className="coverage-breakdown-label">
        <span>{label}</span>
        <div><strong>{count(value)}</strong> <small>{unit}</small>{total > 0 && <small className="coverage-share">{percent(value, total)}</small>}</div>
      </div>
      {total > 0 && <progress className={`coverage-progress coverage-progress-${color ?? 'blue'}`} aria-label={label} value={value} max={total} />}
    </li>)}
  </ul>
}

function BindingFreshnessRows({ freshness }: { freshness: BindingFreshness }) {
  const { current, expired, uncertain, no_binding: noBinding } = freshness
  return <CoverageRows total={current + expired + uncertain + noBinding} unit="个地址" rows={[
    { label: '当前有效绑定', value: current, color: 'teal' },
    { label: '仅有过期绑定', value: expired },
    { label: '撤销或冲突待核实', value: uncertain, color: 'slate' },
    { label: '窗口内无绑定记录', value: noBinding, color: 'slate' },
  ]} />
}

const pendingLabels: Record<PendingRow['status'], string> = {
  with_profile: '画像已识别类型',
  without_profile: '尚无类型判断',
  withdrawn_confirmation: '曾确认后撤回',
  conflict: '类型证据冲突',
  unlinked: '地址归属待核实',
}

function CoveragePendingTable({ rows }: { rows: PendingRow[] }) {
  const statuses = Object.keys(pendingLabels) as PendingRow['status'][]
  return <table className="coverage-pending-table" aria-label="硬件规则未确认 IPv4 的画像及协议证据">
    <thead><tr>
      <th scope="col">类型状态</th><th scope="col">仅网络层</th><th scope="col">有 DHCP</th>
      <th scope="col">有设备协议</th><th scope="col">其他</th><th scope="col">合计</th>
    </tr></thead>
    <tbody>{statuses.map(status => {
      const row = rows.find(item => item.status === status)
      const { network_only = 0, dhcp_only = 0, device_protocol = 0, other = 0 } = row ?? {}
      return <tr key={status}>
        <th scope="row" data-label="类型状态">{pendingLabels[status]}</th>
        <td data-label="仅网络层">{count(network_only)}</td>
        <td data-label="有 DHCP">{count(dhcp_only)}</td>
        <td data-label="有设备协议">{count(device_protocol)}</td>
        <td data-label="其他">{count(other)}</td>
        <td data-label="合计"><strong>{count(network_only + dhcp_only + device_protocol + other)}</strong></td>
      </tr>
    })}</tbody>
  </table>
}

function PlannedIPv4Panel({ report }: { report: NonNullable<CoverageReport['planned_ipv4']> }) {
  const status = {
    ready: '', partial: '投影仅覆盖部分时间或仍有积压。', delayed: '镜像地址投影更新延迟。',
    initializing: '正在等待镜像地址投影。', configuration_error: '报表范围配置有误。', unavailable: '本次范围统计读取失败。',
  }[report.status]
  return <section className="coverage-panel" aria-labelledby="planned-ipv4-heading">
    <header className="coverage-panel-heading">
      <div><h4 id="planned-ipv4-heading">规划设备网段的可见 IPv4</h4>
        <p>覆盖分母按镜像中出现的 IPv4 去重，重叠范围只计一次。设备类别来自网段规划。</p>
      </div>
      {report.visible_ipv4 !== undefined && <strong>{count(report.visible_ipv4)} 个地址</strong>}
    </header>
    {status && <p className="coverage-footnote" role="status">{status}</p>}
    {report.ranges?.length ? <ul className="coverage-network-details">
      {report.ranges.map(row => <li key={JSON.stringify([row.range, row.device_type])}>
        <span>{row.range} · {row.device_type}</span><strong>{count(row.visible_ipv4)} 个地址</strong>
      </li>)}
    </ul> : null}
    <div className="coverage-timestamps">
      {report.available_from && <span>可用起点 {observedTimeTitle(report.available_from)}</span>}
      {report.as_of && <span>镜像统计截至 {observedTimeTitle(report.as_of)}</span>}
      {report.version && <span title={report.version}>范围版本 {report.version.slice(0, 12)}</span>}
    </div>
  </section>
}

function HardwareTrendPanel({ trend }: { trend: NonNullable<CoverageReport['hardware_trend']> }) {
  const end = Date.parse(trend.as_of)
  const windowMs = trend.window_days * 86_400_000
  const priorIncomplete = !trend.observation_from || Date.parse(trend.observation_from) > end - 2 * windowMs
  const changesIncomplete = !trend.changes_from || Date.parse(trend.changes_from) > end - windowMs
  return <section className="coverage-panel" aria-labelledby="coverage-trend-heading">
      <header className="coverage-panel-heading"><div>
        <h4 id="coverage-trend-heading">近 {trend.window_days} 天硬件身份变化</h4>
        <p>按采集范围和设备身份去重，与上一个等长时段比较。上期出现、本期无记录的身份仍可能在网。</p>
      </div></header>
      <dl className="coverage-metrics">
        {([['首次观测', trend.first_seen], ['已确认类型变更', trend.changed_type],
          ['仅上期有观测', trend.previous_only]] as const).map(([label, value]) =>
          <div className="coverage-metric" key={label}><dt>{label}</dt>
            <dd>{value === undefined ? '覆盖待核查' : <><strong>{count(value)}</strong> 个</>}</dd>
          </div>)}
      </dl>
      {(priorIncomplete || changesIncomplete) && <p className="coverage-warning">窗口覆盖不完整。
        {priorIncomplete && '两期对照超出留存观测范围。'}{changesIncomplete && '变更账本只覆盖部分统计时段。'}</p>}
      <div className="coverage-timestamps">
        {trend.observation_from && <span>最早留存观测 {observedTimeTitle(trend.observation_from)}</span>}
        {trend.changes_from && <span>类型变更账本起点 {observedTimeTitle(trend.changes_from)}</span>}
        {trend.last_success_at && <span>投影最近成功 {observedTimeTitle(trend.last_success_at)}</span>}
      </div>
      <p className="coverage-footnote">数字仅计入已有记录，此前连续覆盖待核查。流量图表明细保留 8 天，小时和天汇总保留 31 天。设备变化取自硬件身份投影和变更账本。</p>
    </section>
}

const windowLabels: Record<string, string> = { '15m': '近 15 分钟', '24h': '近 24 小时', '168h': '近 7 天', '720h': '近 30 天' }

type KpiCardItem = {
  key: string
  label: string
  value: number
  unit: string
  detail?: string
  tone: 'primary' | 'teal' | 'blue' | 'slate'
  to?: string
}

function CoverageKpiStrip({
  report,
  summary,
  composition,
  windowKey,
}: {
  report: CoverageReport
  summary: CoverageSummary
  composition?: CoverageComposition
  windowKey: string
}) {
  const hasCompositionTotal = composition?.total !== undefined
  const crossVlan = (hasCompositionTotal ? composition.count_unit : report.identity_count_unit) === 'cross_vlan_discovery_identity'
  const totalIdentities = hasCompositionTotal ? composition.total : report.identity_total
  const confirmedIdentities = hasCompositionTotal ? composition.identified : report.identified
  const profileIdentities = hasCompositionTotal
    ? (composition.profile_typed ?? (composition.candidate_types ? composition.candidate_types.reduce((sum, row) => sum + row.count, 0) : undefined))
    : report.profile_candidate_identities
  const dumbTerminals = hasCompositionTotal
    ? (composition.overview?.dumb_terminals ?? composition.dumb_terminals)
    : report.dumb_terminals
  const activeNow = composition?.overview?.active
  const prevActive = composition?.overview?.previous_active

  const cards: KpiCardItem[] = []
  if (totalIdentities !== undefined) {
    const parts: string[] = []
    if (confirmedIdentities !== undefined) parts.push(`硬件确认 ${count(confirmedIdentities)}`)
    if (profileIdentities !== undefined && profileIdentities > 0) parts.push(`画像识别 ${count(profileIdentities)}`)
    cards.push({
      key: 'identities',
      label: crossVlan ? '发现身份' : '发现记录',
      value: totalIdentities,
      unit: crossVlan ? '个' : '条',
      detail: parts.length > 0 ? parts.join(' · ') : (crossVlan ? '跨 VLAN 合并去重' : '按采集范围去重'),
      tone: 'primary',
      to: discoveryListUrl(windowKey),
    })
  }
  if (confirmedIdentities !== undefined) {
    const rateText = summary.confirmed !== undefined && summary.device !== undefined && summary.device > 0
      ? `IPv4 硬件确认率 ${percent(summary.confirmed, summary.device)}`
      : '硬件规则明确确认'
    cards.push({
      key: 'confirmed',
      label: '硬件规则确认',
      value: confirmedIdentities,
      unit: '个',
      detail: rateText,
      tone: 'teal',
      to: discoveryListUrl(windowKey, { discovery_state: 'identified' }),
    })
  }
  if (dumbTerminals !== undefined) {
    cards.push({
      key: 'dumb',
      label: '重点哑终端',
      value: dumbTerminals,
      unit: '个',
      detail: '打印、摄像、门禁、话机等',
      tone: 'blue',
      to: discoveryListUrl(windowKey, { discovery_capability: 'dumb' }),
    })
  }
  if (activeNow !== undefined) {
    const delta = prevActive !== undefined ? activeNow - prevActive : undefined
    const deltaText = delta !== undefined
      ? `较昨日同期 ${delta >= 0 ? '+' : ''}${count(delta)}`
      : composition?.overview?.new_seven_days !== undefined
        ? `近 7 天新发现 ${count(composition.overview.new_seven_days)} 个`
        : '15 分钟内有观测'
    cards.push({
      key: 'active',
      label: '近 15 分钟活跃',
      value: activeNow,
      unit: '个',
      detail: deltaText,
      tone: 'slate',
      to: discoveryListUrl('15m'),
    })
  } else if (summary.total !== undefined || summary.device !== undefined) {
    const value = summary.total ?? summary.device!
    cards.push({
      key: 'ipv4',
      label: summary.total !== undefined ? '共发现 IPv4' : '设备层 IPv4',
      value,
      unit: '个',
      detail: summary.total !== undefined && summary.device !== undefined ? `设备层报文 ${count(summary.device)} 个` : '去重 IPv4 地址',
      tone: 'slate',
      to: discoveryListUrl(windowKey),
    })
  }

  if (cards.length === 0) return null

  return (
    <dl className="report-kpi-grid" aria-label="核心资产指标">
      {cards.map(card => {
        const inner = (
          <>
            <dt>
              <span className="report-kpi-label">
                <span className={`report-kpi-dot report-kpi-dot-${card.tone}`} aria-hidden="true" />
                {card.label}
              </span>
              {card.to && <ArrowRightOutlined className="report-kpi-arrow" aria-hidden="true" />}
            </dt>
            <dd>
              <strong>{count(card.value)}</strong>
              <span>{card.unit}</span>
            </dd>
            {card.detail && <p className="report-kpi-detail">{card.detail}</p>}
          </>
        )
        return (
          <div key={card.key} className="report-kpi-card">
            {card.to ? (
              <ReportLink to={card.to} className="report-kpi-link" ariaLabel={`查看${card.label}明细`}>{inner}</ReportLink>
            ) : (
              <div className="report-kpi-static">{inner}</div>
            )}
          </div>
        )
      })}
    </dl>
  )
}

function FunnelBar({ segments, label }: { segments: { value: number; tone: Tone }[]; label: string }) {
  let x = 0
  return <svg className="coverage-funnel-bar" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label={label}>
    <rect className="coverage-funnel-track" x="0" y="0" width="100" height="10" />
    {segments.filter(segment => segment.value > 0).map((segment, index) => {
      const start = x
      x += segment.value
      return <rect key={index} className={`coverage-funnel-fill coverage-chart-${segment.tone}`} x={start} y="0" width={segment.value} height="10" />
    })}
  </svg>
}

function CoverageFunnel({ summary, plannedVisible }: { summary: CoverageSummary; plannedVisible?: number }) {
  const { total, device, confirmed, inferred, judged, pending, mirror, mirrorOnly } = summary
  if (device === undefined) return null
  const base = total ?? device
  const width = (value: number) => base > 0 ? 100 * value / base : 0
  const identified = judged ?? confirmed
  return <section className="coverage-panel coverage-funnel" aria-labelledby="coverage-funnel-heading">
    <header className="coverage-panel-heading">
      <div>
        <h4 id="coverage-funnel-heading">发现与识别</h4>
        <p>按 IPv4 地址去重，每一层都包含在上一层中</p>
      </div>
      {plannedVisible !== undefined && (
        <span className="report-panel-badge">规划网段可见 {count(plannedVisible)} 个 IPv4</span>
      )}
    </header>
    <ol className="coverage-funnel-steps">
      {total !== undefined && <li className="coverage-funnel-step">
        <div className="coverage-funnel-label"><strong>共发现 IPv4 地址</strong><span>流量或设备报文中出现过的地址</span></div>
        <FunnelBar label={`共发现 ${count(total)} 个 IPv4 地址`} segments={[{ value: 100, tone: 'slate' }]} />
        <div className="coverage-funnel-value"><strong>{count(total)}</strong></div>
      </li>}
      {total !== undefined && mirrorOnly !== undefined && mirrorOnly > 0 && <li className="coverage-funnel-drop">
        {count(mirrorOnly)} 个只在流量中出现，没有设备层报文，无法判断类型
      </li>}
      <li className="coverage-funnel-step">
        <div className="coverage-funnel-label"><strong>有设备层报文</strong><span>ARP、DHCP、设备协议等可用于识别的报文</span></div>
        <FunnelBar label={`有设备层报文 ${count(device)} 个`} segments={[{ value: width(device), tone: 'blue' }]} />
        <div className="coverage-funnel-value"><strong>{count(device)}</strong>{total !== undefined && total > 0 && <small>占 {percent(device, total)}</small>}</div>
      </li>
      {pending !== undefined && pending > 0 && <li className="coverage-funnel-drop">
        {count(pending)} 个有设备层报文，尚无类型判断，原因见下方
      </li>}
      {identified !== undefined && confirmed !== undefined && <li className="coverage-funnel-step">
        <div className="coverage-funnel-label">
          <strong>{inferred !== undefined ? '已有类型判断' : '硬件规则确认'}</strong>
          <span>{inferred !== undefined ? '按判断依据分组' : '画像识别统计暂不可用'}</span>
        </div>
        <FunnelBar label={inferred !== undefined
          ? `已有类型判断 ${count(identified)} 个，其中硬件规则确认 ${count(confirmed)} 个，画像识别 ${count(inferred)} 个`
          : `硬件规则确认 ${count(confirmed)} 个`}
          segments={[{ value: width(confirmed), tone: 'teal' }, { value: width(inferred ?? 0), tone: 'blue' }]} />
        <div className="coverage-funnel-value"><strong>{count(identified)}</strong>{device > 0 && <small>占设备层 {percent(identified, device)}</small>}</div>
        <ul className="coverage-funnel-legend">
          <li><span className="coverage-chart-key coverage-chart-teal" aria-hidden="true" />硬件规则确认 <strong>{count(confirmed)}</strong>{device > 0 && <small>{percent(confirmed, device)}</small>}</li>
          {inferred !== undefined && <li><span className="coverage-chart-key coverage-chart-blue" aria-hidden="true" />画像识别 <strong>{count(inferred)}</strong>{device > 0 && <small>{percent(inferred, device)}</small>}</li>}
        </ul>
      </li>}
    </ol>
    {total === undefined && mirror !== undefined && <p className="coverage-footnote">镜像流量另见 {count(mirror)} 个站点网段地址，与上面的地址部分重叠，合并总数暂不可用。</p>}
  </section>
}

const categoryTypes: { key: string; label: string; types: string[] }[] = [
  { key: 'network', label: '网络设备', types: ['access_point', 'router', 'switch', 'firewall', 'gateway', 'wireless_host', 'wireless_controller', 'voice_gateway'] },
  { key: 'dumb', label: '哑终端', types: ['printer', 'scanner', 'camera', 'recorder', 'nvr', 'access_control', 'voip_phone', 'media_player', 'media_device', 'display', 'tv', 'ups', 'pdu', 'environment_monitor'] },
  { key: 'computer', label: '电脑与移动终端', types: ['laptop', 'desktop', 'mobile', 'tablet', 'server', 'virtual_machine'] },
]

type TypeRow = { device_type: string; count: number }

function groupTypes(rows?: TypeRow[]) {
  const items = (rows ?? []).filter(row => row.count > 0)
  const groups = [...categoryTypes, { key: 'other', label: '其他', types: [] as string[] }].map(category => {
    const members = items.filter(row => category.key === 'other'
      ? !categoryTypes.some(known => known.types.includes(row.device_type))
      : category.types.includes(row.device_type))
      .sort((a, b) => b.count - a.count || a.device_type.localeCompare(b.device_type))
    return { ...category, members, total: members.reduce((sum, row) => sum + row.count, 0) }
  }).filter(group => group.total > 0)
    .sort((a, b) => Number(a.key === 'other') - Number(b.key === 'other') || b.total - a.total)
  return { groups, total: groups.reduce((sum, group) => sum + group.total, 0) }
}

function TypeGroups({
  label,
  basis,
  rows,
  tone,
  windowKey,
  drillState,
  footnote,
}: {
  label: string
  basis: string
  rows?: TypeRow[]
  tone: Tone
  windowKey: string
  drillState?: 'identified' | 'profile_typed'
  footnote?: ReactNode
}) {
  const { groups, total } = groupTypes(rows)
  if (total === 0) return null
  const max = Math.max(...groups.map(group => group.total))
  return <section className="coverage-type-block" aria-label={label}>
    <h5>{label}<span>{count(total)} 个设备记录</span></h5>
    <p className="coverage-footnote">{basis}</p>
    <ul className="coverage-type-groups">
      {groups.map(group => <li key={group.key}>
        <div className="coverage-type-group-head"><span>{group.label}</span><strong>{count(group.total)}</strong></div>
        <FunnelBar label={`${label}·${group.label} ${count(group.total)} 个`} segments={[{ value: 100 * group.total / max, tone }]} />
        <p className="coverage-type-chips">
          {group.members.slice(0, 6).map(row => drillState ? (
            <ReportLink
              key={row.device_type}
              to={discoveryListUrl(windowKey, { discovery_state: drillState, discovery_type: row.device_type })}
              className="coverage-type-chip"
            >
              {deviceTypeLabel(row.device_type)} {count(row.count)}
            </ReportLink>
          ) : (
            <span key={row.device_type}>{deviceTypeLabel(row.device_type)} {count(row.count)}</span>
          ))}
          {group.members.length > 6 && <span>其他 {count(group.members.slice(6).reduce((sum, row) => sum + row.count, 0))}</span>}
        </p>
      </li>)}
    </ul>
    {footnote && <p className="coverage-footnote">{footnote}</p>}
  </section>
}

function CoverageComposition({
  composition,
  feedback,
  windowKey,
}: {
  composition?: CoverageComposition
  feedback?: ReactNode
  windowKey: string
}) {
  const hasConfirmed = (composition?.types ?? []).some(row => row.count > 0)
  const hasInferred = (composition?.candidate_types ?? []).some(row => row.count > 0)
  const hasIpProduct = Boolean(composition?.ip_product_types?.length)
  const confirmedTotal = (composition?.types ?? []).reduce((sum, row) => sum + row.count, 0)
  const inferredTotal = (composition?.candidate_types ?? []).reduce((sum, row) => sum + row.count, 0)
  const ipProductTotal = (composition?.ip_product_types ?? []).reduce((sum, row) => sum + row.count, 0)
  const compositionSum = confirmedTotal + inferredTotal + ipProductTotal
  const dumbCount = composition?.dumb_terminals ?? composition?.overview?.dumb_terminals
  const columnCount = Math.max(1, Number(hasConfirmed) + Number(hasInferred) + Number(hasIpProduct))

  return <section className="coverage-panel coverage-composition-panel" aria-labelledby="coverage-types-heading">
    <header className="coverage-panel-heading">
      <div>
        <h4 id="coverage-types-heading">识别出了什么</h4>
        <p>{composition?.count_unit === 'cross_vlan_discovery_identity' ? '同一采集域内，地址一致且类型无冲突的全局 MAC 跨 VLAN 计一次。' : '按设备记录计数，同一设备在不同 VLAN 会分别计数'}</p>
      </div>
      <ReportLink to={discoveryListUrl(windowKey)} className="report-inline-link">发现列表 <ArrowRightOutlined aria-hidden="true" /></ReportLink>
    </header>
    {feedback}
    {composition && compositionSum > 0 && (confirmedTotal > 0 || inferredTotal > 0) && (
      <div className="report-confidence-strip" aria-label="类型依据层级分布">
        <FunnelBar
          label={`硬件规则确认 ${count(confirmedTotal)}，画像识别 ${count(inferredTotal)}${ipProductTotal > 0 ? `，IP 自报 ${count(ipProductTotal)}` : ''}`}
          segments={[
            { value: 100 * confirmedTotal / compositionSum, tone: 'teal' },
            { value: 100 * inferredTotal / compositionSum, tone: 'blue' },
            { value: 100 * ipProductTotal / compositionSum, tone: 'amber' },
          ]}
        />
        <div className="report-confidence-legend">
          {confirmedTotal > 0 && <span><i className="coverage-chart-key coverage-chart-teal" aria-hidden="true" />硬件规则确认 {count(confirmedTotal)}</span>}
          {inferredTotal > 0 && <span><i className="coverage-chart-key coverage-chart-blue" aria-hidden="true" />画像识别 {count(inferredTotal)}</span>}
          {ipProductTotal > 0 && <span><i className="coverage-chart-key coverage-chart-amber" aria-hidden="true" />IP 自报线索 {count(ipProductTotal)}</span>}
        </div>
      </div>
    )}
    {!composition ? (!feedback && <p className="coverage-empty">正在读取类型构成…</p>)
      : !hasConfirmed && !hasInferred && !hasIpProduct ? <p className="coverage-empty">选定范围内暂无类型结论。</p>
        : <>
          {!hasConfirmed && !hasInferred && <p className="coverage-empty">选定范围内暂无类型结论。</p>}
          <div className={`coverage-composition-columns coverage-composition-cols-${columnCount}`}>
            <TypeGroups
              label="硬件规则确认"
              basis="按设备协议、产品或型号等证据匹配硬件规则。"
              rows={composition.types}
              tone="teal"
              windowKey={windowKey}
              drillState="identified"
              footnote={dumbCount !== undefined && dumbCount > 0 ? <>其中哑终端 <strong>{count(dumbCount)}</strong> 个，包括打印机、摄像机、门禁、话机等。</> : undefined}
            />
            <TypeGroups label="画像识别" basis="按 DHCP 指纹等终端画像特征判断设备类型。" rows={composition.candidate_types} tone="blue" windowKey={windowKey} drillState="profile_typed" />
            {hasIpProduct && <section className="coverage-type-block" aria-label="IP 自报的产品类型">
              <h5>IP 自报的产品类型<span>{count(ipProductTotal)} 条线索</span></h5>
              <p className="coverage-footnote">产品或型号来自该 IP 的协议报文，设备归属仍待核实。同一地址可能自报多种类型，各类型分别计数。</p>
              <ul className="coverage-type-groups">{composition.ip_product_types!.map(row =>
                <li className="coverage-type-group-head" key={row.device_type}>
                  <span>{deviceTypeLabel(row.device_type)}</span>
                  <strong>{count(row.count)}</strong>
                </li>)}</ul>
            </section>}
          </div>
        </>}
  </section>
}

function CoverageReasons({ summary }: { summary: CoverageSummary }) {
  const { device, pending, reasons } = summary
  const max = Math.max(1, ...reasons.map(reason => reason.value))
  return <section className="coverage-panel" aria-labelledby="coverage-reasons-heading">
    <header className="coverage-panel-heading"><div>
      <h4 id="coverage-reasons-heading">尚无类型判断的原因</h4>
      {pending !== undefined && pending > 0 && <p>{count(pending)} 个有设备层报文的地址尚无类型判断，按主要原因分组。</p>}
    </div></header>
    {reasons.length === 0 ? <p className="coverage-empty">{device === 0 ? '选定范围内暂无有设备层报文的地址。'
      : pending === 0 ? '有设备层报文的地址均已有类型判断。' : pending === undefined ? '本次报表缺少画像识别明细，无法统计尚无类型判断的地址。' : '本次统计暂无原因分组。'}</p>
      : <ul className="coverage-reasons">
        {reasons.map(reason => <li key={reason.key}>
          <div className="coverage-reason-head">
            <span>{reason.label}</span>
            <strong>{count(reason.value)}</strong>
           {pending !== undefined && pending > 0 && <small>{percent(reason.value, pending)}</small>}
          </div>
          <FunnelBar label={`${reason.label} ${count(reason.value)} 个地址`} segments={[{ value: 100 * reason.value / max, tone: reason.tone }]} />
          <p>{reason.detail}</p>
        </li>)}
      </ul>}
  </section>
}

export function DiscoveryCoverageReport({
  report,
  composition,
  compositionFeedback,
  windowKey: providedWindowKey,
  onOpenNetworks,
}: {
  report: CoverageReport
  composition?: CoverageComposition
  compositionFeedback?: ReactNode
  windowKey?: string
  onOpenNetworks?: () => void
}) {
  const summary = buildCoverageSummary(report)
  const { device, confirmed, inferred, judged, total, deviceOutsideMirror } = summary
  const review = report.ipv4_type_review
  const lagMinutes = report.identity_as_of ? Math.round((Date.parse(report.as_of) - Date.parse(report.identity_as_of)) / 60_000) : 0
  const funnel = report.mirror_funnel
  // Go reports retain zero-valued minutes and seconds in their duration strings.
  const windowKey = providedWindowKey ?? normalizeWindowKey(report.window)
  const windowLabel = windowLabels[normalizeWindowKey(report.window)] ?? '所选时间范围'
  const trendDays = composition?.overview?.new_by_day ?? []
  const brandRows = composition?.overview?.brands ?? []
  const hasDailyTrend = trendDays.length > 0
  const hasBrands = brandRows.length > 0
  const hasHotspots = Boolean(
    composition?.overview?.subnets?.some(row => !row.subnet.includes(':') && row.count > 0)
    || composition?.vlans?.some(row => row.vlan && row.count > 0)
    || report.planned_ipv4?.ranges?.some(row => row.visible_ipv4 > 0),
  )

  return <section className="coverage-content" aria-label="设备发现覆盖报表">
    <div className="coverage-timestamps" aria-label="数据时效">
      {report.identity_as_of ? <span>设备数据截至 {observedTimeTitle(report.identity_as_of)}</span>
        : <span>统计时间 {observedTimeTitle(report.as_of)}</span>}
      {funnel?.as_of && <span>镜像流量截至 {observedTimeTitle(funnel.as_of)}</span>}
      {lagMinutes > 5 && <span className="coverage-warning">发现处理滞后约 {lagMinutes} 分钟，最新的设备变化尚未计入</span>}
      {funnel && funnel.status !== 'ready' && funnel.status !== 'initializing' && <span className="coverage-warning">
        {funnel.status === 'partial' ? '镜像统计窗口覆盖不完整' : '镜像统计更新延迟'}
        {funnel.available_from && `，起点 ${observedTimeTitle(funnel.available_from)}`}</span>}
    </div>
    {report.identity_status === 'timeout' && <p className="coverage-empty" role="status">身份统计读取超时。地址覆盖和镜像配对数据已加载，可刷新重试身份统计。</p>}
    <CoverageKpiStrip report={report} summary={summary} composition={composition} windowKey={windowKey} />
    {device !== undefined && <p className="coverage-lead">
      {windowLabel}{total !== undefined ? <>共发现 <strong>{count(total)}</strong> 个 IPv4 地址，其中 <strong>{count(device)}</strong> 个有设备层报文。</>
        : <>有设备层报文的 IPv4 地址 <strong>{count(device)}</strong> 个。</>}
      {confirmed !== undefined && device > 0 && (judged !== undefined && inferred !== undefined
        ? <>其中 <strong>{count(judged)}</strong> 个已有类型判断，占设备层地址的 {percent(judged, device)}（硬件规则确认 {count(confirmed)} 个，画像识别 {count(inferred)} 个）。</>
        : <>硬件规则已确认 <strong>{count(confirmed)}</strong> 个地址的类型；本次报表缺少画像识别明细。</>)}
    </p>}
    <CoverageFunnel summary={summary} plannedVisible={report.planned_ipv4?.visible_ipv4} />
    <CoverageComposition composition={composition} feedback={compositionFeedback} windowKey={windowKey} />
    {(hasDailyTrend || hasBrands) && (
      <div className={hasDailyTrend && hasBrands ? 'coverage-panels coverage-panels-equal' : 'coverage-panels coverage-panels-single'}>
        {hasDailyTrend && <DailyNewTrendChart days={trendDays} totalSevenDays={composition?.overview?.new_seven_days} />}
        {hasBrands && <BrandTypeChart brands={brandRows} windowKey={windowKey} />}
      </div>
    )}
    <div className={hasHotspots ? 'coverage-panels coverage-panels-equal' : 'coverage-panels coverage-panels-single'}>
      <CoverageReasons summary={summary} />
      {hasHotspots && (
        <NetworkHotspotsPanel
          subnets={composition?.overview?.subnets}
          vlans={composition?.vlans}
          plannedRanges={report.planned_ipv4?.ranges}
          windowKey={windowKey}
          onOpenNetworks={onOpenNetworks}
        />
      )}
    </div>
    {report.hardware_trend && <HardwareTrendPanel trend={report.hardware_trend} />}
    <ul className="coverage-scope-notes" aria-label="统计口径">
      <li>地址数不等于设备台数：同一设备可能使用多个地址，同一地址也可能被不同设备先后使用。</li>
      {deviceOutsideMirror !== undefined && deviceOutsideMirror > 0 && <li>有 {count(deviceOutsideMirror)} 个有设备层报文的地址未出现在本窗口的镜像统计中，已计入共发现总数。</li>}
      {report.ipv6 > 0 && <li>另有 IPv6 地址 {count(report.ipv6)} 个，未计入以上数字。</li>}
      {review && review.confirmed_inactive > 0 && <li>硬件规则已确认的类型中有 {count(review.confirmed_inactive)} 个地址的设备活动线索已到期，仍按已确认计入。</li>}
    </ul>
    <details className="coverage-panel coverage-technical">
      <summary>查看技术明细</summary>
      <div className="coverage-technical-body">
        {report.ipv4_pending && <section aria-labelledby="coverage-matrix-heading">
          <h5 id="coverage-matrix-heading" className="coverage-binding-family">硬件规则未确认的地址明细</h5>
          <CoveragePendingTable rows={report.ipv4_pending} />
          <p className="coverage-footnote">有 DHCP 一栏只统计窗口内暂无设备协议的地址。</p>
        </section>}
        {(report.ipv4_binding_freshness || report.ipv6_binding_freshness) && <section aria-labelledby="coverage-freshness-heading">
          <h5 id="coverage-freshness-heading" className="coverage-binding-family">地址绑定时效</h5>
          <p className="coverage-footnote">按窗口内的设备观测地址去重，统计时仍有有效绑定的地址优先计入当前有效。</p>
          <div className="coverage-panels">
            {report.ipv4_binding_freshness && <section aria-label="IPv4 绑定时效">
              <h5 className="coverage-binding-family">IPv4 · {count(report.ipv4)} 个地址</h5>
              <BindingFreshnessRows freshness={report.ipv4_binding_freshness} />
            </section>}
            {report.ipv6_binding_freshness && <section aria-label="IPv6 绑定时效">
              <h5 className="coverage-binding-family">IPv6 · {count(report.ipv6)} 个地址</h5>
              <BindingFreshnessRows freshness={report.ipv6_binding_freshness} />
            </section>}
          </div>
        </section>}
        {report.planned_ipv4 && <PlannedIPv4Panel report={report.planned_ipv4} />}
      </div>
    </details>
  </section>
}

export function DiscoveryMirrorCoverage({ funnel }: { funnel?: MirrorFunnel }) {
  if (!funnel) return <p className="coverage-empty">本次统计暂无镜像标识数据。</p>
  if (funnel.status === 'initializing') return <p className="coverage-empty">镜像标识投影正在建立。</p>
  const identifiers = [
    { label: 'IPv4', total: funnel.ipv4_total, only: funnel.ipv4_only, other: 'MAC' },
    { label: 'MAC', total: funnel.mac_total, only: funnel.mac_only, other: 'IPv4' },
  ]
  return <section className="coverage-content" aria-label="镜像标识与配对">
    <div className="coverage-timestamps">
      {funnel.as_of && <span>镜像数据截至 {observedTimeTitle(funnel.as_of)}</span>}
      <span>绑定状态截至 {observedTimeTitle(funnel.evaluated_at)}</span>
      {funnel.status !== 'ready' && <span className="coverage-warning">{funnel.status === 'partial' ? '窗口覆盖不完整' : '镜像处理延迟'}
        {funnel.available_from && ` · 覆盖起点 ${observedTimeTitle(funnel.available_from)}`}</span>}
    </div>
    <div className="coverage-panels">
      <section className="coverage-panel" aria-labelledby="coverage-binding-heading">
        <header className="coverage-panel-heading">
          <div><h4 id="coverage-binding-heading">有效 IP–MAC 配对</h4><p>窗口内出现且查询时仍有效</p></div>
        </header>
        <CoverageDonut label="有效配对的身份与类型构成" total={funnel.ip_mac_pairs} unit="种有效配对" rows={[
          { label: '关联到设备且硬件规则已确认类型', value: funnel.typed_pairs, color: 'teal' },
          { label: '已关联，暂无硬件规则确认', value: funnel.identified_pairs - funnel.typed_pairs },
          { label: '身份待关联', value: funnel.ip_mac_pairs - funnel.identified_pairs, color: 'slate' },
        ]} />
        <dl className="coverage-pair-identities">
          <div><dt>配对关联的发现身份</dt><dd>{count(funnel.trusted_identities)} 个</dd></div>
          {funnel.typed_identities !== undefined && <div><dt>其中经硬件规则确认</dt><dd>{count(funnel.typed_identities)} 个</dd></div>}
        </dl>
        <p className="coverage-footnote">同一发现身份可对应多种配对。关联按采集范围和镜像时间对齐。</p>
      </section>
      <section className="coverage-panel" aria-labelledby="coverage-mirror-address-heading">
        <header className="coverage-panel-heading"><div><h4 id="coverage-mirror-address-heading">镜像可见地址</h4><p>窗口内分别对 IPv4、MAC 去重</p></div></header>
        {funnel.ipv4_binding_freshness && <section aria-label="镜像 IPv4 绑定时效">
          <h5 className="coverage-binding-family">IPv4 · {count(funnel.ipv4_total)} 个地址</h5>
          <BindingFreshnessRows freshness={funnel.ipv4_binding_freshness} />
        </section>}
        <ul className="coverage-mirror-chart" aria-label="镜像可见地址的有效配对占比">
          {identifiers.filter(({ label }) => label !== 'IPv4' || !funnel.ipv4_binding_freshness).map(({ label, total, only, other }) => <li key={label}>
            <div className="coverage-mirror-chart-label"><strong>{label}</strong><span>{count(total)} 个</span></div>
            {total > 0 && <progress className="coverage-progress coverage-progress-teal" aria-label={`${label} 有有效配对`} value={total - only} max={total} />}
            <div className="coverage-mirror-chart-caption">
              <span>有有效配对 {count(total - only)} 个{total > 0 && ` · ${percent(total - only, total)}`}</span>
              <span>{count(only)} 个无有效 {other} 配对</span>
            </div>
          </li>)}
        </ul>
        <details className="coverage-details">
          <summary>查看 MAC 管理位和厂商前缀</summary>
          <CoverageRows total={funnel.mac_total} unit="个 MAC" rows={[
            { label: '全局管理 · 匹配 OUI', value: funnel.oui_matched },
            { label: '本地管理', value: funnel.locally_administered_mac },
            { label: '全局管理 · 无 OUI 匹配', value: funnel.no_oui_global_mac, color: 'slate' },
          ]} />
          <p className="coverage-footnote">本地管理位也可由虚拟网卡和手工配置使用。OUI 表示地址前缀登记。{funnel.oui_library_version && `库版本 ${funnel.oui_library_version}。`}</p>
        </details>
      </section>
    </div>
  </section>
}
