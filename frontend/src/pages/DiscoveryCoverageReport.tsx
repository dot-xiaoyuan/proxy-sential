import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'

export type CoverageReport = components['schemas']['DiscoveryCoverageReport']
type MirrorFunnel = NonNullable<CoverageReport['mirror_funnel']>
type BindingFreshness = components['schemas']['DiscoveryBindingFreshness']
type PendingRow = NonNullable<CoverageReport['ipv4_pending']>[number]
type CoverageRow = { label: string; value: number; color?: 'teal' | 'blue' | 'slate' | 'amber' | 'purple' }

const count = (value: number) => value.toLocaleString('zh-CN')
const percent = (value: number, total: number) => `${(value / total * 100).toFixed(1)}%`

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
  with_profile: '已有画像类型线索',
  without_profile: '暂无画像类型线索',
  withdrawn_confirmation: '曾确认后撤回',
  conflict: '类型证据冲突',
  unlinked: '地址归属待核实',
}

function CoveragePendingTable({ rows }: { rows: PendingRow[] }) {
  const statuses = Object.keys(pendingLabels) as PendingRow['status'][]
  return <table className="coverage-pending-table" aria-label="待确认 IPv4 的画像及协议证据">
    <thead><tr>
      <th scope="col">类型状态</th><th scope="col">仅网络层</th><th scope="col">有 DHCP</th>
      <th scope="col">有设备协议</th><th scope="col">其他</th><th scope="col">合计</th>
    </tr></thead>
    <tbody>{statuses.map(status => {
      const row = rows.find(item => item.status === status)
      const { network_only = 0, dhcp_only = 0, device_protocol = 0, other = 0 } = row ?? {}
      return <tr key={status}>
        <th scope="row">{pendingLabels[status]}</th>
        <td>{count(network_only)}</td><td>{count(dhcp_only)}</td>
        <td>{count(device_protocol)}</td><td>{count(other)}</td>
        <td><strong>{count(network_only + dhcp_only + device_protocol + other)}</strong></td>
      </tr>
    })}</tbody>
  </table>
}

function CoverageProtocolReplay() {
  return <details className="coverage-panel coverage-protocol-replay">
    <summary>设备协议回放明细 · 11 月 23 日 18:54</summary>
    <p className="coverage-footnote">2026/11/23 18:54 的固定 24 小时快照。从 1,062 条回放观测中追查 197 个已关联且有设备协议的待确认 IPv4。</p>
    <CoverageRows total={197} unit="个 IP" rows={[
      { label: '协议响应缺可信 MAC', value: 129, color: 'slate' },
      { label: '已归属，缺规则可用字段', value: 24 },
      { label: '有字段，单条回放未形成类型', value: 42 },
      { label: '曾确认后撤回或类型冲突', value: 2, color: 'amber' },
    ]} />
    <p className="coverage-footnote">缺可信 MAC 的地址中，66 个已有交换机产品线索，1 个已有无线分布式主机产品线索。</p>
  </details>
}

export function DiscoveryCoverageReport({ report }: { report: CoverageReport }) {
  const { typed_ipv4: typed, identity_no_type_ipv4: needsType, no_identity_ipv4: unlinked } = report
  const review = report.ipv4_type_review
  const total = typed !== undefined && needsType !== undefined && unlinked !== undefined
    ? typed + needsType + unlinked : undefined
  const lagMinutes = report.identity_as_of ? Math.round((Date.parse(report.as_of) - Date.parse(report.identity_as_of)) / 60_000) : 0
  const metrics = [
    { label: '有设备观测的 IPv4', value: total ?? report.ipv4, unit: '个地址' },
    { label: '观测到的 /24 分组', value: report.subnet24, unit: '组 IPv4' },
    { label: '已确认硬件类型', value: report.identified, unit: '个发现身份',
      detail: report.identity_total !== undefined ? `窗口内共 ${count(report.identity_total)} 条发现记录` : undefined },
    { label: '已确认的哑终端', value: report.dumb_terminals, unit: '个发现身份', detail: '已包含在确认数中' },
  ]
  const breakdown = [
    { label: '仅网络层 · ARP、NDP 等', value: report.untyped_network_only_ipv4 },
    { label: '有 DHCP · 缺设备协议证据', value: report.untyped_dhcp_only_ipv4 },
    { label: '有设备协议证据', value: report.untyped_application_ipv4 },
    { label: '其他证据', value: report.untyped_other_ipv4 },
  ].flatMap(({ label, value }) => value === undefined ? [] : [{ label, value }])

  return <section className="coverage-content" aria-label="设备发现覆盖报表">
    <div className="coverage-timestamps">
      <span>{report.diagnostic_as_of
        ? `设备观测截至 ${observedTimeTitle(report.diagnostic_as_of)}`
        : `统计时间 ${observedTimeTitle(report.as_of)}`}</span>
      {report.identity_as_of && <span>发现处理水位 {observedTimeTitle(report.identity_as_of)}</span>}
      {lagMinutes > 5 && <span className="coverage-warning">相对统计时间滞后约 {lagMinutes} 分钟</span>}
    </div>
    {report.identity_status === 'timeout' && <p className="coverage-empty" role="status">身份统计读取超时。地址覆盖和镜像配对数据已加载，可刷新重试身份统计。</p>}
    <dl className="coverage-metrics">
      {metrics.map(({ label, value, unit, detail }) => <div className="coverage-metric" key={label}>
        <dt>{label}</dt>{value !== undefined && <dd><strong>{count(value)}</strong> <span>{unit}</span></dd>}
        {detail && <dd className="coverage-metric-detail">{detail}</dd>}
      </div>)}
    </dl>
    {(report.ipv4_binding_freshness || report.ipv6_binding_freshness) &&
      <section className="coverage-panel" aria-labelledby="coverage-freshness-heading">
        <header className="coverage-panel-heading">
          <div><h4 id="coverage-freshness-heading">地址绑定时效</h4><p>按所选窗口内的设备观测地址去重，统计时仍有有效绑定的地址优先计入当前有效。</p></div>
        </header>
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
    {total !== undefined && typed !== undefined && needsType !== undefined && unlinked !== undefined &&
      <div className="coverage-panels">
        <section className="coverage-panel" aria-labelledby="coverage-address-heading">
          <header className="coverage-panel-heading">
            <div><h4 id="coverage-address-heading">观测 IPv4 的硬件类型确认覆盖</h4><p>{count(typed)} / {count(total)} 个有设备观测的 IPv4 对应已确认硬件类型</p></div>
            {total > 0 && <div className="coverage-highlight"><strong>{percent(typed, total)}</strong></div>}
          </header>
          {total > 0 ? <CoverageDonut label="IPv4 地址类型确认构成" total={total} unit="个 IPv4 地址" rows={[
            { label: '已确认硬件类型', value: typed, color: 'teal' },
            { label: '已关联，尚待确认', value: needsType - (review?.withdrawn_confirmation ?? 0) - (review?.conflict ?? 0) },
            ...(review ? [
              { label: '曾确认，现已撤回', value: review.withdrawn_confirmation, color: 'amber' as const },
              { label: '类型证据冲突', value: review.conflict, color: 'purple' as const },
            ] : []),
            { label: '归属待核实', value: unlinked, color: 'slate' },
          ]} /> : <p className="coverage-empty">选定范围内暂无设备侧 IPv4 观测。</p>}
          <p className="coverage-footnote">按所选窗口内的 IPv4 地址去重，包含历史绑定。仅有画像推测的地址归入待确认。{review && <>有 <strong>{count(review.confirmed_inactive)} 个</strong>地址的设备活动线索已到期，仍计入已确认。</>}</p>
        </section>
        <section className="coverage-panel" aria-labelledby="coverage-gap-heading">
          <header className="coverage-panel-heading"><div><h4 id="coverage-gap-heading">类型待确认的证据</h4>
            <p>{report.ipv4_pending
              ? `${count(needsType + unlinked)} 个 IPv4 暂无确认类型，含地址归属待核实。`
              : `分母为 ${count(needsType)} 个已关联设备、类型待确认的 IP`}</p></div></header>
          {report.ipv4_pending ? <>
            <CoveragePendingTable rows={report.ipv4_pending} />
            <p className="coverage-footnote">有 DHCP 一栏只统计窗口内暂无设备协议的地址。</p>
          </> : breakdown.length > 0 && needsType > 0
            ? <CoverageRows total={needsType} unit="个 IP" rows={breakdown}/>
            : <p className="coverage-empty">{needsType === 0 ? '当前没有这类记录。' : '本次统计暂无协议分项。'}</p>}
          {report.revoked_type_ipv4 !== undefined && needsType > 0 && <div className="coverage-evidence-note">
            <p>待确认地址中，<strong>{count(report.revoked_type_ipv4)} 个</strong>关联到撤回状态，包含撤回的候选线索。</p>
            {review && <p>其中 <strong>{count(review.withdrawn_confirmation)} 个</strong>地址关联到曾确认的硬件类型。</p>}
          </div>}
        </section>
      </div>}
    <CoverageProtocolReplay />
    {report.profile_candidate_identities !== undefined && <p className="coverage-footnote">另有 <strong>{count(report.profile_candidate_identities)} 个发现身份</strong>已有画像类型线索，待确认硬件类型。</p>}
    <p className="coverage-footnote">同一设备可能对应多个地址或采集范围。/24 分组按观测地址统计。</p>
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
          { label: '关联到设备且类型已确认', value: funnel.typed_pairs, color: 'teal' },
          { label: '关联到设备，类型待确认', value: funnel.identified_pairs - funnel.typed_pairs },
          { label: '身份待关联', value: funnel.ip_mac_pairs - funnel.identified_pairs, color: 'slate' },
        ]} />
        <dl className="coverage-pair-identities">
          <div><dt>配对关联的发现身份</dt><dd>{count(funnel.trusted_identities)} 个</dd></div>
          {funnel.typed_identities !== undefined && <div><dt>其中类型已确认</dt><dd>{count(funnel.typed_identities)} 个</dd></div>}
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
