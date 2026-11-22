import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'

export type CoverageReport = components['schemas']['DiscoveryCoverageReport']
type MirrorFunnel = NonNullable<CoverageReport['mirror_funnel']>
type CoverageRow = { label: string; value: number; color?: 'teal' | 'blue' | 'slate' }

const count = (value: number) => value.toLocaleString('zh-CN')
const percent = (value: number, total: number) => `${(value / total * 100).toFixed(1)}%`

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

export function DiscoveryCoverageReport({ report }: { report: CoverageReport }) {
  const { typed_ipv4: typed, identity_no_type_ipv4: needsType, no_identity_ipv4: unlinked } = report
  const total = typed !== undefined && needsType !== undefined && unlinked !== undefined
    ? typed + needsType + unlinked : undefined
  const lagMinutes = Math.round((Date.parse(report.as_of) - Date.parse(report.identity_as_of)) / 60_000)
  const metrics = [
    { label: '有设备观测的 IPv4', value: total ?? report.ipv4, unit: '个地址' },
    { label: '观测到的 /24 分组', value: report.subnet24, unit: '组 IPv4' },
    { label: '已确认硬件类型', value: report.identified, unit: '个发现身份', detail: `共 ${count(report.identity_total)} 个发现身份` },
    { label: '已确认的哑终端', value: report.dumb_terminals, unit: '个发现身份', detail: '已包含在确认数中' },
  ]
  const breakdown = [
    { label: '仅网络层 · ARP、NDP 等', value: report.untyped_network_only_ipv4 },
    { label: '有 DHCP · 缺应用或设备公告', value: report.untyped_dhcp_only_ipv4 },
    { label: '有应用或设备公告', value: report.untyped_application_ipv4 },
    { label: '其他证据', value: report.untyped_other_ipv4 },
  ].flatMap(({ label, value }) => value === undefined ? [] : [{ label, value }])

  return <section className="coverage-content" aria-label="设备发现覆盖报表">
    <div className="coverage-timestamps">
      <span>{report.diagnostic_as_of
        ? `设备观测截至 ${observedTimeTitle(report.diagnostic_as_of)}`
        : `统计时间 ${observedTimeTitle(report.as_of)}`}</span>
      <span>发现处理水位 {observedTimeTitle(report.identity_as_of)}</span>
      {lagMinutes > 5 && <span className="coverage-warning">相对统计时间滞后约 {lagMinutes} 分钟</span>}
    </div>
    <dl className="coverage-metrics">
      {metrics.map(({ label, value, unit, detail }) => <div className="coverage-metric" key={label}>
        <dt>{label}</dt><dd><strong>{count(value)}</strong> <span>{unit}</span></dd>
        {detail && <dd className="coverage-metric-detail">{detail}</dd>}
      </div>)}
    </dl>
    {total !== undefined && typed !== undefined && needsType !== undefined && unlinked !== undefined &&
      <div className="coverage-panels">
        <section className="coverage-panel" aria-labelledby="coverage-address-heading">
          <header className="coverage-panel-heading">
            <div><h4 id="coverage-address-heading">IPv4 识别进度</h4><p>按 {count(total)} 个有设备观测的 IPv4 地址去重</p></div>
            {total > 0 && <div className="coverage-highlight"><strong>{percent(typed, total)}</strong><span>地址已有类型</span></div>}
          </header>
          {total > 0 ? <CoverageRows total={total} unit="个 IP" rows={[
            { label: '已确认设备类型', value: typed, color: 'teal' },
            { label: '已关联设备 · 类型待确认', value: needsType },
            { label: '有设备观测 · 归属待核实', value: unlinked, color: 'slate' },
          ]} /> : <p className="coverage-empty">选定范围内暂无设备侧 IPv4 观测。</p>}
        </section>
        <section className="coverage-panel" aria-labelledby="coverage-gap-heading">
          <header className="coverage-panel-heading"><div><h4 id="coverage-gap-heading">类型待确认的证据</h4>
            <p>分母为 {count(needsType)} 个已关联设备、类型待确认的 IP</p></div></header>
          {breakdown.length > 0 && needsType > 0
            ? <CoverageRows total={needsType} unit="个 IP" rows={breakdown}/>
            : <p className="coverage-empty">{needsType === 0 ? '当前没有这类记录。' : '本次统计暂无协议分项。'}</p>}
        </section>
      </div>}
    <p className="coverage-footnote">一个设备可能使用多个 IP 或出现在多个采集范围。/24 按观测地址分组，网络覆盖率需与镜像配置和台账核对。</p>
  </section>
}

export function DiscoveryMirrorCoverage({ funnel }: { funnel?: MirrorFunnel }) {
  if (!funnel) return <p className="coverage-empty">本次统计暂无镜像标识数据。</p>
  if (funnel.status === 'initializing') return <p className="coverage-empty">镜像标识投影正在建立。</p>
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
          <div className="coverage-highlight"><strong>{count(funnel.ip_mac_pairs)}</strong><span>种配对</span></div>
        </header>
        <CoverageRows total={funnel.ip_mac_pairs} unit="种配对" rows={[
          { label: '已确认设备类型', value: funnel.typed_pairs, color: 'teal' },
          { label: '类型待确认', value: Math.max(0, funnel.ip_mac_pairs - funnel.typed_pairs), color: 'slate' },
        ]} />
        <p className="coverage-footnote">同一设备可对应多种配对，确认率按配对数计算。</p>
      </section>
      <section className="coverage-panel" aria-labelledby="coverage-mirror-address-heading">
        <header className="coverage-panel-heading"><div><h4 id="coverage-mirror-address-heading">镜像可见地址</h4><p>窗口内分别对 IPv4、MAC 去重</p></div></header>
        <dl className="coverage-mirror-rows">
          <div><dt>IPv4</dt><dd>{count(funnel.ipv4_total)} 个</dd><dd>其中 {count(funnel.ipv4_only)} 个无有效 MAC 配对</dd></div>
          <div><dt>MAC</dt><dd>{count(funnel.mac_total)} 个</dd><dd>其中 {count(funnel.mac_only)} 个无有效 IPv4 配对</dd></div>
        </dl>
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
