import { Typography } from 'antd'
import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'

type Report = components['schemas']['DiscoveryCoverageReport']

export function DiscoveryCoverageReport({ report, loading, error }: { report?: Report; loading: boolean; error: boolean }) {
  const lagMinutes = report ? Math.max(0, Math.round((Date.parse(report.as_of) - Date.parse(report.identity_as_of)) / 60_000)) : 0
  const windowCode = report?.window.replace(/0s$/, '').replace(/0m$/, '')
  const windowLabel = windowCode ? ({'15m':'近 15 分钟','24h':'近 24 小时','168h':'近 7 天','720h':'近 30 天'} as Record<string,string>)[windowCode] || report?.window : ''
  const funnel = report?.mirror_funnel
  const funnelIdentityLag = funnel?.as_of && report ? Math.max(0, Math.round((Date.parse(funnel.as_of) - Date.parse(report.identity_as_of)) / 60_000)) : 0
  const withoutDeviceRecord = funnel ? Math.max(0, funnel.ip_mac_pairs - funnel.identified_pairs) : 0
  const rate = (count: number, total: number) => total > 0 ? `${(count / total * 100).toFixed(1)}%` : ''
  const metric = (label: string, value?: number, detail?: string) => <div className="discovery-report-metric" key={label}><span>{label}</span><strong>{value === undefined ? error ? '读取失败' : '统计中' : value.toLocaleString('zh-CN')}</strong>{detail && <small>{detail}</small>}</div>
  return <section className="discovery-report" aria-label="设备发现覆盖报表">
    <div className="discovery-report-heading"><div><h3>镜像标识与设备发现</h3><Typography.Text type="secondary">{funnel?.as_of ? `${windowLabel} · 镜像数据截至 ${observedTimeTitle(funnel.as_of)} · 绑定状态截至 ${observedTimeTitle(funnel.evaluated_at)}` : loading ? '正在读取现场统计' : '镜像标识统计读取失败'}</Typography.Text></div></div>
    {funnel?.status === 'initializing' && <p className="discovery-report-delay">镜像标识投影正在建立，暂时没有可核对的统计。</p>}
    {funnel && funnel.status !== 'initializing' && <>
      {funnel.status !== 'ready' && <p className="discovery-report-delay">本窗口数据{funnel.status === 'partial' ? '覆盖不完整' : '处理延迟'}；镜像标识投影从 {funnel.available_from ? observedTimeTitle(funnel.available_from) : '当前起点'} 开始，以下数量只代表已处理的范围。</p>}
      {funnelIdentityLag > 5 && <p className="discovery-report-delay">设备发现结果截至 {observedTimeTitle(report!.identity_as_of)}，比镜像数据晚约 {funnelIdentityLag} 分钟；近期新配对可能还在处理中。</p>}
      <div className="discovery-report-group"><h4>地址与 MAC</h4><p>前两项分别数 IPv4、MAC；第三项数 IP–MAC 配对，三项不能相加。配对只计算窗口内出现过且查询时仍有效的记录。</p></div>
      <div className="discovery-report-grid">
        {metric('只有 IPv4', funnel.ipv4_only, '个 IPv4 地址；当前没有有效的 MAC 配对')}
        {metric('只有 MAC', funnel.mac_only, '个 MAC 地址；当前没有有效的 IPv4 配对')}
        {metric('有 IP 和 MAC', funnel.ip_mac_pairs, '种当前有效的 IPv4 与 MAC 配对')}
      </div>
      <div className="discovery-report-group"><h4>设备发现结果</h4><p>“有设备记录”表示当前配对能关联到同接入位置、同 MAC 的发现设备条目，不要求识别出设备类型。配对按 IP–MAC 去重，设备记录按接入位置和 MAC 去重；同一设备有多个 IP 时，配对数会多于设备记录数。</p></div>
      <div className="discovery-report-grid">
        {metric('有设备记录的配对', funnel.identified_pairs, '种 IP–MAC 配对；可对应到设备记录')}
        {metric('没有设备记录的配对', withoutDeviceRecord, '种 IP–MAC 配对；截至发现处理水位尚无记录')}
        {metric('涉及的设备记录', funnel.trusted_identities, '条按接入位置和 MAC 去重的记录；类型不一定已确认')}
        <div className="discovery-report-metric discovery-report-rate" aria-label="有设备记录的组合占比"><span>有设备记录的组合占比</span><strong>{rate(funnel.identified_pairs, funnel.ip_mac_pairs)}</strong><small>{funnel.identified_pairs.toLocaleString('zh-CN')} / {funnel.ip_mac_pairs.toLocaleString('zh-CN')} 种组合</small><progress value={funnel.identified_pairs} max={funnel.ip_mac_pairs || 1}/></div>
      </div>
      <div className="discovery-report-group"><h4>MAC 地址分类</h4><p>按不同 MAC 去重。固定标志位区分本地管理与全局管理；全局管理地址再按 OUI 库分为匹配与未匹配。</p></div>
      <div className="discovery-report-grid">
        <div className="discovery-report-metric" aria-label="MAC OUI 匹配占比"><span>MAC OUI 匹配</span><strong>{rate(funnel.oui_matched, funnel.mac_total)}</strong><small>{funnel.oui_matched.toLocaleString('zh-CN')} / {funnel.mac_total.toLocaleString('zh-CN')} 个不同 MAC</small></div>
        <div className="discovery-report-metric" aria-label="本地管理 MAC 占比"><span>本地管理 MAC</span><strong>{rate(funnel.locally_administered_mac, funnel.mac_total)}</strong><small>{funnel.locally_administered_mac.toLocaleString('zh-CN')} / {funnel.mac_total.toLocaleString('zh-CN')} 个不同 MAC；不能等同随机 MAC</small></div>
        {metric('无 OUI 且非本地管理 MAC', funnel.no_oui_global_mac, '按当前 OUI 库查无匹配的全局管理地址')}
      </div>
      <p className="discovery-report-boundary">随机 MAC 数量目前无法确定。随机生成的地址通常会设置本地管理位，但手工设置和虚拟网卡地址也可以设置这一位；它只说明地址由本地分配，不证明生成方式。OUI 匹配只说明地址前缀登记，不代表设备类型。当前 OUI 库：{funnel.oui_library_version}。</p>
    </>}
    <details className="discovery-report-details"><summary>查看设备观测与类型统计（另一统计口径）</summary>
    <div className="discovery-report-evidence">
    <div className="discovery-report-heading"><div><h3>设备发现观测</h3><Typography.Text type="secondary">{report ? `${windowLabel} · 观测截至 ${observedTimeTitle(report.as_of)} · 类型统计截至 ${observedTimeTitle(report.identity_as_of)}` : loading ? '正在读取现场统计' : '现场统计读取失败'}</Typography.Text></div></div>
    <p className="discovery-report-boundary">此处只统计进入设备发现链的观测；上方镜像标识还包括流量两侧的本地 IPv4，因此两组总数不同。</p>
    <div className="discovery-report-grid">
      {metric('/24 地址分组', report?.subnet24, '窗口内地址按前三段分桶；不代表完整网段清单')}
      {metric('IPv4 地址', report?.ipv4, '窗口内不同地址')}
      {metric('MAC 地址', report?.mac, '窗口内设备侧绑定证据中的不同 MAC')}
      {metric('已确认类型的设备', report?.identified, '按设备归属统计，不等于 IP 地址数')}
      {metric('已确认的哑终端', report?.dumb_terminals, '属于上述设备数中的哑终端品类')}
    </div>
    {report && <p className="discovery-report-boundary">另有 IPv6 地址 {report.ipv6.toLocaleString('zh-CN')} 个；按 MAC 和接入位置统计为 {report.scoped_mac.toLocaleString('zh-CN')} 组，按设备归属统计为 {report.identity_total.toLocaleString('zh-CN')} 个。计数单位不同，不能相加。/24 分组只表示该地址段中至少看到一个 IP，并非完整网段清单。</p>}
    </div>
    {Number.isFinite(lagMinutes) && lagMinutes > 0 && <p className="discovery-report-delay">设备类型统计比地址统计慢约 {lagMinutes} 分钟；近期流量仍可能在处理中。</p>}
    {report?.typed_ipv4 !== undefined && <div className="discovery-report-evidence">
      <div className="discovery-report-heading"><h4>设备类型识别进展：按 IP 统计</h4><Typography.Text type="secondary">设备观测截至 {report.diagnostic_as_of ? observedTimeTitle(report.diagnostic_as_of) : observedTimeTitle(report.as_of)}</Typography.Text></div>
      <div className="discovery-report-evidence-stage">
        {metric('已确认类型的 IP', report.typed_ipv4, '对应的设备已有明确类型；不等于设备台数')}
        {metric('已关联设备，类型待确认的 IP', report.identity_no_type_ipv4, '看到了设备，但证据还不足以确定品类')}
        {metric('暂时无法关联设备的 IP', report.no_identity_ipv4, '有设备观测，缺少可靠的设备侧 MAC 或归属')}
      </div>
      <div className="discovery-report-evidence-breakdown">
        <h4>类型待确认的 IP：目前拿到了什么信息？</h4>
        <div className="discovery-report-evidence-bars">
          <label><span>只看到 ARP 等网络层信息</span><strong>{report.untyped_network_only_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_network_only_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
          <label><span>拿到了 DHCP，没看到应用服务</span><strong>{report.untyped_dhcp_only_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_dhcp_only_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
          <label><span>看到了应用或设备公告</span><strong>{report.untyped_application_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_application_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
          <label><span>只有其他零散信息</span><strong>{report.untyped_other_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_other_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
        </div>
        <p className="discovery-report-boundary">上面三组 IP 不重复，合起来就是本窗口看到的 IPv4 地址。下面四组只拆解“已关联设备，类型待确认”的 IP：ARP 通常只能证明地址关系；DHCP 可能只提供系统线索；应用信息也可能是通用软件。要判断是流量缺特征、解析漏字段还是规则没覆盖，仍需逐 IP 查原始证据。只有连接记录、没有设备观测的 IP 不在这里。</p>
      </div>
    </div>}
    </details>
  </section>
}
