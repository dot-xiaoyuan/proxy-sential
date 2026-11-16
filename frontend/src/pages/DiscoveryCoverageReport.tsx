import { Typography } from 'antd'
import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'

type Report = components['schemas']['DiscoveryCoverageReport']

export function DiscoveryCoverageReport({ report, loading, error }: { report?: Report; loading: boolean; error: boolean }) {
  const lagMinutes = report ? Math.max(0, Math.round((Date.parse(report.as_of) - Date.parse(report.identity_as_of)) / 60_000)) : 0
  const windowCode = report?.window.replace(/0s$/, '').replace(/0m$/, '')
  const windowLabel = windowCode ? ({'15m':'近 15 分钟','24h':'近 24 小时','168h':'近 7 天','720h':'近 30 天'} as Record<string,string>)[windowCode] || report?.window : ''
  const pairedExtra = report?.ip_mac_unique_pairs !== undefined && report.ipv4_with_mac !== undefined ? Math.max(0, report.ip_mac_unique_pairs - report.ipv4_with_mac) : 0
  const scopedExtra = report?.ip_mac_unique_pairs !== undefined ? Math.max(0, report.ip_mac_pairs - report.ip_mac_unique_pairs) : 0
  const typedIPRate = report?.typed_ipv4 !== undefined && report.ipv4 > 0 ? `${(report.typed_ipv4 / report.ipv4 * 100).toFixed(1)}%` : ''
  const metric = (label: string, value?: number, detail?: string) => <div className="discovery-report-metric" key={label}><span>{label}</span><strong>{value === undefined ? error ? '读取失败' : '统计中' : value.toLocaleString('zh-CN')}</strong>{detail && <small>{detail}</small>}</div>
  return <section className="discovery-report" aria-label="设备发现覆盖报表">
    <div className="discovery-report-heading"><div><h3>现场观测</h3><Typography.Text type="secondary">{report ? `${windowLabel} · 地址统计截至 ${observedTimeTitle(report.as_of)} · 设备类型统计截至 ${observedTimeTitle(report.identity_as_of)}` : loading ? '正在读取现场统计' : '现场统计读取失败'}</Typography.Text></div></div>
    <div className="discovery-report-grid">
      {metric('/24 地址分组', report?.subnet24, '窗口内地址按前三段分桶；不代表完整网段清单')}
      {metric('IPv4 地址', report?.ipv4, '窗口内不同地址')}
      {metric('MAC 地址', report?.mac, '窗口内设备侧绑定证据中的不同 MAC')}
      {metric('IP–MAC 组合', report?.ip_mac_unique_pairs, 'IPv4 与 MAC 去重；包含窗口内历史换绑')}
      {metric('已确认类型的设备', report?.identified, '按设备归属统计，不等于 IP 地址数')}
      {metric('已确认的哑终端', report?.dumb_terminals, '属于上述设备数中的哑终端品类')}
      {report && typedIPRate && <div className="discovery-report-metric discovery-report-rate" aria-label="已确认类型的 IP 占比"><span>已确认类型的 IP 占全部发现 IPv4</span><strong>{typedIPRate}</strong><small>{report.typed_ipv4?.toLocaleString('zh-CN')} / {report.ipv4.toLocaleString('zh-CN')} 个 IPv4 · 按地址去重，不是设备台数</small><progress value={report.typed_ipv4} max={report.ipv4} aria-label="已确认类型的 IP 在发现的 IPv4 中的占比"/></div>}
    </div>
    {report && report.ip_mac_unique_pairs !== undefined && <div className="discovery-report-reconciliation"><h4>为什么 IP–MAC 数量比 IP 多？</h4><p>先数地址：窗口内有 {report.ipv4.toLocaleString('zh-CN')} 个 IPv4，其中 {report.ipv4_with_mac?.toLocaleString('zh-CN')} 个找到了可信的设备 MAC。</p><p>再数配对：一个 IP 可能先后或在不同位置对应不同 MAC，因此得到 {report.ip_mac_unique_pairs.toLocaleString('zh-CN')} 种 IP–MAC 配对，比有 MAC 的 IP 多 {pairedExtra.toLocaleString('zh-CN')} 种；{report.multi_mac_ipv4?.toLocaleString('zh-CN')} 个 IP 出现过多个 MAC。</p><p>最后数采集记录：同一配对在不同 VLAN 或接入位置重复出现，记录数升到 {report.ip_mac_pairs.toLocaleString('zh-CN')}，比配对数多 {scopedExtra.toLocaleString('zh-CN')}。其中 {report.multi_scope_ip_mac_pairs?.toLocaleString('zh-CN')} 种配对跨多个位置，{report.blank_and_filled_vlan_pairs?.toLocaleString('zh-CN')} 种既有空 VLAN 记录也有明确 VLAN 记录。有效期还没结束的记录有 {report.ip_mac_valid_scoped_pairs?.toLocaleString('zh-CN')} 条。记录数和配对数都不等于当前设备数。</p></div>}
    {report && <p className="discovery-report-boundary">另有 IPv6 地址 {report.ipv6.toLocaleString('zh-CN')} 个；按 MAC 和接入位置统计为 {report.scoped_mac.toLocaleString('zh-CN')} 组，按设备归属统计为 {report.identity_total.toLocaleString('zh-CN')} 个。计数单位不同，不能相加。/24 分组只表示该地址段中至少看到一个 IP，并非完整网段清单。</p>}
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
  </section>
}
