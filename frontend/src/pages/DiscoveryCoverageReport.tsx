import { Typography } from 'antd'
import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'

type Report = components['schemas']['DiscoveryCoverageReport']

export function DiscoveryCoverageReport({ report, loading, error }: { report?: Report; loading: boolean; error: boolean }) {
  const metric = (label: string, value?: number, detail?: string) => <div className="discovery-report-metric" key={label}><span>{label}</span><strong>{value === undefined ? error ? '读取失败' : '统计中' : value.toLocaleString('zh-CN')}</strong>{detail && <small>{detail}</small>}</div>
  return <section className="discovery-report" aria-label="设备发现覆盖报表">
    <div className="discovery-report-heading"><div><h3>现场观测</h3><Typography.Text type="secondary">{report ? `${report.window} 观测窗口 · 地址查询 ${observedTimeTitle(report.as_of)} · 设备发现水位 ${observedTimeTitle(report.identity_as_of)}` : loading ? '正在读取现场统计' : '现场统计读取失败'}</Typography.Text></div></div>
    <div className="discovery-report-grid">
      {metric('/24 观察分组', report?.subnet24, '按地址前三段分组，非校方配置网段')}
      {metric('IPv4 地址', report?.ipv4, '窗口内不同地址')}
      {metric('MAC 地址', report?.mac, '设备侧绑定证据，不跨作用域累加')}
      {metric('IP–MAC 关联', report?.ip_mac_pairs, 'IP、MAC、传感器及 VLAN/VRF 去重')}
      {metric('已确认设备类型', report?.identified, '可信作用域身份')}
      {metric('哑终端类型', report?.dumb_terminals, '已确认类型中的哑终端品类')}
    </div>
    {report && <p className="discovery-report-boundary">另有 IPv6 地址 {report.ipv6.toLocaleString('zh-CN')}、作用域 MAC 身份 {report.scoped_mac.toLocaleString('zh-CN')}；设备身份合计 {report.identity_total.toLocaleString('zh-CN')}。IP、MAC、关联与身份的去重单位不同，不能相加。</p>}
    {report?.typed_ipv4 !== undefined && <div className="discovery-report-evidence">
      <div className="discovery-report-heading"><h4>类型缺口：按 IPv4 地址拆解</h4><Typography.Text type="secondary">设备观测截至 {report.diagnostic_as_of ? observedTimeTitle(report.diagnostic_as_of) : observedTimeTitle(report.as_of)}</Typography.Text></div>
      <div className="discovery-report-evidence-stage">
        {metric('至少一个身份有类型', report.typed_ipv4, '同一 IP 可能先后对应多个设备')}
        {metric('有身份，缺类型结论', report.identity_no_type_ipv4, '以下按可见协议分解')}
        {metric('有观测，缺当前身份', report.no_identity_ipv4, '优先核对同作用域设备侧 MAC')}
      </div>
      <div className="discovery-report-evidence-breakdown">
        <h4>有身份但缺类型的地址：当前可见特征</h4>
        <div className="discovery-report-evidence-bars">
          <label><span>仅 ARP / TTL / NDP</span><strong>{report.untyped_network_only_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_network_only_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
          <label><span>有 DHCP、无应用协议观测</span><strong>{report.untyped_dhcp_only_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_dhcp_only_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
          <label><span>有应用或发现协议</span><strong>{report.untyped_application_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_application_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
          <label><span>其他设备观测</span><strong>{report.untyped_other_ipv4?.toLocaleString('zh-CN')}</strong><progress value={report.untyped_other_ipv4 || 0} max={report.identity_no_type_ipv4 || 1}/></label>
        </div>
        <p className="discovery-report-boundary">这些是互斥的 IP 桶，只说明采集到的协议层次。DHCP 可能仅给操作系统，应用协议可能仅给通用软件；仍需逐 IP 核对设备侧产品字段、规则和归属。镜像里只有连接、尚无设备观测的地址不在本分解中。</p>
      </div>
    </div>}
  </section>
}
