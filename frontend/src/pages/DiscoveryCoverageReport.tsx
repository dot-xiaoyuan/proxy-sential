import { Typography } from 'antd'
import type { components } from '../shared/api/generated'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { deviceFactSnapshot } from './deviceFactSnapshot'

type Report = components['schemas']['DiscoveryCoverageReport']

const facts = deviceFactSnapshot.rows
const covered = facts.filter(row => row.mirror > 0).length
const typed = facts.filter(row => row.identified > 0).length
const noMirror = facts.length - covered
const withTrafficNoType = covered - typed

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
    <div className="discovery-report-facts"><div><h4>设备事实表对照</h4><Typography.Text type="secondary">冻结核查：{deviceFactSnapshot.observedAt} · 流量窗口 {deviceFactSnapshot.flowWindow}</Typography.Text></div>
      <div className="discovery-report-fact-grid">
        {metric('表内事实范围', facts.length, '原表地址行，范围可能重叠')}
        {metric('镜像覆盖', covered, '范围内有镜像 IP')}
        {metric('已有类型识别', typed, '范围内至少一个可信身份有类型')}
        {metric('有流量待识别', withTrafficNoType, '覆盖范围内没有类型结论')}
        {metric('未见镜像 IP', noMirror, '该次流量窗口')}
      </div>
      <div className="discovery-report-bars"><label>镜像覆盖 <progress value={covered} max={facts.length} /></label><label>至少一个类型结论 <progress value={typed} max={facts.length} /></label></div>
      <p className="discovery-report-boundary">事实表的 46 行含 /16、/24、区间和单 IP，重叠行只按原表行数统计；本区块是核查快照，不随上方实时窗口更新。<a href={deviceFactSnapshot.source} target="_blank" rel="noreferrer">查看逐行依据</a></p>
    </div>
  </section>
}
