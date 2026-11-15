import { useMemo, useState } from 'react'
import { Input, Select, Typography } from 'antd'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { deviceFactDiagnosis, type FactStage } from './deviceFactDiagnosis'
import { deviceFactLiveSnapshot } from './deviceFactLiveSnapshot'
import { deviceFactSnapshot } from './deviceFactSnapshot'

const stageLabels: Record<FactStage, string> = {
  no_traffic: '当次窗口缺镜像地址',
  flow_no_identity: '有流量，缺设备身份',
  identity_no_type: '有身份，缺类型结论',
  has_type: '至少一个类型结论',
}
const stages: FactStage[] = ['no_traffic', 'flow_no_identity', 'identity_no_type', 'has_type']
const examples = [
  {id:'42',range:'10.161.8.0/24 · 一卡通',seen:'早间 89 个 IP 留有 ARP，1 个有 TTL；广播 UDP/1947 没有产品响应，MAC 为本地管理地址。',meaning:'只能证明地址活动和同段行为，OUI 无法提供品牌，业务用途来自设备事实表。',need:'接入交换机端口与一卡通平台台账；同窗采集设备响应或控制器产品字段。'},
  {id:'39',range:'10.161.64.0/18 · 无线 AP',seen:'早间样本含锐捷 MAC、DHCP Option 138；抽样 CAPWAP 为加密 DTLS，缺可读 WTP 型号。',meaning:'可形成厂商或 AP 行为线索，不能把全部地址按网段用途定型。',need:'核对逐消息 DHCP、正确解码 chaddr；从 AC 获得 AP 清单和管理地址。'},
  {id:'15',range:'10.131.254.0/24 · 交换机',seen:'早间 18 个管理 IP 有 SNMP 产品响应；响应所在 VLAN 4005 缺唯一同作用域设备 MAC。',meaning:'IP 级产品线索存在，物理设备归属条件当时未满足。',need:'交换机管理地址、ARP 与端口台账对齐，保持 IP 线索和确认身份分开。'},
  {id:'6',range:'10.126.1.250 · 监控相关',seen:'早间 HTTP nginx、TLS SNI/证书和 ARP 均已取得。',meaning:'这些字段说明服务组件和连接方向，无法证明监控硬件品牌或型号。',need:'设备侧产品响应、摄像平台台账或可归属的产品自报。'},
]
const stageCount = (stage: FactStage) => deviceFactDiagnosis.filter(row => row.stage === stage).length
const liveById = new Map<string, (typeof deviceFactLiveSnapshot.rows)[number]>(deviceFactLiveSnapshot.rows.map(row => [row.id, row]))
type LiveStage = 'no_observation' | 'no_identity' | 'identity_no_type' | 'has_type'
const liveStageLabels: Record<LiveStage,string> = {
  no_observation:'20:40 缺设备观测',no_identity:'20:40 缺设备身份',
  identity_no_type:'20:40 缺类型结论',has_type:'20:40 已有类型',
}
const liveStages: LiveStage[] = ['no_observation','no_identity','identity_no_type','has_type']
const liveStage = (id:string): LiveStage => {
  const row = liveById.get(id)
  if (!row || row.observedIps === 0) return 'no_observation'
  if (row.typed > 0) return 'has_type'
  if (row.identities > 0) return 'identity_no_type'
  return 'no_identity'
}
const liveCounts = deviceFactLiveSnapshot.rows.reduce((counts,row) => {
  if (row.observedIps === 0) counts.noObservation++
  else if (row.typed > 0) counts.hasType++
  else if (row.identities > 0) counts.identityNoType++
  else counts.noIdentity++
  return counts
}, {noObservation:0,noIdentity:0,identityNoType:0,hasType:0})
const causeGroups: {stage: FactStage; title: string}[] = [
  {stage:'flow_no_identity',title:'流量已出现，身份仍缺'},
  {stage:'identity_no_type',title:'身份已建立，类型仍缺'},
]

export function DiscoveryCoverageDiagnostics() {
  const [stage, setStage] = useState<LiveStage | 'all'>('all')
  const [query, setQuery] = useState('')
  const rows = useMemo(() => deviceFactDiagnosis.filter(row =>
    (stage === 'all' || liveStage(row.id) === stage) &&
    [row.id,row.range,row.kind,row.cause,row.finding].join(' ').toLowerCase().includes(query.trim().toLowerCase()),
  ), [stage, query])
  return <section className="discovery-diagnostics" aria-label="设备事实原因分析">
    <div className="discovery-diagnostics-header">
      <div><h3>缺口定位</h3><Typography.Text type="secondary">设备事实表逐行对照</Typography.Text></div>
      <a href={deviceFactSnapshot.source} target="_blank" rel="noreferrer">原始核查表</a>
    </div>
    <p className="discovery-report-boundary">下列数字按 46 行事实范围统计，/16、/24 和单 IP 互有重叠。范围有类型只表示至少一台形成结论，不能推断该范围内其他设备均已定型。</p>
    <div className="discovery-diagnostics-current">
      <h4>11 月 15 日 20:40 只读复核 · 近 24 小时设备观测</h4>
      <p>查询时间 {observedTimeTitle(deviceFactLiveSnapshot.capturedAt)}；发现处理水位 {observedTimeTitle(deviceFactLiveSnapshot.observationWaterline.replace(' ','T'))}。这是设备观测，不等同镜像流量覆盖。</p>
      <div className="discovery-diagnostics-current-grid">
        <div><strong>{liveCounts.noObservation}</strong><span>范围缺设备观测</span></div>
        <div><strong>{liveCounts.noIdentity}</strong><span>有设备观测，缺身份</span></div>
        <div><strong>{liveCounts.identityNoType}</strong><span>有身份，缺类型</span></div>
        <div><strong>{liveCounts.hasType}</strong><span>至少一个类型结论</span></div>
      </div>
    </div>
    <div className="discovery-diagnostics-historical"><h4>09:35 原核查表 · 镜像流量对照</h4><Typography.Text type="secondary">流量窗口 {deviceFactSnapshot.flowWindow}；后续修复改变了部分类型结果</Typography.Text></div>
    <div className="discovery-diagnostics-stages" aria-label="事实范围处理阶段">
      {stages.map(item => <div className="discovery-diagnostics-stage" key={item}>
        <div><strong>{stageCount(item)}</strong><span>{stageLabels[item]}</span></div>
        <progress value={stageCount(item)} max={deviceFactDiagnosis.length}/>
      </div>)}
    </div>
    <div className="discovery-diagnostics-summary">
      <h4>汇报判断</h4>
      <ol>
        <li><strong>采集与身份：</strong>早间 7 行缺镜像地址、12 行有流量却缺身份；当前复核有 {liveCounts.noObservation} 行缺设备观测、{liveCounts.noIdentity} 行有观测却缺身份。这两种输入来源和时间不同，不能把数值差直接解释成采集退化。</li>
        <li><strong>特征与处理链路：</strong>早间 14 行有身份但缺类型；当前为 {liveCounts.identityNoType} 行。DHCP 型号字段修复已使 AP 子段形成类型，但其他范围仍有 ARP/TTL、通用服务或 SNMP 产品归属缺口。逐 IP 见下表。</li>
        <li><strong>识别边界：</strong>一卡通本地管理 MAC、无产品响应的广播及加密 CAPWAP 不会因增加指纹规则而变成型号证据。网段用途只是待核真值，不自动写成设备类型。</li>
      </ol>
    </div>
    <div className="discovery-diagnostics-causes">
      <h4>原因分解</h4>
      <div className="discovery-diagnostics-cause-grid">{causeGroups.map(group => {
        const counts = deviceFactDiagnosis.filter(row => row.stage === group.stage).reduce<Record<string,number>>((result,row) => {
          result[row.cause] = (result[row.cause] || 0) + 1
          return result
        }, {})
        return <div key={group.stage}><h5>{group.title} · {stageCount(group.stage)} 行</h5><ul>{Object.entries(counts).sort((a,b) => b[1]-a[1]).map(([cause,count]) => <li key={cause}><span>{cause}</span><strong>{count}</strong></li>)}</ul></div>
      })}</div>
      <p className="discovery-report-boundary">分类对应冻结核查的主要阻塞点，不代表每行只有一种缺口；按事实范围计数，不能换算为 IP 或设备数。“字段链路”与“产品归属”属于当时可修复项，当前状态须重新对账。</p>
    </div>
    <h4 className="discovery-diagnostics-subtitle">代表性范围：拿到了什么，还差什么</h4>
    <div className="discovery-diagnostics-examples">
      {examples.map(item => <article key={item.range}>
        <h5>{item.range}</h5>
        <p className="discovery-diagnostics-example-current">20:40 设备观测：{liveById.get(item.id)?.observedIps} IP，类型身份 {liveById.get(item.id)?.typed}；仅网络层 {liveById.get(item.id)?.networkOnlyIps} IP，应用/发现协议 {liveById.get(item.id)?.appIps} IP。</p>
        <dl><dt>流量与特征</dt><dd>{item.seen}</dd><dt>证据含义</dt><dd>{item.meaning}</dd><dt>补证路径</dt><dd>{item.need}</dd></dl>
      </article>)}
    </div>
    <div className="discovery-diagnostics-fingerbank">
      <h4>Fingerbank 采购判断</h4>
      <p><strong>购买不能确保这些地址形成设备类型。</strong>官方组合查询把 DHCP、MAC、HTTP/UPnP UA、主机名、mDNS、目标域名、JA3、TCP 指纹等作为可选输入；命中也可能只返回操作系统或低分结果。缺设备侧特征、只有 ARP、加密协议无产品字段或设备归属不清时，订阅不会自动补出事实。</p>
      <p>当前本地包只有 196 条经审核的 Fingerbank DHCP 规则，不能代表完整在线库能力。采购前应固定待定型样本，按同一 IP/MAC/作用域和时间提交实际可用字段，逐项记录“有结果、仅系统线索、多解、无结果”，由设备事实复核新增类型和误判，再计算有效新增类型数与调用成本。</p>
      <p className="discovery-diagnostics-sources">资料：<a href="https://api.fingerbank.org/api_doc/2/combinations/interrogate.html" target="_blank" rel="noreferrer">Fingerbank 官方组合查询说明</a> · <a href="https://www.fingerbank.org/usage/" target="_blank" rel="noreferrer">Fingerbank 使用说明</a></p>
    </div>
    <div className="discovery-diagnostics-detail-heading">
      <div><h4>46 行逐项依据</h4><Typography.Text type="secondary">11 月 15 日早间镜像事实与 20:40 设备观测并列</Typography.Text></div>
      <div className="discovery-diagnostics-filters">
        <Select aria-label="筛选处理阶段" value={stage} onChange={setStage} options={[{value:'all',label:'全部阶段'},...liveStages.map(value => ({value,label:liveStageLabels[value]}))]}/>
        <Input.Search aria-label="搜索 IP 段或原因" placeholder="搜索 IP 段、类别、原因" allowClear value={query} onChange={event => setQuery(event.target.value)}/>
      </div>
    </div>
    <div className="discovery-diagnostics-table-wrap"><table className="discovery-diagnostics-table">
      <thead><tr><th>事实范围 / 表内用途</th><th>09:35 镜像 / 身份 / 类型</th><th>20:40 观测 / 身份 / 类型</th><th>20:40 协议层次</th><th>核查原因与证据</th></tr></thead>
      <tbody>{rows.map(row => {const live = liveById.get(row.id); return <tr key={row.id}>
        <td data-label="事实范围 / 表内用途"><strong>{row.range}</strong>{row.kind !== '未明确' && <small>{row.kind.replace('（类型未知）','')}</small>}</td>
        <td data-label="09:35 镜像 / 身份 / 类型">{row.mirror} / {row.identities} / {row.typed}<small>流量无身份 IP：{row.flowNoIdentity}</small></td>
        <td data-label="20:40 观测 / 身份 / 类型">{live?.observedIps} / {live?.identities} / {live?.typed}<small>观测无身份 IP：{live?.withoutIdentityIps}</small></td>
        <td data-label="20:40 协议层次">仅网络层 {live?.networkOnlyIps}<small>DHCP {live?.dhcpIps} · 应用/发现 {live?.appIps}</small></td>
        <td data-label="核查原因与证据"><strong>09:35 {stageLabels[row.stage]}{row.cause ? ' · '+row.cause : ''}</strong><span>{row.finding}</span><small>{row.evidence}</small></td>
      </tr>})}</tbody>
    </table></div>
    {rows.length === 0 && <p className="discovery-report-boundary">当前筛选没有匹配行。</p>}
  </section>
}
