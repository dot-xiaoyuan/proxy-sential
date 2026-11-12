import {Tag,Typography} from 'antd'
import {observedTimeTitle} from '../shared/ui/observedTime'
import {evidenceService,groupDiscoveryEvidence,type EvidenceObservation} from './discoveryEvidenceGroups'
const protocols:Record<string,string>={arp:'ARP 地址声明',ndp:'IPv6 邻居发现',dhcp:'DHCP 地址与终端资料',dns_sd:'DNS-SD 服务公告',ssdp:'SSDP 服务公告',ws_discovery:'WS-Discovery 设备公告',sadp:'SADP 设备自报',lldp:'LLDP 链路发现',cdp:'CDP 链路发现',ieee1905_client:'IEEE 1905 客户关联',sip:'SIP 通话',rtsp:'RTSP 视频',snmp:'SNMP 设备响应',bacnet:'BACnet 设备属性',modbus:'Modbus 设备标识'}
const services:Record<string,string>={'_ipp._tcp':'IPP 打印','_ipps._tcp':'IPPS 打印','_printer._tcp':'LPD 打印','_pdl-datastream._tcp':'RAW 打印','_uscan._tcp':'扫描','_uscans._tcp':'加密扫描','_http._tcp':'HTTP 服务','_https._tcp':'HTTPS 服务'}
const states={current:'有效',expired:'已过期',withdrawn:'已撤销',recorded:'记录'}
export function DiscoveryEvidenceSummary({observations}:{observations:EvidenceObservation[]}) {
 const groups=groupDiscoveryEvidence(observations)
 const origins=[...new Set(groups.map(g=>g.origin))]
 const count=groups.reduce((n,g)=>n+g.count,0)
 return <section className="discovery-evidence-summary" aria-label="汇总发现证据">
  <Typography.Title level={5}>发现证据</Typography.Title>
  <Typography.Paragraph type="secondary">本次摘要 {count} 条，按内容归并为 {groups.length} 组。展开协议可查看服务差异、时间和原始引用。</Typography.Paragraph>
  {origins.map(origin=>{
   const rows=groups.filter(g=>g.origin===origin)
   const kinds=[...new Set(rows.map(g=>evidenceService(g.sample)).filter(Boolean))]
   const first=rows.map(g=>g.firstSeen).sort((a,b)=>Date.parse(a)-Date.parse(b))[0],last=rows.map(g=>g.lastSeen).sort((a,b)=>Date.parse(a)-Date.parse(b)).at(-1)
   return <details className="discovery-protocol-evidence" key={origin}>
    <summary><span className="discovery-protocol-heading"><strong>{protocols[origin]??origin}</strong><span>{rows.reduce((n,g)=>n+g.count,0)} 条摘要 · {rows.length} 组内容</span></span><span className="discovery-protocol-overview">{kinds.map(kind=><Tag key={kind}>{services[kind]??kind}</Tag>)}<Typography.Text type="secondary">{first===last?observedTimeTitle(first):`${observedTimeTitle(first)} 至 ${observedTimeTitle(last)}`}</Typography.Text></span></summary>
    <div className="discovery-protocol-records">{rows.map(group=>{
     const o=group.sample,payload=o.evidence?.payload
     const service=evidenceService(o)
     const target=typeof payload?.service_target==='string'?payload.service_target:''
     const instance=typeof payload?.service_instance==='string'?payload.service_instance:''
     const identity=o.origin==='sadp'&&o.model_name?`自报型号 ${o.model_name}`:o.origin==='sip'||o.origin==='rtsp'?(typeof payload?.user_agent==='string'&&payload.user_agent?`${o.origin==='sip'?'话机标识':'客户端标识'} ${payload.user_agent}`:(typeof payload?.server==='string'&&payload.server?`服务端标识 ${payload.server}`:'')):''
     return <article key={group.key} className="discovery-evidence-fact"><div className="discovery-evidence-fact-heading"><strong>{service?services[service]??service:o.explanation||protocols[origin]||origin}</strong><Tag color={group.state==='withdrawn'?'warning':undefined}>{states[group.state]}</Tag>{group.count>1&&<Tag>相同内容 {group.count} 条</Tag>}</div>
      {service&&<Typography.Text className="discovery-identifier">{service}{o.port?` · ${o.port}`:''}</Typography.Text>}
      {service&&o.explanation&&<Typography.Text type="secondary">{o.explanation}</Typography.Text>}
      {identity&&<Typography.Text className="discovery-identifier">{identity}</Typography.Text>}
      {o.origin==='sadp'&&o.rule_version&&<Typography.Text type="secondary">规则 {o.rule_version}</Typography.Text>}
      {(o.ip||target||instance)&&<Typography.Text className="discovery-identifier">{[o.ip,target,instance].filter(Boolean).join(' · ')}</Typography.Text>}
      <Typography.Text type="secondary">{group.firstSeen===group.lastSeen?`观测于 ${observedTimeTitle(group.firstSeen)}`:`首次 ${observedTimeTitle(group.firstSeen)} · 最近 ${observedTimeTitle(group.lastSeen)}`}</Typography.Text>
      <details className="discovery-evidence-references"><summary>原始引用（{group.count}）</summary>{group.records.map(record=><div className="discovery-evidence-reference" key={record.id}><span>{record.event_id||record.evidence?.event_id||record.id}</span>{record.origin==='sadp'&&typeof record.evidence?.payload?.payload_sha256==='string'&&<span>报文 SHA256 {record.evidence.payload.payload_sha256}</span>}<span>{observedTimeTitle(record.observed_at)}</span></div>)}</details>
     </article>
    })}</div>
   </details>
  })}
 </section>
}
