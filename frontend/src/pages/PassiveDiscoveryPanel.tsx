import { useSearchParams } from 'react-router-dom'
import { DeviceAddress } from '../entities/device/DeviceAddress'
import { DeviceHistoryPanel } from './DeviceHistoryPanel'
import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Modal, Select, Space, Table, Tabs, Tag, Typography } from 'antd'
import { request } from '../shared/api/client'

type Observation = { id:string; ip?:string; mac?:string; name?:string; origin:string; observed_at:string; valid_until:string; withdrawn?:boolean; explanation?:string; confidence?:string; device_type?:string; capabilities?:string[]; port?:string; vlan?:string }
type Device = { id:string; primary_ip?:string; addresses?:string[]; historical_addresses?:{value:string}[]; mac?:string; name?:string; category:string; device_type?:string; capabilities:string[]; protocols:string[]; confidence:string; last_seen:string; current:boolean; observations:Observation[] }
type Page = { items:Device[]|null; total:number }
export type ProtocolSummary = { devices:number; last_observed_at?:string; status:string }
export type DiscoverySummary = { iot_devices?:number; passive_devices?:number; protocols?:Record<string,ProtocolSummary> }

const protocolNames:Record<string,string> = { dhcp:'DHCP', dns_sd:'DNS-SD', ssdp:'SSDP', ws_discovery:'WS-Discovery', arp:'ARP', ndp:'NDP', ieee1905_client:'IEEE 1905' }
const categoryNames:Record<string,string> = { printer:'打印设备', camera:'摄像设备', media:'媒体设备' }
const capabilityNames:Record<string,string> = { printing:'打印', scanning:'扫描', casting:'投屏', network_video:'网络视频', media_rendering:'媒体播放' }
const time = (value?:string) => value ? new Date(value).toLocaleString('zh-CN',{hour12:false}) : ''
const statusText = (value:string) => ({ready:'采集正常',error:'任务异常',lagging:'任务延迟',waiting:'等待任务'}[value] ?? '任务异常')
const confidenceText = (value?:string) => ({confirmed:'明确证据',strong:'较强证据',clue:'初步线索'}[value??'']??'')
const iotEvidenceText = (item:Device) => (item.observations??[]).some(o=>['dns_sd','ssdp','ws_discovery'].includes(o.origin)&&o.confidence==='strong'&&(o.capabilities??[]).some(c=>capabilityNames[c]))?'较强服务证据':'待核实服务线索'

export function ProtocolOverview({summary}:{summary?:DiscoverySummary}) {
 return <div className="passive-protocol-grid" aria-label="被动发现协议概况">{(['dhcp','dns_sd','ssdp'] as const).map(origin=>{
  const item=summary?.protocols?.[origin]
  return <article className="passive-protocol-card" key={origin}><div className="passive-protocol-heading"><strong>{protocolNames[origin]}</strong>{item&&<Tag color={item.status==='ready'?'blue':'orange'}>{statusText(item.status)}</Tag>}</div><div className="passive-protocol-count">{item?.devices??0}<span>台／近 24 小时</span></div>{item?.last_observed_at?<Typography.Text type="secondary">最近观测 {time(item.last_observed_at)}</Typography.Text>:<Typography.Text type="secondary">近 24 小时 0 条观测</Typography.Text>}</article>
 })}</div>
}

export function PassiveDiscoveryPanel({view,addressState='current'}:{view:'iot'|'records';addressState?:'current'|'link'|'history'|'all'}) {
 const [urlParams,setUrlParams]=useSearchParams()
 const selectedID=urlParams.get('device')||''
 const [page,setPage]=useState(1)
 const [category,setCategory]=useState('')
 const [draft,setDraft]=useState('')
 const [search,setSearch]=useState('')
 const [selected,setSelected]=useState<Device>()
 useEffect(()=>{setPage(1);setSelected(undefined)},[view,addressState])
 const selectedQuery=useQuery({queryKey:['discovery-device',selectedID],enabled:!!selectedID&&!selected,queryFn:()=>request<Device>(`/discovery/devices/${encodeURIComponent(selectedID)}`)})
 const detail=selected||selectedQuery.data
 const setDetail=(item?:Device)=>{setSelected(item);setUrlParams(current=>{const next=new URLSearchParams(current);if(item)next.set('device',item.id);else next.delete('device');return next},{replace:true})}

 const params=new URLSearchParams({address_state:addressState,mode:'passive',window:'24h',limit:'20',offset:String((page-1)*20)})
 if(view==='iot') params.set('view','iot')
 if(category) params.set('category',category)
 if(search) params.set('search',search)
 const devices=useQuery({queryKey:['discovery','passive',view,addressState,page,category,search],queryFn:()=>request<Page>(`/discovery/devices?${params}`),refetchInterval:()=>document.visibilityState==='visible'?15000:false})
 const items=devices.data?.items??[]
 const controls=<div className="passive-discovery-controls"><Input.Search aria-label="搜索设备" placeholder="搜索 IP、MAC 或名称" value={draft} onChange={e=>setDraft(e.target.value)} onSearch={value=>{setSearch(value.trim());setPage(1)}} allowClear />{view==='iot'&&<Select aria-label="设备类型" value={category} options={[{value:'',label:'全部类型'},{value:'printer',label:'打印设备'},{value:'camera',label:'摄像设备'},{value:'media',label:'媒体设备'}]} onChange={value=>{setCategory(value);setPage(1)}}/>}<Typography.Text type="secondary">近 24 小时发现 {devices.data?.total??0} 台；记录有效不代表设备在线</Typography.Text></div>
 const columns=[
  {title:'IP / 名称 / MAC',key:'device',width:280,render:(_:unknown,item:Device)=><DeviceAddress ip={item.primary_ip} name={item.name} mac={item.mac} addresses={item.addresses} historicalIP={item.historical_addresses?.[0]?.value}/>},
  {title:'类型与能力',key:'type',render:(_:unknown,item:Device)=><Space wrap>{view==='iot'&&categoryNames[item.category]&&<Tag color="blue">{categoryNames[item.category]}</Tag>}{(item.capabilities??[]).filter(c=>capabilityNames[c]).map(c=><Tag key={c}>{capabilityNames[c]}</Tag>)}{view==='records'&&item.device_type&&!categoryNames[item.category]&&<Typography.Text type="secondary">{item.device_type} 线索</Typography.Text>}</Space>},
  {title:'发现依据',key:'protocols',render:(_:unknown,item:Device)=><Space wrap>{(item.protocols??[]).map(p=><Tag key={p}>{protocolNames[p]??p}</Tag>)}<Typography.Text type="secondary">{view==='iot'?iotEvidenceText(item):confidenceText(item.confidence)}</Typography.Text></Space>},
  {title:'最近观测',key:'seen',render:(_:unknown,item:Device)=><div>{time(item.last_seen)}<Typography.Text type="secondary" className="passive-validity">{item.current?'证据有效':'证据已过期'}</Typography.Text></div>},
  {title:'操作',key:'action',render:(_:unknown,item:Device)=><Button type="link" onClick={()=>setDetail(item)}>查看证据</Button>},
 ]
 return <section className="passive-discovery-panel">{view==='iot'&&<Typography.Paragraph type="secondary">依据设备自身的服务公告归类；仅有 DHCP 地址绑定的手机、电脑不会进入此列表。</Typography.Paragraph>}{controls}{devices.error&&<Alert type="error" title="读取发现设备失败" description={String(devices.error)}/>}<div className="discovery-desktop"><Table size="small" tableLayout="fixed" rowKey="id" columns={columns} dataSource={items} loading={devices.isLoading} pagination={{current:page,total:devices.data?.total??0,pageSize:20,onChange:setPage}} locale={{emptyText:view==='iot'?'近 24 小时没有符合条件的设备':'没有发现记录'}}/></div><div className="discovery-mobile">{items.map(item=><article className="discovery-card" key={item.id}><DeviceAddress ip={item.primary_ip} name={item.name} mac={item.mac} addresses={item.addresses} historicalIP={item.historical_addresses?.[0]?.value}/><div>{(item.protocols??[]).map(p=>protocolNames[p]??p).join(' · ')}</div><Typography.Text type="secondary">{time(item.last_seen)} · {view==='iot'?iotEvidenceText(item):confidenceText(item.confidence)} · {item.current?'证据有效':'证据已过期'}</Typography.Text><Button onClick={()=>setDetail(item)}>查看证据</Button></article>)}<Space wrap><Button disabled={page===1} onClick={()=>setPage(page-1)}>上一页</Button><Button disabled={page*20>=(devices.data?.total??0)} onClick={()=>setPage(page+1)}>下一页</Button></Space></div><Modal title="发现证据" open={!!selectedID||!!selected} footer={null} onCancel={()=>setDetail(undefined)}>{selectedQuery.isError&&<Alert type="error" title="发现设备读取失败"/>}{detail&&<Tabs items={[{key:'overview',label:'概况',children:<><DeviceAddress ip={detail.primary_ip} name={detail.name} mac={detail.mac} addresses={detail.addresses} historicalIP={detail.historical_addresses?.[0]?.value}/><p>{iotEvidenceText(detail)}</p><p>{detail.protocols.map(p=>protocolNames[p]??p).join(' · ')}</p></>},{key:'history',label:'变化历史',children:<DeviceHistoryPanel kind="discovery" id={detail.id}/>},{key:'evidence',label:'发现证据',children:<DeviceHistoryPanel kind="discovery" id={detail.id}/>} ]}/>}</Modal></section>
}
