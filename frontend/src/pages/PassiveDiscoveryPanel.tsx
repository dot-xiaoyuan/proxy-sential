import {
  AppErrorAlert,
  AppServerPagination, useCursorPagePosition, usePaginationMetadata,
  AppTable, AppTableBar } from '../shared/ui'
import { Notice as Alert } from '../shared/ui/Notice'
import { useEffect,
  useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button,
  Collapse,
  Input,
  Modal,
  Select,
  Space,
  Tag,
  Typography,
} from 'antd'
import { useSearchParams } from 'react-router-dom'
import { LoadingOutlined, ReloadOutlined } from '@ant-design/icons'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { DiscoveryDeviceIcon } from '../entities/device/DiscoveryDeviceIcon'
import { BrandLogo } from '../entities/device/BrandLogo'
import { resolveDeviceBrand } from '../entities/device/brandMatcher'
import { DiscoveryEvidenceSummary } from './DiscoveryEvidenceSummary'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'
import { flowBelongsToDevice, serviceBelongsToDevice, signalAddressMatchesDevice } from './discoveryServiceAttribution'
import { discoveryClassificationExplanation, discoveryNameClue } from './discoveryClassificationClues'

type DeviceRecognition = { os_family?: string; device_type?: string; brand?: string; model?: string; confidence?: number; rule_version?: string; source?: string; evidence?: string[]; brand_inference_status?: string; brand_inference_brand?: string; brand_inference_confidence?: number }
type Device = components['schemas']['DiscoveryDevice'] & { recognition?: DeviceRecognition }
type Page = components['schemas']['DiscoveryDevicePage']
type Coverage = components['schemas']['DiscoveryCoverage']
type Statistics = components['schemas']['DiscoveryStatistics']
type Catalogue = components['schemas']['DiscoveryTypeCatalogue']
type History = components['schemas']['DiscoveryHistoryPage']
type ServiceClue = components['schemas']['DiscoveryServiceClue']
type ObservedPort = components['schemas']['DiscoveryObservedPort']
type PassiveSignals = components['schemas']['DiscoveryPassiveSignals']
type PassiveSignal = components['schemas']['DiscoveryPassiveSignal']
const dhcpEvidenceLabels: Record<string,string> = {
  hostname: 'DHCP 主机名',
  dhcp_vendor_class: 'DHCP 厂商类',
  dhcp_requested_options: 'DHCP 请求选项',
  dhcp_client_id_hwtype: 'DHCP 客户端标识类型',
  dhcp_option93_present: 'DHCP 选项 93',
}
function dhcpFieldEvidenceFor(signal?: PassiveSignal) {
  const values: Record<string,string> = {
    hostname: signal?.dhcp_hostname ?? '',
    dhcp_vendor_class: signal?.dhcp_vendor_class ?? '',
    dhcp_requested_options: signal?.dhcp_options ?? '',
    dhcp_client_id_hwtype: signal?.dhcp_client_id_hwtype ?? '',
    dhcp_option93_present: signal?.dhcp_option93_present ? '已观测' : '',
  }
  return Object.entries(signal?.dhcp_field_evidence ?? {})
    .filter(([field, ref]) => values[field] && (ref.event_id || ref.raw_sha256))
    .map(([field, ref]) => ({ field, label: dhcpEvidenceLabels[field] ?? field, value: values[field], ref }))
}
type HandshakeClue = components['schemas']['DiscoveryHandshakeClue']
const protocols: Record<string,string> = { dhcp:'DHCP', dhcpv6:'DHCPv6', dns_sd:'DNS-SD', ssdp:'SSDP', ws_discovery:'WS-Discovery', arp:'ARP', ndp:'NDP', ieee1905_client:'IEEE 1905', ieee1905_client_association:'IEEE 1905', lldp:'LLDP', cdp:'CDP', snmp:'SNMP', ipp:'IPP', onvif:'ONVIF', nbns:'NBNS', llmnr:'LLMNR', bacnet:'BACnet/IP', coap:'CoAP', mqtt:'MQTT', http:'HTTP', tls:'TLS', rtsp:'RTSP', fdb:'交换机 MAC 表', neighbor:'邻居表', active:'探测响应' }
const capabilities: Record<string,string> = { printing:'打印', scanning:'扫描', casting:'投屏', network_video:'网络视频', media_rendering:'媒体播放', voice:'语音通话' }
const states: Record<string,string> = { identified:'证据有效', expired:'证据已过期', conflict:'类型证据冲突', candidate:'发现线索' }
function qualityItem(label:string,value:{known:number;rate:number}|undefined,total:number) {
  if(!value)return null
  return <span className="recognition-quality-item" key={label}><Typography.Text type="secondary">{label}</Typography.Text><Typography.Text strong>{Math.round(value.rate*100)}%</Typography.Text><Typography.Text type="secondary">{value.known}/{total}</Typography.Text></span>
}

function dumbTerminal(item: Device) {
  const caps = item.capabilities ?? []
  if (caps.includes('printing') || caps.includes('scanning')) return '打印/扫描'
  if (caps.includes('casting') || caps.includes('media_rendering') || caps.includes('network_video')) return '媒体播放/投屏'
  if (caps.includes('routing')) return '网关/路由'
  if (caps.includes('voice')) return '语音话机'
  return ''
}

// One discovery key can legitimately split into separate evidence/identity groups.
// Keep the API id for history and use a scoped evidence key only for reconciliation.
function discoveryTableRowKey(item:Device) {
  return JSON.stringify([item.id,item.sensor_id,item.site,item.domain,item.vlan,item.endpoint_id,item.mac,item.observations.map(o=>o.id).sort()])
}

function typeLabel(item:Device, types:Record<string,string>) {
  if(item.classification_status==='conflict')return '类型证据冲突'
  if(item.classification_status==='expired')return item.last_device_type?`${types[item.last_device_type]??deviceTypeLabel(item.last_device_type)} · 历史类型`:''
  const observed=item.device_type
  if(observed)return types[observed]??deviceTypeLabel(observed)
  const recognized=item.recognition?.device_type
  if(recognized&&((item.recognition?.confidence??0)>=.8))return types[recognized]??deviceTypeLabel(recognized)
  return ''
}

function dhcpHintLabel(hint:string) {
  const lower=hint.toLowerCase()
  if(lower.includes('android'))return 'Android 设备'
  if(lower.includes('windows'))return 'Windows 设备'
  if(lower.includes('apple')||lower.includes('ios')||lower.includes('mac'))return 'Apple 设备'
  if(lower.includes('linux'))return 'Linux 设备'
  return hint
}

function secondaryTypeClue(item:Device, types:Record<string,string>, signal?:PassiveSignal) {
  if(dumbTerminal(item))return `服务能力线索 · ${dumbTerminal(item)}`
  if(signal?.device_hint)return `${dhcpHintLabel(signal.device_hint)} · DHCP ${signal.dhcp_historical?'历史线索':'线索'}`
  if(item.recognition?.brand_inference_status==='inferred'&&item.recognition?.brand_inference_brand)return `${item.recognition.brand_inference_brand} · 品牌推断线索`
  const recognized=item.recognition?.device_type
  return recognized&&(item.recognition?.confidence??0)<.8?`${types[recognized]??deviceTypeLabel(recognized)} · 低置信度线索`:''
}

export function PassiveDiscoveryPanel({view}:{view:'iot'|'records'}) {
  const [params,setParams] = useSearchParams()
  const queryClient=useQueryClient()
  const search = params.get('discovery_search') || ''
  const [draft,setDraft] = useState(search)
  const [moreOpen,setMoreOpen] = useState(false)
  const [qualityOpen,setQualityOpen] = useState(false)
  const quality=useQuery({queryKey:['device-recognition-summary'],queryFn:({signal})=>request<components['schemas']['DeviceRecognitionSummary']>('/device-recognition/summary',{signal}),enabled:qualityOpen,staleTime:60_000})
  const [pageSize,setPageSize] = useState(20)
  const filterKey = [view,search,pageSize,...['category','type','protocol','state','domain','vlan','window','capability'].map(k=>params.get(`discovery_${k}`)||'')].join('|')
  const [paging,setPaging] = useState({key:filterKey,page:0})
  useEffect(()=>setPaging(current=>current.key===filterKey?current:{key:filterKey,page:0}),[filterKey])
  const page=paging.key===filterKey?paging.page:0
  const [selected,setSelected] = useState<Device>()
  const [historyPage,setHistoryPage]=useState(1),[historyPageSize,setHistoryPageSize]=useState(20)
  useEffect(()=>setDraft(search),[search])
  useEffect(()=>{const timer=globalThis.setTimeout(()=>{const next=draft.trim();if(next!==search)change('search',next)},300);return()=>globalThis.clearTimeout(timer)},[draft])
  const change = (key:string,value:string) => {
    setParams(current=>{const next=new URLSearchParams(current);if(value)next.set(`discovery_${key}`,value);else next.delete(`discovery_${key}`);if(key==='type')next.delete('discovery_category');return next},{replace:true})
  }
  const shortcut=(type:string,capability='')=>setParams(current=>{const next=new URLSearchParams(current);for(const key of ['type','category','capability'])next.delete(`discovery_${key}`);if(type)next.set('discovery_type',type);if(capability)next.set('discovery_capability',capability);return next},{replace:true})
  const query = new URLSearchParams({mode:'passive',limit:String(pageSize)})
  if(view==='iot')query.set('view','iot')
  if(search)query.set('search',search)
  for(const key of ['category','type','protocol','state','domain','vlan','window','capability']){const value=params.get(`discovery_${key}`);if(value)query.set(key,value)}
  const position=useCursorPagePosition({path:'/discovery/devices/position',query,page:page+1,pageSize})
  if(position.cursor)query.set('cursor',position.cursor)
  const devices = useQuery({queryKey:['discovery-center',query.toString()],queryFn:({signal})=>request<Page>(`/discovery/devices?${query}`,{signal}),enabled:position.ready})
  const catalogue=useQuery({queryKey:['discovery-types'],queryFn:({signal})=>request<Catalogue>('/discovery/types',{signal})})
  const coverage=useQuery({queryKey:['discovery-coverage'],queryFn:({signal})=>request<Coverage>('/discovery/coverage',{signal})})
  const statistics=useQuery({queryKey:['discovery-statistics'],queryFn:({signal})=>request<Statistics>('/discovery/statistics',{signal}),enabled:coverage.data?.enabled===true})
  const metadataQuery=new URLSearchParams(query);metadataQuery.delete('cursor');metadataQuery.delete('limit')
  const discoveryMetadata=useQuery({queryKey:['discovery-metadata',metadataQuery.toString()],queryFn:({signal})=>request<components['schemas']['DiscoveryDeviceMetadata']>(`/discovery/devices/metadata?${metadataQuery}`,{signal})})
  const metadataValue=(value?:number)=>value??(discoveryMetadata.isError?'统计读取失败':'统计中')
  // keepPreviousData 会保留上一次结果，只看 isPending 会让搜索看起来没有反应。
  // 输入尚未落到 URL、列表或统计仍在请求时都算“更新中”，给用户持续反馈。
  const pendingSearch = draft.trim() !== search
  const listUpdating = devices.isFetching || position.isLocating
  const searching = pendingSearch || listUpdating || discoveryMetadata.isFetching
  const historyEnabled=Boolean(selected)&&coverage.data?.enabled===true
  const historyMetadata=usePaginationMetadata('/discovery/history/metadata',{device_id:selected?.id},historyEnabled)
  const historyScope=new URLSearchParams({device_id:selected?.id??''})
  if(historyMetadata.data?.snapshot)historyScope.set('snapshot',historyMetadata.data.snapshot)
  const historyPosition=useCursorPagePosition({path:'/discovery/history/position',query:historyScope,page:historyPage,pageSize:historyPageSize,enabled:historyEnabled&&Boolean(historyMetadata.data)})
  const historyQuery=new URLSearchParams(historyScope);historyQuery.set('limit',String(historyPageSize));if(historyPosition.cursor)historyQuery.set('cursor',historyPosition.cursor)
  const history=useQuery({queryKey:['discovery-history',historyQuery.toString()],queryFn:({signal})=>request<History>(`/discovery/history?${historyQuery}`,{signal}),enabled:historyPosition.ready})
  const detailIP=selected?.current_addresses?.[0]??(selected?.current_addresses?undefined:selected?.primary_ip)
  const detailFlowTarget=selected?.sensor_id&&detailIP?`${selected.sensor_id}|${detailIP}`:''
  const portReadEnabled=detailFlowTarget!==''&&coverage.data?.enabled===true
  const handshakeClues=useQuery({queryKey:['discovery-handshake-clues',selected?.id,selected?.sensor_id,selected?.site,selected?.domain,detailIP],queryFn:({signal})=>request<{items:HandshakeClue[]}>(`/discovery/handshake-clues?${new URLSearchParams({sensor_id:selected!.sensor_id||'',campus_id:selected!.site||'',access_domain:selected!.domain||'',ip:detailIP!})}`,{signal}),enabled:!!selected?.sensor_id&&!!selected?.site&&!!selected?.domain&&!!detailIP&&coverage.data?.enabled===true,staleTime:30_000})
  const types=Object.fromEntries((catalogue.data?.items??[]).map(t=>[t.id,t.label]))
  const items:Device[]=devices.data?.items??[]
  const typedPageCount=items.filter(item=>!['conflict','expired'].includes(item.classification_status??'')&&!!(item.device_type||(item.recognition?.device_type&&(item.recognition.confidence??0)>=.8))).length
  const allServiceTargets=[...new Set(items.flatMap(item=>item.sensor_id&&item.mac?(item.current_addresses??(item.primary_ip?[item.primary_ip]:[])).map(ip=>`${item.sensor_id}|${item.mac!.toLowerCase()}|${ip}`):[]))].sort()
  const serviceKey=allServiceTargets.slice(0,50).join(',')
  const serviceClues=useQuery({queryKey:['discovery-service-clues',serviceKey],queryFn:({signal})=>request<{items:Record<string,ServiceClue[]>}>(`/discovery/service-clues?targets=${encodeURIComponent(serviceKey)}`,{signal}),enabled:serviceKey!==''&&coverage.data?.enabled===true,staleTime:60_000})
  const signalKey=[...new Set(items.flatMap(item=>[item.current_addresses?.[0],item.primary_ip,item.last_observed_ip].filter(Boolean) as string[]))].sort().join(',')
  const signalMACs=[...new Set(items.map(item=>item.mac?.toLowerCase()).filter(Boolean))].sort().join(',')
  const signalSensors=[...new Set(items.map(item=>item.sensor_id).filter(Boolean))].sort().join(',')
  const observedPorts=useQuery({queryKey:['discovery-observed-ports',detailFlowTarget],queryFn:({signal})=>request<{items:Record<string,ObservedPort[]>}>(`/discovery/observed-ports?targets=${encodeURIComponent(detailFlowTarget)}`,{signal}),enabled:portReadEnabled,staleTime:60_000})
  const passiveSignals=useQuery({queryKey:['discovery-passive-signals',signalKey,signalMACs,signalSensors],queryFn:({signal})=>request<PassiveSignals>(`/discovery/passive-signals?ips=${encodeURIComponent(signalKey)}&macs=${encodeURIComponent(signalMACs)}&sensors=${encodeURIComponent(signalSensors)}`,{signal}),enabled:(signalKey!==''||signalMACs!=='')&&coverage.data?.enabled===true,staleTime:60_000})
  const signalFor=(item:Device)=>{const ips=new Set(item.current_addresses??[item.primary_ip].filter(Boolean));const mac=(item.mac||'').toLowerCase();const candidates=(passiveSignals.data?.items??[]).filter(signal=>{const vlan=signal.dhcp_vlan||signal.ttl_vlan;return !!item.sensor_id&&signal.sensor_id===item.sensor_id&&!signal.client_clues?.length&&(!item.vlan||!vlan||item.vlan===vlan)&&signalAddressMatchesDevice(item,signal)&&((mac&&signal.mac?.toLowerCase()===mac)||(signal.ip&&ips.has(signal.ip)&&(!mac||!signal.mac)))});return candidates.find(signal=>mac&&signal.mac?.toLowerCase()===mac&&(signal.dhcp_vlan||signal.ttl_vlan)===item.vlan)??(candidates.length===1?candidates[0]:undefined)}
  const clientFor=(item:Device)=>{const current=new Set(item.current_addresses??[]);return (passiveSignals.data?.items??[]).find(signal=>!!item.sensor_id&&signal.sensor_id===item.sensor_id&&!!signal.ip&&current.has(signal.ip)&&!!signal.client_clues?.length)}
  const osFor=(item:Device)=>{const signal=signalFor(item);const client=clientFor(item);const base=signal?.os_family||item.recognition?.os_family;const ipFamily=item.mac?'':client?.os_family;const conflict=signal?.os_conflict||(!item.mac&&client?.os_conflict)||(base&&ipFamily&&base!==ipFamily);const detail=[signal?.os_evidence,item.recognition?.os_family?`识别：${item.recognition.rule_version||'规则'}${item.recognition.confidence?`（${Math.round(item.recognition.confidence*100)}%）`:''}`:'',!item.mac&&client?.os_evidence?`${client.os_evidence}；仅按 IP 关联，需核对地址归属`:'' ].filter(Boolean).join('；');if(conflict)return {label:'线索冲突',detail,ipOnly:false};return {label:base||ipFamily||signal?.os_hint||'',detail:detail||(signal?.ttl?`TTL ${signal.ttl}`:''),ipOnly:!base&&!!ipFamily}}
  const fresh=devices.data?.freshness
  const dumbFilter=params.get('discovery_capability')==='dumb'
  const recentPageCount=(devices.data?.items??[]).filter(item=>Date.now()-new Date(item.last_seen).getTime()<=15*60*1000).length
  const identity=(item:Device)=>{
    const type=['conflict','expired'].includes(item.classification_status??'')?'':item.device_type||((item.recognition?.confidence??0)>=.8?item.recognition?.device_type:'')
    return <div className="terminal-identity"><DiscoveryDeviceIcon type={type} capabilities={item.capabilities}/><div><Button type="link" className="terminal-device-link" onClick={()=>show(item)}>{item.name||typeLabel(item,types)||item.mac||item.primary_ip}</Button>{item.mac&&<span className="terminal-mac">{item.mac}</span>}{item.name&&typeLabel(item,types)&&<span className="terminal-kind-caption">{typeLabel(item,types)}</span>}{discoveryNameClue(item.name)&&<Typography.Text type="secondary" className="terminal-kind-caption" title={discoveryNameClue(item.name)?.detail}>{discoveryNameClue(item.name)?.label}</Typography.Text>}</div></div>
  }
  const kind=(item:Device)=>{const label=typeLabel(item,types);return label?<Typography.Text strong={item.classification_status!=='expired'}>{label}</Typography.Text>:null}
  const vendor=(item:Device)=>{const brand=item.manufacturer||((item.recognition?.confidence??0)>=.8?item.recognition?.brand:'');return <div className="terminal-vendor">{brand&&(resolveDeviceBrand({brand}).key!=='unknown'?<BrandLogo brandKey={brand}/>:<Typography.Text>{brand}</Typography.Text>)}{item.model_name&&<Typography.Text type="secondary">{item.model_name}</Typography.Text>}</div>}
  const location=(item:Device)=><Space orientation="vertical" size={0}><Typography.Text>{item.vlan?`VLAN ${item.vlan}`:item.domain}</Typography.Text><Typography.Text type="secondary">{item.vlan?[item.domain,item.sensor_id].filter(Boolean).join(' · '):item.sensor_id}</Typography.Text></Space>
  const servicesFor=(item:Device)=>{const list=serviceClues.data?.items?.[`${item.sensor_id}|${(item.mac||'').toLowerCase()}`]??[];const seen=new Set<string>();return list.filter(clue=>{if(!serviceBelongsToDevice(item,clue))return false;const key=`${clue.service_type}:${clue.port}`;if(seen.has(key))return false;seen.add(key);return true})}
  const portsFor=(item:Device)=>{const seen=new Set<string>();return (portReadEnabled?observedPorts.data?.items?.[detailFlowTarget]??[]:[]).filter(clue=>{if(!flowBelongsToDevice(item,clue))return false;const key=`${clue.proto}:${clue.dst_port}`;if(seen.has(key))return false;seen.add(key);return true}).slice(0,8)}
  const portLabel=(clue:ObservedPort)=>clue.connection_outcome==='syn_ack_observed'?`见 TCP SYN-ACK ${clue.dst_port}`:`尝试连接 ${clue.proto.toUpperCase()} ${clue.dst_port}`
  const clues=(item:Device)=><Space wrap>{(item.capabilities??[]).filter(c=>capabilities[c]).map(c=><Tag key={c}>{capabilities[c]}</Tag>)}{(item.protocols??[]).map(p=><Tag key={p}>{protocols[p]??p}</Tag>)}</Space>
  const state=(item:Device)=><Typography.Text type={item.classification_status==='conflict'?'warning':'secondary'}>{item.classification_status==='candidate'&&!typeLabel(item,types)?((item.protocols??[]).every(p=>p==='arp'||p==='ndp')&&item.protocols?.length?(item.protocols.includes('arp')?'ARP 地址候选':'NDP 地址线索'):'缺少类型证据'):states[item.classification_status??'']??(item.current?'证据有效':'证据已过期')}</Typography.Text>
  const refreshDiscovery=()=>{const first=new URLSearchParams(query);first.delete('cursor');setPaging({key:filterKey,page:0});void position.invalidate();void discoveryMetadata.refetch();void coverage.refetch();void statistics.refetch();void queryClient.invalidateQueries({queryKey:['discovery-center'],refetchType:'none'});void queryClient.refetchQueries({queryKey:['discovery-center',first.toString()],exact:true})}
  const refreshWorkspace=()=>refreshDiscovery()
  const show=(item:Device)=>{setHistoryPage(1);setSelected(item)}
  const columns=[
    {title:'设备',key:'identity',width:250,render:(_:unknown,item:Device)=>identity(item)},
    {title:'设备类型',key:'type',width:145,render:(_:unknown,item:Device)=>kind(item)},
    {title:'地址 / 网络',key:'address',width:175,render:(_:unknown,item:Device)=><div className="terminal-address"><span>{item.current_addresses?.[0]??item.primary_ip}</span>{item.current_addresses?.length===0&&item.last_observed_ip&&<Typography.Text type="secondary">最后地址 {item.last_observed_ip}</Typography.Text>}{location(item)}</div>},
    {title:'厂商 / 系统',key:'vendor',width:160,render:(_:unknown,item:Device)=><div>{vendor(item)}{osFor(item).label&&<Typography.Text type="secondary">{osFor(item).label} · 线索</Typography.Text>}</div>},
    {title:'识别依据',key:'clues',width:145,render:(_:unknown,item:Device)=><div className="discovery-ledger-stack">{clues(item)}{secondaryTypeClue(item,types,signalFor(item))&&<Typography.Text type="secondary">{secondaryTypeClue(item,types,signalFor(item))}</Typography.Text>}{state(item)}</div>},
    {title:'最近观测',key:'seen',width:110,render:(_:unknown,item:Device)=><span title={observedTimeTitle(item.last_seen)}>{observedTimeLabel(item.last_seen)}</span>},
    {title:'操作',key:'action',width:140,fixed:'right' as const,render:(_:unknown,item:Device)=><div className="terminal-row-actions"><Button type="link" onClick={()=>show(item)}>查看详情</Button></div>},
  ]

  return <section className="passive-discovery-panel terminal-workspace">
    <div className="workspace-topbar">
    <header className="terminal-workspace-header"><div><span className="terminal-eyebrow">设备中心 / 204 独立管理</span><Typography.Title level={3}>发现设备</Typography.Title><Typography.Text type="secondary">发现镜像中的设备，核对类型与识别依据。</Typography.Text></div><div className="terminal-header-actions"><Button icon={<ReloadOutlined aria-hidden="true"/>} onClick={refreshWorkspace}>刷新数据</Button></div></header>
    </div>
    {discoveryMetadata.isError&&<AppErrorAlert title="读取发现数量失败" message={discoveryMetadata.error.message} action={<Button onClick={()=>void discoveryMetadata.refetch()}>重试统计</Button>}/>}
    {position.isError&&<AppErrorAlert title="页码定位失败" message={position.error.message} action={<Button onClick={()=>void position.refetch()}>重试定位</Button>}/>}
    {devices.isError?<AppErrorAlert title="读取发现设备失败" message={devices.error.message} />:<section aria-busy={searching} className={searching?'surface center-list-surface is-updating':'surface center-list-surface'}>
      <div className="list-surface-head">
      <AppTableBar
        searchPlaceholder="搜索 IP、MAC、名称或型号"
        searching={searching}
        searchValue={draft}
        onSearchChange={setDraft}
        onSearch={value=>change('search', value.trim())}
        filters={<>
          <Select aria-label="设备类型" showSearch optionFilterProp="label" value={params.get('discovery_type')||''} options={[{value:'',label:'全部设备类型'},...(catalogue.data?.items??[]).map(t=>({value:t.id,label:t.label}))]} onChange={v=>change('type',v)}/>
          <Select aria-label="证据状态" value={params.get('discovery_state')||''} options={[{value:'',label:'全部证据状态'},...Object.entries(states).filter(([k])=>view!=='iot'||k!=='candidate').map(([value,label])=>({value,label}))]} onChange={v=>change('state',v)}/>
          <Button size="small" type="text" onClick={()=>setMoreOpen(value=>!value)}>{moreOpen?'收起筛选':'更多筛选'}{['type','protocol','window','domain','vlan'].filter(key=>params.get(`discovery_${key}`)).length?`（${['type','protocol','window','domain','vlan'].filter(key=>params.get(`discovery_${key}`)).length}）`:''}</Button>
        </>}
        extra={<div className="discovery-list-actions">{searching&&<span className="discovery-search-status" role="status" aria-live="polite"><LoadingOutlined aria-hidden="true" spin /> {draft.trim()||search?'正在搜索…':'正在加载…'}</span>}<span className="terminal-page-summary" aria-label="发现设备摘要"><span>当前页 <strong>{items.length}</strong> 个设备</span><span>本页明确类型 <strong>{typedPageCount}</strong></span><span>本页近15分钟观测 <strong>{recentPageCount}</strong></span></span><Button type="link" size="small" onClick={()=>setParams(current=>{const next=new URLSearchParams(current);for(const key of [...next.keys()])if(key.startsWith("discovery_")&&key!=="discovery_view")next.delete(key);return next})}>清除筛选</Button></div>}
      panel={moreOpen?<div className="app-filter-panel">
          <Select aria-label="发现协议" value={params.get('discovery_protocol')||''} options={[{value:'',label:'全部协议'},...Object.entries(protocols).map(([value,label])=>({value,label}))]} onChange={v=>change('protocol',v)}/>
          <Select aria-label="最近观测范围" value={params.get('discovery_window')==='all'?'720h':params.get('discovery_window')||''} options={[{value:'',label:'近 24 小时'},{value:'168h',label:'近 7 天'},{value:'720h',label:'近 30 天'}]} onChange={v=>change('window',v)}/>
          <Input aria-label="网络域" placeholder="网络域" allowClear value={params.get('discovery_domain')||''} onChange={e=>change('domain',e.target.value)}/>
          <Input aria-label="VLAN" placeholder="VLAN" allowClear value={params.get('discovery_vlan')||''} onChange={e=>change('vlan',e.target.value)}/>
        </div>:undefined}
      />
        <nav className="terminal-type-shortcuts" aria-label="快捷设备类型">{[{value:'',label:'全部设备'},{value:'printer',label:'打印机'},{value:'camera',label:'摄像机'},{value:'access_point',label:'无线 AP'},{value:'router',label:'路由器'},{value:'switch',label:'交换机'},{value:'desktop',label:'电脑'},{value:'mobile',label:'手机'}].map(t=><Button key={t.value} type={(params.get('discovery_type')||'')===t.value&&!dumbFilter?'primary':'default'} onClick={()=>shortcut(t.value)}>{t.label}</Button>)}<Button type={dumbFilter?'primary':'default'} onClick={()=>shortcut('',dumbFilter?'':'dumb')}>哑终端线索</Button></nav>
      </div>
      <div className="discovery-overview-strip" aria-label="发现设备总览" title={`${params.get('discovery_window')==='168h'?'近 7 天':params.get('discovery_window')==='720h'?'近 30 天':'近 24 小时'} · 按采集范围与可信身份去重${discoveryMetadata.data?.as_of?` · 统计于 ${observedTimeTitle(discoveryMetadata.data.as_of)}`:''}`}>
        <div className="discovery-overview-line">
          <strong>共 {metadataValue(discoveryMetadata.data?.total)} 个设备</strong>
          <span>已识别类型 {metadataValue(discoveryMetadata.data?.identified)}</span>
          <span>待核实 {metadataValue(discoveryMetadata.data?.candidate)}</span>
          <span>类型冲突 {metadataValue(discoveryMetadata.data?.conflict)}</span>
          <span>证据过期 {metadataValue(discoveryMetadata.data?.expired)}</span>
          <Typography.Text className="discovery-overview-caption" type="secondary">{params.get('discovery_window')==='168h'?'近 7 天':params.get('discovery_window')==='720h'?'近 30 天':'近 24 小时'} · 按采集范围与可信身份去重{discoveryMetadata.data?.as_of?` · 统计于 ${observedTimeTitle(discoveryMetadata.data.as_of)}`:''}{discoveryMetadata.isFetching?' · 统计更新中':''}</Typography.Text>
        </div>
        <div className="discovery-overview-types"><Typography.Text type="secondary">具体类型{discoveryMetadata.data?`（合计 ${discoveryMetadata.data.types.reduce((sum,item)=>sum+item.count,0)}）`:''}</Typography.Text>{discoveryMetadata.data?.types.length?[...discoveryMetadata.data.types].sort((a,b)=>b.count-a.count||a.device_type.localeCompare(b.device_type)).map(item=><span className="discovery-overview-type" key={item.device_type}>{types[item.device_type]??deviceTypeLabel(item.device_type)} <strong>{item.count}</strong></span>):<Typography.Text type="secondary">{discoveryMetadata.data?'当前筛选下暂无明确类型':discoveryMetadata.isError?'统计读取失败':'统计中'}</Typography.Text>}</div>
      </div>
      <AppTable className="passive-ledger-table" rowKey={discoveryTableRowKey} columns={columns} dataSource={items} tableLayout="fixed" loading={{spinning:listUpdating,delay:150}} scroll={{x:1125}} locale={{emptyText:listUpdating?'正在加载设备…':'当前筛选下暂无符合条件的设备'}}/>
      <AppServerPagination disabled={devices.isFetching||position.isLocating} page={page+1} pageSize={pageSize} total={discoveryMetadata.data?.total} onChange={(nextPage,nextSize)=>{
        if(nextSize!==pageSize){setPageSize(nextSize);setPaging({key:filterKey,page:0});return}
        setPaging({key:filterKey,page:nextPage-1})
      }} totalText={discoveryMetadata.data?`共 ${discoveryMetadata.data.total} 个设备`:(discoveryMetadata.isError?'数量读取失败':'正在统计数量')} />
    </section>}
    <details className="terminal-diagnostics" open={qualityOpen}><summary onClick={event=>{event.preventDefault();setQualityOpen(value=>!value)}}>采集与识别状态</summary>    <section className="surface center-list-toolbar">
      {qualityOpen&&<div className="recognition-quality-strip" aria-label="识别质量">
        {quality.isError&&<AppErrorAlert title="识别质量读取失败" message={quality.error.message} />}
        {quality.data&&<>
          {qualityItem('类型覆盖',quality.data.coverage.device_type,quality.data.total_endpoints)}
          {qualityItem('品牌覆盖',quality.data.coverage.brand,quality.data.total_endpoints)}
          {qualityItem('型号覆盖',quality.data.coverage.model,quality.data.total_endpoints)}
          {qualityItem('系统覆盖',quality.data.coverage.os_family,quality.data.total_endpoints)}
          <span className="recognition-quality-item"><Typography.Text type="secondary">链路层归属</Typography.Text><Typography.Text strong>{Math.round((quality.data.mac_attribution_rate??0)*100)}%</Typography.Text></span>
        </>}
        {quality.isLoading&&<Typography.Text type="secondary">识别质量读取中</Typography.Text>}
      </div>}
      {catalogue.isError&&<AppErrorAlert title="读取设备类型失败" message={catalogue.error.message} />}
      {fresh&&fresh.status!=='ready'&&<Alert type={fresh.status==='failed'?'error':'warning'} showIcon title={fresh.status==='failed'?'设备数据处理失败':fresh.status==='delayed'?'设备数据更新延迟':'设备数据处理中'} description={fresh.oldest_pending_at?`最早待处理时间：${observedTimeTitle(fresh.oldest_pending_at)}`:undefined}/>}
      {coverage.data?.capture_scope?.status==='expiring'&&<Alert type="warning" showIcon title="镜像采集范围即将到期" description={coverage.data.capture_scope.valid_until?`有效期至 ${observedTimeTitle(coverage.data.capture_scope.valid_until)}，请提前更新采集范围。`:undefined}/>}
      {coverage.data?.capture_scope?.status==='expired'&&<Alert type="error" showIcon title="镜像采集范围已到期" description={coverage.data.capture_scope.valid_until?`有效期截止于 ${observedTimeTitle(coverage.data.capture_scope.valid_until)}。`:undefined}/>}
      {coverage.data?.capture_scope?.status==='invalid'&&<Alert type="error" showIcon title="镜像采集范围配置无法读取" />}
      {coverage.data?.quarantine?.status==='blocked'&&<Alert type="error" showIcon title="发现数据段已隔离，处理存在缺口" description={`待核对段数至少 ${coverage.data.quarantine.count_at_least}；原始段已保留，需核对采集范围后恢复。`}/>}
      {coverage.data?.quarantine?.status==='unavailable'&&<Alert type="warning" showIcon title="发现隔离状态暂不可用" />}
      {passiveSignals.data?.durable_status==='unavailable'&&<Alert type="warning" showIcon title="较早的 DHCP 线索暂不可用" description="当前仅展示近期镜像日志中的被动线索。" />}
      {passiveSignals.data?.client_status==='unavailable'&&<Alert type="warning" showIcon title="HTTP 与 TLS 被动线索暂不可用" />}
      {passiveSignals.isError&&<AppErrorAlert title="读取被动识别线索失败" message={passiveSignals.error.message} />}
      {serviceClues.isError&&<AppErrorAlert title="读取服务公告线索失败" message={serviceClues.error.message} action={<Button size="small" loading={serviceClues.isFetching} onClick={()=>void serviceClues.refetch()}>重试</Button>} />}
      {allServiceTargets.length>50&&<Alert type="warning" showIcon title="本页当前地址超过 50 个，仅展示已查询地址的服务公告线索" />}
      {statistics.isError&&<AppErrorAlert title="读取设备统计失败" message={statistics.error.message} />}
      {statistics.data&&<div className="discovery-statistics" aria-label="设备类型统计">{statistics.data.items.filter(item=>item.count>0&&item.state!=='candidate').map(item=><span className="discovery-statistics-item" title={`统计更新于 ${observedTimeTitle(item.updated_at)}`} key={`${item.device_type}:${item.state}`}>{types[item.device_type]??item.device_type} · {states[item.state]??''} {item.count}</span>)}{statistics.data.pending_updates>0&&<Typography.Text type="secondary">统计处理中 {statistics.data.pending_updates}</Typography.Text>}</div>}
      <Collapse ghost items={[{key:'coverage',label:'采集覆盖与处理状态',children:coverage.isError?<AppErrorAlert title="读取采集状态失败" />:coverage.data?.enabled===false?<Typography.Text>当前运行旧版发现路径</Typography.Text>:<div className="iot-coverage-grid">{coverage.data?.items.map(p=><article className="iot-coverage-item" key={`${p.sensor_id}:${p.protocol}`}><strong>{protocols[p.protocol]??p.protocol}</strong><Typography.Text type="secondary">{p.sensor_id}</Typography.Text><span>{p.message_source_epoch?'逐消息源已登记':p.handshake_source_epoch?'握手侧车已登记 · 详情弱线索':p.error?'采集异常':!p.enabled?'未启用':p.received===0?'暂未捕获协议流量':'已捕获协议流量'}</span><span>{p.message_source_epoch?'旧链路累计 ':p.handshake_source_epoch?'发现链路累计 ':''}捕获 {p.received} · 解析 {p.parsed} · 处理 {p.admitted}</span></article>)}</div>}]} />
    </section>
</details>
    <Modal className="discovery-evidence-modal" title="设备详情" open={!!selected} footer={null} onCancel={()=>setSelected(undefined)}>{selected&&<><div className="discovery-detail-identity">{identity(selected)}{kind(selected)}</div><dl className="discovery-detail-facts">{[[`设备类型`,typeLabel(selected,types)],[`分类状态说明`,discoveryClassificationExplanation(selected)],[`名称线索`,discoveryNameClue(selected.name)?.label],[`名称线索依据`,discoveryNameClue(selected.name)?.detail],[`分类补充线索`,secondaryTypeClue(selected,types,signalFor(selected))],[`操作系统线索`,osFor(selected).label?`${osFor(selected).label} · ${signalFor(selected)?.dhcp_historical&&signalFor(selected)?.os_family?'历史线索':'线索'}`:''],[`操作系统依据`,osFor(selected).detail],[`DHCP 线索时效`,signalFor(selected)?.dhcp_historical?'历史 REQUEST 线索；同源当前租约仍有效，需结合观测时间核对':''],[`DHCP 观测时间`,signalFor(selected)?.dhcp_observed_at?observedTimeTitle(signalFor(selected)!.dhcp_observed_at!):''],[`最近 DHCP 证据事件`,signalFor(selected)?.dhcp_evidence_id],[`TTL 证据引用`,signalFor(selected)?.ttl_evidence?.event_id||((signalFor(selected)?.ttl_evidence?.raw_sha256)?`原文 SHA256 ${signalFor(selected)?.ttl_evidence?.raw_sha256}`:'')],[`TTL 观测时间`,signalFor(selected)?.ttl_observed_at?observedTimeTitle(signalFor(selected)!.ttl_observed_at!):''],[`TTL`,signalFor(selected)?.ttl?String(signalFor(selected)?.ttl):''],[`DHCP 主机名`,signalFor(selected)?.dhcp_hostname],[`DHCP 厂商类`,signalFor(selected)?.dhcp_vendor_class],[`DHCP 请求选项`,signalFor(selected)?.dhcp_options],[`DHCP 客户端标识类型`,signalFor(selected)?.dhcp_client_id_hwtype],[`DHCP 选项 93`,signalFor(selected)?.dhcp_option93_present?'已观测':''],[`识别操作系统`,selected.recognition?.os_family],[`识别设备类型`,selected.recognition?.device_type],[`识别规则`,selected.recognition?.rule_version],[`识别依据`,(selected.recognition?.evidence??[]).join('；')],[`品牌推断`,selected.recognition?.brand_inference_status==='inferred'&&selected.recognition?.brand_inference_brand?`${selected.recognition.brand_inference_brand} · 设备服务线索推断${selected.recognition.brand_inference_confidence?`（${Math.round(selected.recognition.brand_inference_confidence*100)}%）`:''}`:''],[`制造商`,selected.manufacturer],[`型号`,selected.model_name],[`MAC`,selected.mac],[`当前地址`,(selected.current_addresses??[]).join('、')||selected.primary_ip],[`最后观测地址`,selected.last_observed_ip],[`网络域`,selected.domain],[`VLAN`,selected.vlan],[`采集传感器`,selected.sensor_id],[`首次观测`,selected.first_seen?observedTimeTitle(selected.first_seen):''],[`最近观测`,observedTimeTitle(selected.last_seen)],[`证据数`,selected.evidence_count?String(selected.evidence_count):'']].filter(([,value])=>value).map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>{dhcpFieldEvidenceFor(signalFor(selected)).length>0&&<section className="discovery-client-clues"><Typography.Text type="secondary">DHCP 字段证据（各字段保留对应原始报文引用）</Typography.Text>{dhcpFieldEvidenceFor(signalFor(selected)).map(entry=><article key={entry.field}><strong>{entry.label}</strong><span>{entry.value}</span><Typography.Text type="secondary">{[entry.ref.event_id?`事件 ${entry.ref.event_id}`:entry.ref.raw_sha256?`原文 SHA256 ${entry.ref.raw_sha256}`:'',entry.ref.historical?'历史线索':'',observedTimeTitle(entry.ref.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}{clientFor(selected)?.client_clues?.length&&<section className="discovery-client-clues"><Typography.Text type="secondary">HTTP / TLS 客户端弱线索（仅按当前 IP 关联，地址共享或复用时需核对）</Typography.Text>{clientFor(selected)?.client_clues?.map((clue,index)=><article key={`${clue.kind}:${clue.evidence_id}:${index}`}><strong>{clue.kind==='user_agent'?'HTTP User-Agent':clue.kind.toUpperCase()}</strong><span>{clue.value}</span><Typography.Text type="secondary">{[clue.evidence_id,observedTimeTitle(clue.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}<Typography.Paragraph>{selected.classification?.reason}</Typography.Paragraph><DiscoveryEvidenceSummary observations={selected.observations}/>
      {handshakeClues.isError&&<AppErrorAlert title="读取握手弱线索失败" />}
      {!!handshakeClues.data?.items.length&&<section className="discovery-client-clues"><Typography.Text type="secondary">镜像握手弱线索（当前 IP {detailIP}，地址共享或复用时需核对）</Typography.Text>{handshakeClues.data.items.map((clue,index)=><article key={`${clue.kind}:${clue.evidence_id}:${index}`}><strong>{clue.kind==='user_agent'?'HTTP User-Agent':clue.kind==='ja4'?'TLS JA4':'TLS JA3'}</strong><span>{clue.value}</span><Typography.Text type="secondary">{[clue.dst_port?`握手目标 TCP/${clue.dst_port}`:'',clue.evidence_id,observedTimeTitle(clue.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}
      {servicesFor(selected).length>0&&<section className="discovery-client-clues"><Typography.Text type="secondary">服务公告证据事件</Typography.Text>{servicesFor(selected).map(clue=><article key={`${clue.service_type}:${clue.port}`}><strong>{clue.service_type} · {clue.port}</strong><Typography.Text type="secondary">{clue.evidence_id} · {observedTimeTitle(clue.last_seen)}</Typography.Text></article>)}</section>}
      {portReadEnabled&&observedPorts.isPending&&<Typography.Text type="secondary">正在读取当前 IP 近 2 小时目标端口线索</Typography.Text>}
      {portReadEnabled&&observedPorts.isError&&<AppErrorAlert title="读取目标端口线索失败" message={observedPorts.error.message} />}
      {portReadEnabled&&observedPorts.data&&portsFor(selected).length===0&&<Typography.Text type="secondary">当前 IP 近 2 小时的镜像端口聚合中无匹配记录</Typography.Text>}
      {portsFor(selected).length>0&&<section className="discovery-client-clues"><Typography.Text type="secondary">近 2 小时目标端口线索（按当前 IP 关联；SYN-ACK 仅说明镜像见到反向响应，不证明连接完成或设备本机端口开放）</Typography.Text>{portsFor(selected).map(clue=><article key={`${clue.proto}:${clue.dst_port}`}><strong>{portLabel(clue)}</strong><Typography.Text type="secondary">{clue.evidence_id} · {observedTimeTitle(clue.last_seen)}</Typography.Text></article>)}</section>}
      {history.isError&&<AppErrorAlert title="读取设备历史失败" />}
      {historyEnabled&&<section className="discovery-history"><Typography.Title level={5}>变化历史</Typography.Title>
        {(history.isError||historyMetadata.isError||historyPosition.isError)?<AppErrorAlert title="读取设备历史失败" message={history.error?.message||historyMetadata.error?.message||historyPosition.error?.message}/>:historyMetadata.isPending||historyPosition.isLocating||history.isFetching?<Typography.Text type="secondary">正在读取历史记录</Typography.Text>:historyPosition.ready&&(history.data?.items??[]).map(row=><article className="discovery-card" key={row.id}><strong>{protocols[row.evidence?.origin]??row.evidence?.origin}</strong><span>{row.evidence?.explanation}</span><Typography.Text type="secondary">观测于 {observedTimeTitle(row.observed_at)}</Typography.Text></article>)}
        <AppServerPagination disabled={history.isFetching||historyPosition.isLocating} page={historyPage} pageSize={historyPageSize} total={historyMetadata.data?.total} totalText={historyMetadata.isError?'数量读取失败':undefined} onChange={(next,size)=>{setHistoryPage(next);setHistoryPageSize(size)}}/>
      </section>}
    </>}</Modal>
  </section>
}
