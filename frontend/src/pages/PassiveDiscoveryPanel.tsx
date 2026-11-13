import {
  AppErrorAlert,
  AppServerPagination, useCursorPagePosition, usePaginationMetadata,
  AppTable, AppTableBar } from '../shared/ui'
import { Notice as Alert } from '../shared/ui/Notice'
import { useEffect,
  useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button,
  Checkbox,
  Collapse,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
  message,
} from 'antd'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { DownloadOutlined, LoadingOutlined, ReloadOutlined } from '@ant-design/icons'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import type { InventoryDetail } from '../shared/api/types'
import { DiscoveryDeviceIcon } from '../entities/device/DiscoveryDeviceIcon'
import { BrandLogo } from '../entities/device/BrandLogo'
import { resolveDeviceBrand } from '../entities/device/brandMatcher'
import { isRandomizedMAC } from '../entities/device/mac'
import { DiscoveryEvidenceSummary } from './DiscoveryEvidenceSummary'
import { discoveryCSV, fetchDiscoveryExport } from './discoveryExport'
import { qualityReportCSV } from './discoveryQualityReport'
import { loadDiscoveryViews, removeDiscoveryView, saveDiscoveryView } from './discoveryViews'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'
import { flowBelongsToDevice, serviceBelongsToDevice, signalAddressMatchesDevice } from './discoveryServiceAttribution'
import { discoveryClassificationExplanation, discoveryNameClue } from './discoveryClassificationClues'
import { CensusPanel } from './CensusPanel'
import { activityStates, confirmedDeviceType, hardwareStates, type HardwareView } from './discoveryHardware'

type DeviceRecognition = { os_family?: string; os_family_confidence?: number; device_type?: string; brand?: string; model?: string; confidence?: number; rule_version?: string; source?: string; evidence?: string[]; brand_inference_status?: string; brand_inference_brand?: string; brand_inference_confidence?: number }
type Device = components['schemas']['DiscoveryDevice'] & HardwareView & { recognition?: DeviceRecognition }
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
const protocols: Record<string,string> = { dhcp:'DHCP', dhcpv6:'DHCPv6', sip:'SIP', sadp:'SADP', dns_sd:'DNS-SD', ssdp:'SSDP', ws_discovery:'WS-Discovery', arp:'ARP', ndp:'NDP', ieee1905_client:'IEEE 1905', ieee1905_client_association:'IEEE 1905', lldp:'LLDP', cdp:'CDP', snmp:'SNMP', ipp:'IPP', onvif:'ONVIF', nbns:'NBNS', llmnr:'LLMNR', bacnet:'BACnet/IP', modbus:'Modbus', coap:'CoAP', mqtt:'MQTT', http:'HTTP', tls:'TLS', rtsp:'RTSP', fdb:'交换机 MAC 表', neighbor:'邻居表', active:'探测响应' }
const capabilities: Record<string,string> = { printing:'打印', scanning:'扫描', casting:'投屏', network_video:'网络视频', media_rendering:'媒体播放', voice:'语音通话' }
const states: Record<string,string> = { identified:'证据有效', expired:'证据已过期', conflict:'类型证据冲突', candidate:'发现线索' }
const reviewReasons: Record<string,string> = { new_priority:'近 7 天新出现重点品类', type_change:'待核实类型变化线索', conflict:'类型证据冲突', address_only:'长期只有地址线索' }
const categories: Record<string,string> = { mobile:'手机', tablet:'平板', desktop:'桌面终端', printer:'打印设备', camera:'摄像设备', access_control:'门禁设备', network:'网络设备', media:'媒体设备', voice:'语音设备', identity_only:'仅身份线索' }
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
  if(item.hardware_type_status){
    if(item.hardware_type_status==='conflict')return hardwareStates.conflict
    const hardware=confirmedDeviceType(item)
    return hardware?types[hardware]??deviceTypeLabel(hardware):''
  }
  if(item.classification_status==='conflict')return '类型证据冲突'
  if(item.classification_status==='expired')return item.last_device_type?`${types[item.last_device_type]??deviceTypeLabel(item.last_device_type)} · 历史类型`:''
  if(item.classification_status==='candidate'&&item.last_product_type)return `${types[item.last_product_type]??deviceTypeLabel(item.last_product_type)} · 历史型号自报`
  const observed=item.device_type
  if(observed) {
    const label=types[observed]??deviceTypeLabel(observed)
    return item.classification_status==='candidate'?`${label} · 类型线索`:label
  }
  const recognized=item.recognition?.device_type
  if(recognized&&((item.recognition?.confidence??0)>=.8))return types[recognized]??deviceTypeLabel(recognized)
  return ''
}

function conclusionTypeLabel(item:Device, types:Record<string,string>) {
  if(!item.hardware_type_status&&item.classification_status==='candidate')return ''
  return typeLabel(item,types)
}

function recognitionTypeLabel(item:Device, types:Record<string,string>) {
  if(item.hardware_type_status)return ''
  const type=item.recognition?.device_type
  if(!type)return ''
  const label=types[type]??deviceTypeLabel(type)
  const confidence=item.recognition?.confidence??0
  return confidence>0&&confidence<.8?`${label} · 类型线索（${Math.round(confidence*100)}%）`:label
}

function recognitionOSLabel(item:Device) {
  const os=item.recognition?.os_family
  if(!os)return ''
  const confidence=item.recognition?.os_family_confidence??item.recognition?.confidence??0
  return confidence>0&&confidence<.8?`${os} · 系统线索（${Math.round(confidence*100)}%）`:os
}

function dhcpHintLabel(hint:string) {
  const lower=hint.toLowerCase()
  if(lower.includes('android'))return 'Android 设备'
  if(lower.includes('windows'))return 'Windows 设备'
  if(lower.includes('apple')||lower.includes('ios')||lower.includes('mac'))return 'Apple 设备'
  if(lower.includes('linux'))return 'Linux 设备'
  return hint
}

function DebouncedInput({label,placeholder,value,onChange}:{label:string;placeholder:string;value:string;onChange:(value:string)=>void}) {
  const [draft,setDraft]=useState(value)
  useEffect(()=>setDraft(value),[value])
  useEffect(()=>{
    const timer=globalThis.setTimeout(()=>{if(draft!==value)onChange(draft)},300)
    return ()=>globalThis.clearTimeout(timer)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[draft,value])
  return <Input aria-label={label} placeholder={placeholder} allowClear value={draft} onChange={event=>setDraft(event.target.value)}/>
}

function trendBucket(value:number,max:number) {
  if(value<=0)return 0
  if(max<=0)return 1
  return Math.min(5,Math.max(1,Math.ceil(value/max*5)))
}

function secondaryTypeClue(item:Device, types:Record<string,string>, signal?:PassiveSignal) {
  if(dumbTerminal(item))return `服务能力线索 · ${dumbTerminal(item)}`
  if(signal?.device_hint)return `${dhcpHintLabel(signal.device_hint)} · DHCP ${signal.dhcp_historical?'历史线索':'线索'}`
  if(item.recognition?.brand_inference_status==='inferred'&&item.recognition?.brand_inference_brand)return `${item.recognition.brand_inference_brand} · 品牌推断线索`
  const recognized=item.hardware_type_status?'':item.recognition?.device_type
  if(recognized&&(item.recognition?.confidence??0)<.8)return `${types[recognized]??deviceTypeLabel(recognized)} · 低置信度线索`
  if(item.classification_status==='candidate'&&item.device_type&&!item.last_product_type)return `${types[item.device_type]??deviceTypeLabel(item.device_type)} · 类型线索`
  return ''
}

export function PassiveDiscoveryPanel({view}:{view:'iot'|'records'}) {
  const [params,setParams] = useSearchParams()
  const navigate=useNavigate()
  const queryClient=useQueryClient()
  const search = params.get('discovery_search') || ''
  const [draft,setDraft] = useState(search)
  const [moreOpen,setMoreOpen] = useState(false)
  const [views,setViews]=useState(()=>loadDiscoveryViews(globalThis.localStorage))
  const [activeViewId,setActiveViewId]=useState('')
  const [saveViewOpen,setSaveViewOpen]=useState(false)
  const [viewName,setViewName]=useState('')
  const [manageViewsOpen,setManageViewsOpen]=useState(false)
  const deleteSavedView=(id:string)=>{
    setViews(removeDiscoveryView(globalThis.localStorage,id))
    if(activeViewId===id)setActiveViewId('')
  }
  const saveCurrentView=()=>{
    const next=new URLSearchParams()
    for(const [key,value] of params)if(key.startsWith('discovery_'))next.set(key,value)
    const updated=saveDiscoveryView(globalThis.localStorage,viewName,next.toString())
    setViews(updated)
    setSaveViewOpen(false)
    setViewName('')
    message.success('视图已保存')
  }
  const [qualityOpen,setQualityOpen] = useState(false)
  const [trendDays,setTrendDays]=useState(7)
  const [autoRefresh,setAutoRefresh]=useState(()=>{
    try{return globalThis.localStorage.getItem('proxy-sentinel.discovery.auto-refresh')==='true'}catch{return false}
  })
  const toggleAutoRefresh=(value:boolean)=>{
    setAutoRefresh(value)
    try{globalThis.localStorage.setItem('proxy-sentinel.discovery.auto-refresh',String(value))}catch{}
  }
  const quality=useQuery({queryKey:['device-recognition-summary'],queryFn:({signal})=>request<components['schemas']['DeviceRecognitionSummary']>('/device-recognition/summary',{signal}),enabled:qualityOpen,staleTime:60_000})
  const trends=useQuery({queryKey:['discovery-trends',trendDays],queryFn:({signal})=>request<components['schemas']['DiscoveryTrends']>(`/discovery/trends?days=${trendDays}`,{signal}),enabled:qualityOpen,staleTime:60_000})
  const [pageSize,setPageSize] = useState(20)
  const filterKey = [view,search,pageSize,...['category','type','protocol','state','domain','vlan','window','capability','review_reason'].map(k=>params.get(`discovery_${k}`)||'')].join('|')
  const [paging,setPaging] = useState({key:filterKey,page:0})
  useEffect(()=>setPaging(current=>current.key===filterKey?current:{key:filterKey,page:0}),[filterKey])
  const page=paging.key===filterKey?paging.page:0
  const [selected,setSelected] = useState<Device>()
  const [historyPage,setHistoryPage]=useState(1),[historyPageSize,setHistoryPageSize]=useState(20)
  useEffect(()=>setDraft(search),[search])
  useEffect(()=>{const timer=globalThis.setTimeout(()=>{const next=draft.trim();if(next!==search)change('search',next)},300);return()=>globalThis.clearTimeout(timer)},[draft])
  const change = (key:string,value:string) => {
    setParams(current=>{const next=new URLSearchParams(current);if(value)next.set(`discovery_${key}`,value);else next.delete(`discovery_${key}`);if(key==='type')next.delete('discovery_category');if(key==='review_reason'&&value)next.delete('discovery_state');return next},{replace:true})
  }
  const shortcut=(type:string,capability='',state?:string)=>setParams(current=>{const next=new URLSearchParams(current);for(const key of ['type','category','capability'])next.delete(`discovery_${key}`);if(type)next.set('discovery_type',type);if(capability)next.set('discovery_capability',capability);if(state!==undefined){if(state)next.set('discovery_state',state);else next.delete('discovery_state')}return next},{replace:true})
  const toggleState=(value:string)=>change('state',params.get('discovery_state')===value?'':value)
  const query = new URLSearchParams({mode:'passive',limit:String(pageSize)})
  if(view==='iot')query.set('view','iot')
  if(search)query.set('search',search)
  for(const key of ['category','type','protocol','state','domain','vlan','window','capability','random_mac','os','review_reason']){const value=params.get(`discovery_${key}`);if(value)query.set(key,value)}
  const position=useCursorPagePosition({path:'/discovery/devices/position',query,page:page+1,pageSize})
  if(position.cursor)query.set('cursor',position.cursor)
  const devices = useQuery({queryKey:['discovery-center',query.toString()],queryFn:({signal})=>request<Page>(`/discovery/devices?${query}`,{signal}),enabled:position.ready,refetchInterval:autoRefresh?60_000:false,refetchOnWindowFocus:autoRefresh})
  const catalogue=useQuery({queryKey:['discovery-types'],queryFn:({signal})=>request<Catalogue>('/discovery/types',{signal})})
  const coverage=useQuery({queryKey:['discovery-coverage'],queryFn:({signal})=>request<Coverage>('/discovery/coverage',{signal})})
  const statistics=useQuery({queryKey:['discovery-statistics'],queryFn:({signal})=>request<Statistics>('/discovery/statistics',{signal}),enabled:coverage.data?.enabled===true})
  const metadataQuery=new URLSearchParams(query);metadataQuery.delete('cursor');metadataQuery.delete('limit')
  const discoveryMetadata=useQuery({queryKey:['discovery-metadata',metadataQuery.toString()],queryFn:({signal})=>request<components['schemas']['DiscoveryDeviceMetadata']>(`/discovery/devices/metadata?${metadataQuery}`,{signal}),refetchInterval:autoRefresh?60_000:false,refetchOnWindowFocus:autoRefresh})
  const hardwareV2=discoveryMetadata.data?.classification_version==='passive-hardware/v2'
  const viewStates=hardwareV2?{...states,identified:'已知硬件类型',expired:'硬件结论已撤销'}:states
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
  const fingerprintDetail=useQuery({queryKey:['discovery-fingerprints',selected?.endpoint_id],queryFn:({signal})=>request<InventoryDetail>(`/device-inventory/${encodeURIComponent(selected!.endpoint_id!)}`,{signal}),enabled:!!selected?.endpoint_id,staleTime:60_000})
  const types=Object.fromEntries((catalogue.data?.items??[]).map(t=>[t.id,t.label]))
  const items:Device[]=devices.data?.items??[]
  const typedPageCount=items.filter(item=>!!confirmedDeviceType(item)).length
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
  const osFor=(item:Device)=>{const signal=signalFor(item);const client=clientFor(item);const base=signal?.os_family||item.recognition?.os_family;const ipFamily=item.mac?'':client?.os_family;const conflict=signal?.os_conflict||(!item.mac&&client?.os_conflict)||(base&&ipFamily&&base!==ipFamily);const detail=[signal?.os_evidence,item.recognition?.os_family?`识别：${item.recognition.rule_version||'规则'}${item.recognition.os_family_confidence?`（${Math.round(item.recognition.os_family_confidence*100)}%）`:''}`:'',!item.mac&&client?.os_evidence?`${client.os_evidence}；仅按 IP 关联，需核对地址归属`:'' ].filter(Boolean).join('；');if(conflict)return {label:'线索冲突',detail,ipOnly:false};return {label:base||ipFamily||signal?.os_hint||'',detail:detail||(signal?.ttl?`TTL ${signal.ttl}`:''),ipOnly:!base&&!!ipFamily}}
  const hardwareFresh=devices.data?.hardware_freshness
  const fresh=devices.data?.freshness
  const dumbFilter=params.get('discovery_capability')==='dumb'
  const recentPageCount=(devices.data?.items??[]).filter(item=>Date.now()-new Date(item.last_seen).getTime()<=15*60*1000).length
  const identity=(item:Device)=>{
    const type=item.hardware_type_status?confirmedDeviceType(item):['conflict','expired'].includes(item.classification_status??'')?'':item.device_type||((item.recognition?.confidence??0)>=.8?item.recognition?.device_type:'')
    return <div className="terminal-identity"><DiscoveryDeviceIcon type={type} capabilities={item.capabilities}/><div><Button type="link" className="terminal-device-link" onClick={()=>show(item)}>{item.name||typeLabel(item,types)||item.mac||item.primary_ip}</Button>{item.mac&&<span className="terminal-mac">{item.mac}{isRandomizedMAC(item.mac)?' · 随机':''}</span>}{item.name&&typeLabel(item,types)&&<span className="terminal-kind-caption">{typeLabel(item,types)}</span>}{discoveryNameClue(item.name)&&<Typography.Text type="secondary" className="terminal-kind-caption" title={discoveryNameClue(item.name)?.detail}>{discoveryNameClue(item.name)?.label}</Typography.Text>}</div></div>
  }
  const kind=(item:Device)=>{const label=typeLabel(item,types);return label?<Typography.Text strong={!!confirmedDeviceType(item)} title={item.type_evidence_at?`类型依据于 ${observedTimeTitle(item.type_evidence_at)}`:item.last_product_at&&item.classification_status==='candidate'?`型号自报于 ${observedTimeTitle(item.last_product_at)}；当前类型证据已过期`:undefined}>{label}</Typography.Text>:null}
  const vendor=(item:Device)=>{const brand=item.manufacturer||((item.recognition?.confidence??0)>=.8?item.recognition?.brand:'');return <div className="terminal-vendor">{brand&&(resolveDeviceBrand({brand}).key!=='unknown'?<BrandLogo brandKey={brand}/>:<Typography.Text>{brand}</Typography.Text>)}{(item.hardware_type_status?item.hardware_model:item.model_name)&&<Typography.Text type="secondary">{item.hardware_type_status?item.hardware_model:item.model_name}</Typography.Text>}</div>}
  const location=(item:Device)=><Space orientation="vertical" size={0}><Typography.Text>{item.vlan?`VLAN ${item.vlan}`:item.domain}</Typography.Text><Typography.Text type="secondary">{item.vlan?[item.domain,item.sensor_id].filter(Boolean).join(' · '):item.sensor_id}</Typography.Text></Space>
  const servicesFor=(item:Device)=>{const list=serviceClues.data?.items?.[`${item.sensor_id}|${(item.mac||'').toLowerCase()}`]??[];const seen=new Set<string>();return list.filter(clue=>{if(!serviceBelongsToDevice(item,clue))return false;const key=`${clue.service_type}:${clue.port}`;if(seen.has(key))return false;seen.add(key);return true})}
  const portsFor=(item:Device)=>{const seen=new Set<string>();return (portReadEnabled?observedPorts.data?.items?.[detailFlowTarget]??[]:[]).filter(clue=>{if(!flowBelongsToDevice(item,clue))return false;const key=`${clue.proto}:${clue.dst_port}`;if(seen.has(key))return false;seen.add(key);return true}).slice(0,8)}
  const portLabel=(clue:ObservedPort)=>clue.connection_outcome==='syn_ack_observed'?`见 TCP SYN-ACK ${clue.dst_port}`:`尝试连接 ${clue.proto.toUpperCase()} ${clue.dst_port}`
  const clues=(item:Device)=><Space wrap>{(item.capabilities??[]).filter(c=>capabilities[c]).map(c=><Tag key={c}>{capabilities[c]}</Tag>)}{(item.protocols??[]).map(p=><Tag key={p}>{protocols[p]??p}</Tag>)}</Space>
  const state=(item:Device)=><Space orientation="vertical" size={0}>{item.hardware_type_status?<><Typography.Text type={item.hardware_type_status==='conflict'?'warning':'secondary'}>{hardwareStates[item.hardware_type_status]}</Typography.Text>{item.activity_status&&<Typography.Text type="secondary">{activityStates[item.activity_status]}</Typography.Text>}{item.type_evidence_at&&<Typography.Text type="secondary" title={observedTimeTitle(item.type_evidence_at)}>类型依据 {observedTimeLabel(item.type_evidence_at)}</Typography.Text>}{item.hardware_model_status==='conflict'&&<Typography.Text type="warning">型号证据冲突</Typography.Text>}</>:<><Typography.Text type={item.classification_status==='conflict'?'warning':'secondary'}>{item.classification_status==='candidate'&&!typeLabel(item,types)?((item.protocols??[]).every(p=>p==='arp'||p==='ndp')&&item.protocols?.length?(item.protocols.includes('arp')?'ARP 地址候选':'NDP 地址线索'):'缺少类型证据'):states[item.classification_status??'']??(item.current?'证据有效':'证据已过期')}</Typography.Text></>}{item.review_reason&&<Typography.Text type="secondary" title={item.review_observed_at?observedTimeTitle(item.review_observed_at):undefined}>{reviewReasons[item.review_reason]??item.review_reason}{item.review_observed_at?` · ${observedTimeLabel(item.review_observed_at)}`:''}</Typography.Text>}</Space>
  const refreshDiscovery=()=>{const first=new URLSearchParams(query);first.delete('cursor');setPaging({key:filterKey,page:0});void position.invalidate();void discoveryMetadata.refetch();void coverage.refetch();void statistics.refetch();void queryClient.invalidateQueries({queryKey:['discovery-center'],refetchType:'none'});void queryClient.refetchQueries({queryKey:['discovery-center',first.toString()],exact:true})}
  const refreshWorkspace=()=>refreshDiscovery()
  const selectedPosition=selected?items.findIndex(item=>item.id===selected.id):-1
  const [exporting,setExporting]=useState(false)
  const [exportProgress,setExportProgress]=useState({count:0,total:0})
  const exportDevices=async()=>{
    setExporting(true)
    setExportProgress({count:0,total:0})
    try{
      const {items:devices,snapshotAt}=await fetchDiscoveryExport<Device>(query,(count,total)=>setExportProgress({count,total}),discoveryTableRowKey)
      const blob=new Blob(['\ufeff'+discoveryCSV(devices,types)],{type:'text/csv;charset=utf-8'})
      const url=URL.createObjectURL(blob)
      const anchor=document.createElement('a')
      anchor.href=url
      anchor.download=`discovery-${new Date().toISOString().slice(0,10)}.csv`
      anchor.click()
      URL.revokeObjectURL(url)
      message.success(`已导出当前筛选的全部 ${devices.length} 台设备${snapshotAt?` · 快照 ${observedTimeTitle(snapshotAt)}`:''}`)
    }catch(error){
      message.error(`导出失败：${error instanceof Error?error.message:String(error)}`)
    }finally{
      setExporting(false)
      setExportProgress({count:0,total:0})
    }
  }
  const exportQualityReport=()=>{
    if(!quality.data)return
    const blob=new Blob(['\ufeff'+qualityReportCSV(quality.data,trends.data,types)],{type:'text/csv;charset=utf-8'})
    const url=URL.createObjectURL(blob)
    const anchor=document.createElement('a')
    anchor.href=url
    anchor.download=`discovery-quality-${new Date().toISOString().slice(0,10)}.csv`
    anchor.click()
    URL.revokeObjectURL(url)
  }
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
    <CensusPanel/>
    {discoveryMetadata.isError&&<AppErrorAlert title="读取发现数量失败" message={discoveryMetadata.error.message} action={<Button onClick={()=>void discoveryMetadata.refetch()}>重试统计</Button>}/>}
    {position.isError&&<AppErrorAlert title="页码定位失败" message={position.error.message} action={<Button onClick={()=>void position.refetch()}>重试定位</Button>}/>}
    {devices.isError&&<AppErrorAlert title="读取发现设备失败" message={devices.data?'当前展示上次成功读取的结果；请重试。':devices.error.message} action={<Button onClick={()=>void devices.refetch()}>重试列表</Button>}/>}
    {(!devices.isError||devices.data)&&<section aria-busy={searching} className={searching?'surface center-list-surface is-updating':'surface center-list-surface'}>
      <div className="list-surface-head">
      <AppTableBar
        searchPlaceholder="搜索 IP、MAC、名称或型号"
        searching={searching}
        searchValue={draft}
        onSearchChange={setDraft}
        onSearch={value=>change('search', value.trim())}
        filters={<>
          <Select aria-label="设备类型" mode="multiple" allowClear placeholder="全部设备类型" showSearch optionFilterProp="label" value={(params.get('discovery_type')||'').split(',').filter(Boolean)} options={(catalogue.data?.items??[]).map(t=>({value:t.id,label:t.label}))} onChange={values=>setParams(current=>{const next=new URLSearchParams(current);if(values.length)next.set('discovery_type',values.join(','));else next.delete('discovery_type');next.delete('discovery_category');return next},{replace:true})}/>
          <Select aria-label="证据状态" value={params.get('discovery_state')||''} options={[{value:'',label:'全部证据状态'},{value:'identified,candidate,conflict',label:'当前有效（不含过期）'},...Object.entries(viewStates).filter(([k])=>view!=='iot'||k!=='candidate').map(([value,label])=>({value,label}))]} onChange={v=>change('state',v)}/>
          <Select aria-label="待核实原因" value={params.get('discovery_review_reason')||''} options={[{value:'',label:'全部核实原因'},...Object.entries(reviewReasons).map(([value,label])=>({value,label}))]} onChange={v=>change('review_reason',v)}/>
          <Button size="small" type="text" onClick={()=>setMoreOpen(value=>!value)}>{moreOpen?'收起筛选':'更多筛选'}{['category','type','protocol','window','domain','vlan','random_mac','os'].filter(key=>params.get(`discovery_${key}`)).length?`（${['category','type','protocol','window','domain','vlan','random_mac','os'].filter(key=>params.get(`discovery_${key}`)).length}）`:''}</Button>
        </>}
        extra={<div className="discovery-list-actions"><span className="discovery-auto-refresh"><Switch size="small" aria-label="自动刷新" checked={autoRefresh} onChange={toggleAutoRefresh}/><Typography.Text type="secondary">自动刷新</Typography.Text></span>{searching&&<span className="discovery-search-status" role="status" aria-live="polite"><LoadingOutlined aria-hidden="true" spin /> {draft.trim()||search?'正在搜索…':'正在加载…'}</span>}<span className="terminal-page-summary" aria-label="发现设备摘要"><span>当前页 <strong>{items.length}</strong> 个设备</span><span>本页明确类型 <strong>{typedPageCount}</strong></span><span>本页近15分钟观测 <strong>{recentPageCount}</strong></span></span><Button size="small" icon={<DownloadOutlined aria-hidden="true"/>} loading={exporting} onClick={()=>void exportDevices()}>{exporting?`导出中 ${exportProgress.count}/${exportProgress.total||'…'}`:'导出全部筛选结果'}</Button><Button type="link" size="small" onClick={()=>setParams(current=>{const next=new URLSearchParams(current);for(const key of [...next.keys()])if(key.startsWith("discovery_")&&key!=="discovery_view")next.delete(key);return next})}>清除筛选</Button></div>}
      panel={moreOpen?<div className="app-filter-panel">
          <Select aria-label="设备分类" value={params.get('discovery_category')||''} options={[{value:'',label:'全部设备分类'},...Object.entries(categories).map(([value,label])=>({value,label}))]} onChange={v=>setParams(current=>{const next=new URLSearchParams(current);next.delete('discovery_type');if(v)next.set('discovery_category',v);else next.delete('discovery_category');return next},{replace:true})}/>
          <Select aria-label="发现协议" mode="multiple" allowClear placeholder="全部协议" value={(params.get('discovery_protocol')||'').split(',').filter(Boolean)} options={Object.entries(protocols).map(([value,label])=>({value,label}))} onChange={values=>setParams(current=>{const next=new URLSearchParams(current);if(values.length)next.set('discovery_protocol',values.join(','));else next.delete('discovery_protocol');return next},{replace:true})}/>
          <Select aria-label="最近观测范围" value={params.get('discovery_window')==='all'?'720h':params.get('discovery_window')||''} options={[{value:'',label:'近 24 小时'},{value:'15m',label:'近 15 分钟'},{value:'168h',label:'近 7 天'},{value:'720h',label:'近 30 天'}]} onChange={v=>change('window',v)}/>
          <DebouncedInput label="网络域" placeholder="网络域（逗号分隔）" value={params.get('discovery_domain')||''} onChange={value=>change('domain',value)}/>
          <DebouncedInput label="VLAN" placeholder="VLAN（逗号分隔）" value={params.get('discovery_vlan')||''} onChange={value=>change('vlan',value)}/>
          <DebouncedInput label="操作系统" placeholder="操作系统" value={params.get('discovery_os')||''} onChange={value=>change('os',value)}/>
          <Checkbox checked={params.get('discovery_random_mac')==='true'} onChange={e=>change('random_mac',e.target.checked?'true':'')}>随机 MAC</Checkbox>
          <div className="discovery-view-bar">
            <Select aria-label="保存的视图" placeholder="保存的视图" value={activeViewId||undefined} options={views.map(item=>({value:item.id,label:item.name}))} onChange={id=>{const view=views.find(item=>item.id===id);if(view){const next=new URLSearchParams(params);for(const key of [...next.keys()])if(key.startsWith('discovery_'))next.delete(key);for(const [key,value] of new URLSearchParams(view.params))next.set(key,value);setParams(next,{replace:true});setActiveViewId(id)}}} allowClear onClear={()=>setActiveViewId('')}/>
            <Button size="small" onClick={()=>setSaveViewOpen(true)}>保存视图</Button>
            {activeViewId&&<Button type="link" size="small" onClick={()=>{setViews(removeDiscoveryView(globalThis.localStorage,activeViewId));setActiveViewId('');message.success('视图已删除')}}>删除视图</Button>}
            {views.length>0&&<Button type="link" size="small" onClick={()=>setManageViewsOpen(true)}>管理</Button>}
          </div>
        </div>:undefined}
      />
        <nav className="terminal-type-shortcuts" aria-label="快捷设备类型">{[{value:'',label:'全部设备'},{value:'printer',label:'打印机'},{value:'camera',label:'摄像机'},{value:'access_point',label:'无线 AP'},{value:'router',label:'路由器'},{value:'switch',label:'交换机'},{value:'desktop',label:'电脑'},{value:'mobile',label:'手机'},{value:'voip_phone',label:'VoIP 话机'}].map(t=><Button key={t.value} type={(params.get('discovery_type')||'')===t.value&&!dumbFilter?'primary':'default'} onClick={()=>shortcut(t.value)}>{t.label}</Button>)}<Button type={dumbFilter?'primary':'default'} onClick={()=>shortcut('',dumbFilter?'':'dumb')}>哑终端线索</Button></nav>
      </div>
      <div className="discovery-overview-strip" aria-label="发现设备总览" title={`${params.get('discovery_window')==='15m'?'近 15 分钟':params.get('discovery_window')==='168h'?'近 7 天':params.get('discovery_window')==='720h'?'近 30 天':'近 24 小时'} · 按采集范围与可信身份去重${discoveryMetadata.data?.as_of?` · 统计于 ${observedTimeTitle(discoveryMetadata.data.as_of)}`:''}`}>
        <div className="discovery-overview-line">
          <strong>共 {metadataValue(discoveryMetadata.data?.total)} 个设备</strong>
          <Button type="text" size="small" className={`discovery-overview-count${params.get('discovery_state')==='identified'?' is-active':''}`} onClick={()=>toggleState('identified')}>已识别类型 <strong>{metadataValue(discoveryMetadata.data?.identified)}</strong></Button>
          <Button type="text" size="small" className={`discovery-overview-count${params.get('discovery_state')==='candidate'?' is-active':''}`} onClick={()=>toggleState('candidate')}>待核实 <strong>{metadataValue(discoveryMetadata.data?.candidate)}</strong></Button>
          <Button type="text" size="small" className={`discovery-overview-count${params.get('discovery_state')==='conflict'?' is-active':''}`} onClick={()=>toggleState('conflict')}>类型冲突 <strong>{metadataValue(discoveryMetadata.data?.conflict)}</strong></Button>
          <Button type="text" size="small" className={`discovery-overview-count${params.get('discovery_state')==='expired'?' is-active':''}`} onClick={()=>toggleState('expired')}>{hardwareV2?'硬件结论已撤销':'证据过期'} <strong>{metadataValue(discoveryMetadata.data?.expired)}</strong></Button>{fresh?.status==='ready'&&<Typography.Text type="secondary" className="discovery-freshness">{fresh.lag_seconds<60?'数据实时':`数据延迟 ${Math.round(fresh.lag_seconds/60)} 分钟`}</Typography.Text>}
          <Typography.Text className="discovery-overview-caption" type="secondary">{params.get('discovery_window')==='168h'?'近 7 天':params.get('discovery_window')==='720h'?'近 30 天':'近 24 小时'} · 按采集范围与可信身份去重{discoveryMetadata.data?.as_of?` · 统计于 ${observedTimeTitle(discoveryMetadata.data.as_of)}`:''}{discoveryMetadata.isFetching?' · 统计更新中':''}</Typography.Text>
        </div>
        {hardwareFresh&&<div className="discovery-hardware-progress" aria-label="硬件分类处理进度"><Typography.Text type={hardwareFresh.status==='failed'?'warning':'secondary'}>{hardwareFresh.status==='failed'?`硬件分类处理异常：${hardwareFresh.error||'处理状态读取失败'}`:<>硬件分类{hardwareFresh.coverage==='live_input_only'?'仅含启用后输入':hardwareFresh.backfill_complete?'保留观测回填完成':'保留观测回填中'}{hardwareFresh.available_from?` · 可用起点 ${observedTimeTitle(hardwareFresh.available_from)}`:''} · 待处理 {hardwareFresh.pending_identities??0} · 处理失败 {hardwareFresh.failed_identities??0}{hardwareFresh.oldest_pending_at?` · 最早积压 ${observedTimeTitle(hardwareFresh.oldest_pending_at)}`:''}{hardwareFresh.missing_source_refs?` · 缺少原文引用 ${hardwareFresh.missing_source_refs}`:''}{hardwareFresh.changed_after_backfill_start?` · 回填窗口被新观测替换 ${hardwareFresh.changed_after_backfill_start}`:''}</>}</Typography.Text></div>}
        {fresh?.source==='passive-discovery-batch-v3'&&<div className="discovery-batch-progress" aria-label="存储处理进度">
          {fresh.ingested_at&&<Typography.Text type="secondary">采集入库 {observedTimeTitle(fresh.ingested_at)}</Typography.Text>}
          {fresh.processed_at&&<Typography.Text type="secondary">设备发现 {observedTimeTitle(fresh.processed_at)}</Typography.Text>}
          {fresh.pending_batches!==undefined&&<Typography.Text type="secondary">待发现批次 {fresh.pending_batches}</Typography.Text>}
          {fresh.archive_verified_at&&<Typography.Text type="secondary">证据归档 {observedTimeTitle(fresh.archive_verified_at)}</Typography.Text>}
          {fresh.archive_pending_batches!==undefined&&<Typography.Text type="secondary">待归档批次 {fresh.archive_pending_batches}</Typography.Text>}
          {fresh.archive_oldest_pending_at&&<Typography.Text type="secondary">最早待归档 {observedTimeTitle(fresh.archive_oldest_pending_at)}</Typography.Text>}
        </div>}
        <div className="discovery-overview-types"><Typography.Text type="secondary">已识别类型{discoveryMetadata.data?`（合计 ${discoveryMetadata.data.types.reduce((sum,item)=>sum+item.count,0)}）`:''}</Typography.Text>{discoveryMetadata.data?.types.length?[...discoveryMetadata.data.types].sort((a,b)=>b.count-a.count||a.device_type.localeCompare(b.device_type)).map(item=><Button key={item.device_type} type="text" size="small" className="discovery-overview-type" onClick={()=>shortcut(item.device_type,'','identified')}>{types[item.device_type]??deviceTypeLabel(item.device_type)} <strong>{item.count}</strong></Button>):<Typography.Text type="secondary">{discoveryMetadata.data?'当前筛选下暂无已识别类型':discoveryMetadata.isError?'统计读取失败':'统计中'}</Typography.Text>}</div>
      </div>
      <AppTable className="passive-ledger-table" rowKey={discoveryTableRowKey} columns={columns} dataSource={items} tableLayout="fixed" loading={{spinning:listUpdating,delay:150}} scroll={{x:1125}} locale={{emptyText:listUpdating?'正在加载设备…':'当前筛选下暂无符合条件的设备'}}/>
      <AppServerPagination disabled={devices.isFetching||position.isLocating} page={page+1} pageSize={pageSize} total={discoveryMetadata.data?.total} onChange={(nextPage,nextSize)=>{
        if(nextSize!==pageSize){setPageSize(nextSize);setPaging({key:filterKey,page:0});return}
        setPaging({key:filterKey,page:nextPage-1})
      }} totalText={discoveryMetadata.data?`共 ${discoveryMetadata.data.total} 个设备`:(discoveryMetadata.isError?'数量读取失败':'正在统计数量')} />
    </section>}
    <details className="terminal-diagnostics" open={qualityOpen}><summary onClick={event=>{event.preventDefault();setQualityOpen(value=>!value)}}>采集与识别状态</summary>    <section className="surface center-list-toolbar">
      {qualityOpen&&<div className="recognition-quality-strip" aria-label="识别质量">
        <Typography.Text type="secondary" className="recognition-quality-scope">全局识别画像 · 不随列表筛选变化</Typography.Text>
        {quality.isError&&<AppErrorAlert title="识别质量读取失败" message={quality.error.message} />}
        {quality.data&&<>
          {qualityItem('类型覆盖',quality.data.coverage.device_type,quality.data.total_endpoints)}
          {qualityItem('品牌覆盖',quality.data.coverage.brand,quality.data.total_endpoints)}
          {qualityItem('型号覆盖',quality.data.coverage.model,quality.data.total_endpoints)}
          {qualityItem('系统覆盖',quality.data.coverage.os_family,quality.data.total_endpoints)}
          <span className="recognition-quality-item"><Typography.Text type="secondary">链路层归属</Typography.Text><Typography.Text strong>{Math.round((quality.data.mac_attribution_rate??0)*100)}%</Typography.Text></span>
          {quality.data.top_brands?.length?<span className="recognition-quality-brands"><Typography.Text type="secondary">厂商 Top</Typography.Text>{quality.data.top_brands.map(item=><Button key={item.brand} type="text" size="small" className="recognition-quality-link" onClick={()=>change('search',item.brand)}>{item.brand} {item.count}</Button>)}</span>:null}
          {quality.data.top_type_brands?.length?<span className="recognition-quality-brands"><Typography.Text type="secondary">类型厂商</Typography.Text>{quality.data.top_type_brands.map(item=><Button key={`${item.device_type}:${item.brand}`} type="text" size="small" className="recognition-quality-link" onClick={()=>setParams(current=>{const next=new URLSearchParams(current);next.set('discovery_search',item.brand);next.set('discovery_type',item.device_type);next.delete('discovery_category');return next},{replace:true})}>{types[item.device_type]??deviceTypeLabel(item.device_type)} · {item.brand} {item.count}</Button>)}</span>:null}
          {quality.data.top_os?.length?<span className="recognition-quality-brands"><Typography.Text type="secondary">系统 Top</Typography.Text>{quality.data.top_os.map(item=><Button key={item.os} type="text" size="small" className="recognition-quality-link" onClick={()=>change('os',item.os)}>{item.os} {item.count}</Button>)}</span>:null}
          {quality.data.top_models?.length?<span className="recognition-quality-brands"><Typography.Text type="secondary">型号 Top</Typography.Text>{quality.data.top_models.map(item=><Button key={`${item.brand}:${item.model}`} type="text" size="small" className="recognition-quality-link" onClick={()=>setParams(current=>{const next=new URLSearchParams(current);next.set('discovery_search',item.model);next.delete('discovery_type');next.delete('discovery_category');return next},{replace:true})}>{item.brand?`${item.brand} · `:''}{item.model} {item.count}</Button>)}</span>:null}
          {quality.data.untyped_reasons?.length?<span className="recognition-quality-brands"><Typography.Text type="secondary">未识别原因</Typography.Text>{quality.data.untyped_reasons.map(item=><Tag key={item.reason}>{item.reason} {item.count}</Tag>)}</span>:null}
          <div className="recognition-quality-actions"><Button size="small" icon={<DownloadOutlined aria-hidden="true"/>} onClick={exportQualityReport} disabled={!quality.data}>导出质量报告</Button></div>
          {trends.data?.days?.length?<span className="discovery-trend" aria-label={`近 ${trendDays} 天新增设备`}><Typography.Text type="secondary">近 {trendDays} 天新增</Typography.Text><span className={`discovery-trend-bars${trendDays>7?' is-wide':''}`}>{trends.data.days.map(day=><span key={day.date} className={`discovery-trend-bar is-${trendBucket(day.new,Math.max(...trends.data.days.map(item=>item.new),1))}`} title={`${day.date} 新增 ${day.new}，明确类型 ${day.typed}`}/>)}</span><Typography.Text type="secondary">{trends.data.days.reduce((sum,day)=>sum+day.new,0)} 台 · 今天 {trends.data.days[trends.data.days.length-1]?.new??0}</Typography.Text><Select size="small" aria-label="趋势范围" value={String(trendDays)} options={[{value:'7',label:'近 7 天'},{value:'30',label:'近 30 天'}]} onChange={value=>setTrendDays(Number(value))}/></span>:null}
          {trends.data?.top_types?.length?<span className="recognition-quality-brands"><Typography.Text type="secondary">新增类型</Typography.Text>{trends.data.top_types.map(item=><Button key={item.device_type} type="text" size="small" className="recognition-quality-link" onClick={()=>shortcut(item.device_type)}>{types[item.device_type]??deviceTypeLabel(item.device_type)} {item.count}</Button>)}</span>:null}
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
      {statistics.data&&!hardwareV2&&<div className="discovery-statistics" aria-label="设备类型统计">{statistics.data.items.filter(item=>item.count>0&&item.state!=='candidate').map(item=><span className="discovery-statistics-item" title={`统计更新于 ${observedTimeTitle(item.updated_at)}`} key={`${item.device_type}:${item.state}`}>{types[item.device_type]??item.device_type} · {states[item.state]??''} {item.count}</span>)}{statistics.data.pending_updates>0&&<Typography.Text type="secondary">统计处理中 {statistics.data.pending_updates}</Typography.Text>}</div>}
      <Collapse ghost items={[{key:'coverage',label:'采集覆盖与处理状态',children:coverage.isError?<AppErrorAlert title="读取采集状态失败" />:coverage.data?.enabled===false?<Typography.Text>当前运行旧版发现路径</Typography.Text>:<div className="iot-coverage-grid">{coverage.data?.items.map(p=><article className="iot-coverage-item" key={`${p.sensor_id}:${p.protocol}`}><strong>{protocols[p.protocol]??p.protocol}</strong><Typography.Text type="secondary">{p.sensor_id}</Typography.Text><span>{p.message_source_epoch?'逐消息源已登记':p.handshake_source_epoch?'握手侧车已登记 · 详情弱线索':p.error?'采集异常':!p.enabled?'未启用':p.received===0?'暂未捕获协议流量':'已捕获协议流量'}</span><span>{p.message_source_epoch?'旧链路累计 ':p.handshake_source_epoch?'发现链路累计 ':''}捕获 {p.received} · 解析 {p.parsed} · 处理 {p.admitted}</span></article>)}</div>}]} />
    </section>
</details>
    <Modal title="管理视图" open={manageViewsOpen} footer={null} onCancel={()=>setManageViewsOpen(false)}>{views.length?views.map(view=><div key={view.id} className="discovery-view-manage-row"><Typography.Text>{view.name}</Typography.Text><Button type="link" size="small" danger onClick={()=>deleteSavedView(view.id)}>删除</Button></div>):<Typography.Text type="secondary">还没有保存的视图</Typography.Text>}</Modal>
    <Modal title="保存视图" open={saveViewOpen} okText="保存" cancelText="取消" onOk={saveCurrentView} onCancel={()=>{setSaveViewOpen(false);setViewName('')}}><Input aria-label="视图名称" placeholder="例如：网络设备 · 近 7 天" value={viewName} onChange={e=>setViewName(e.target.value)}/><Typography.Paragraph type="secondary">保存当前筛选条件，仅存储在本机浏览器。</Typography.Paragraph></Modal>
    <Modal className="discovery-evidence-modal" title="设备详情" open={!!selected} footer={selected?<div className="discovery-detail-nav"><Typography.Text type="secondary">{selectedPosition+1} / {items.length}</Typography.Text><Button disabled={selectedPosition<=0} onClick={()=>setSelected(items[selectedPosition-1])}>上一台</Button><Button disabled={selectedPosition<0||selectedPosition>=items.length-1} onClick={()=>setSelected(items[selectedPosition+1])}>下一台</Button></div>:null} onCancel={()=>setSelected(undefined)}>{selected&&<><div className="discovery-detail-identity">{identity(selected)}{kind(selected)}{selected.endpoint_id&&<Button type="link" size="small" className="discovery-detail-profile-link" onClick={()=>{setSelected(undefined);navigate(`/devices/${encodeURIComponent(selected.endpoint_id!)}`)}}>查看终端画像</Button>}</div><dl className="discovery-detail-facts">{[[`硬件类型状态`,hardwareStates[selected.hardware_type_status??'']],[`类型依据时间`,selected.type_evidence_at?observedTimeTitle(selected.type_evidence_at):''],[`活动状态`,activityStates[selected.activity_status??'']],[`硬件规则版本`,selected.type_rule_version],[`型号状态`,selected.hardware_model_status==='conflict'?'型号证据冲突':''],[`互斥类型`,(selected.hardware_conflicting_types??[]).map(type=>types[type]??deviceTypeLabel(type)).join('、')],[`型号冲突项`,(selected.hardware_conflicting_models??[]).join('、')],[`设备类型`,conclusionTypeLabel(selected,types)],[`设备分类`,selected.category?categories[selected.category]??selected.category:''],[`分类状态说明`,discoveryClassificationExplanation(selected)],[`名称线索`,discoveryNameClue(selected.name)?.label],[`名称线索依据`,discoveryNameClue(selected.name)?.detail],[`分类补充线索`,secondaryTypeClue(selected,types,signalFor(selected))],[`操作系统线索`,osFor(selected).label?`${osFor(selected).label} · ${signalFor(selected)?.dhcp_historical&&signalFor(selected)?.os_family?'历史线索':'线索'}`:''],[`操作系统依据`,osFor(selected).detail],[`DHCP 线索时效`,signalFor(selected)?.dhcp_historical?'历史 REQUEST 线索；同源当前租约仍有效，需结合观测时间核对':''],[`DHCP 观测时间`,signalFor(selected)?.dhcp_observed_at?observedTimeTitle(signalFor(selected)!.dhcp_observed_at!):''],[`最近 DHCP 证据事件`,signalFor(selected)?.dhcp_evidence_id],[`TTL 证据引用`,signalFor(selected)?.ttl_evidence?.event_id||((signalFor(selected)?.ttl_evidence?.raw_sha256)?`原文 SHA256 ${signalFor(selected)?.ttl_evidence?.raw_sha256}`:'')],[`TTL 观测时间`,signalFor(selected)?.ttl_observed_at?observedTimeTitle(signalFor(selected)!.ttl_observed_at!):''],[`TTL`,signalFor(selected)?.ttl?String(signalFor(selected)?.ttl):''],[`DHCP 主机名`,signalFor(selected)?.dhcp_hostname],[`DHCP 厂商类`,signalFor(selected)?.dhcp_vendor_class],[`DHCP 请求选项`,signalFor(selected)?.dhcp_options],[`DHCP 客户端标识类型`,signalFor(selected)?.dhcp_client_id_hwtype],[`DHCP 选项 93`,signalFor(selected)?.dhcp_option93_present?'已观测':''],[`识别操作系统`,recognitionOSLabel(selected)],[`识别设备类型`,recognitionTypeLabel(selected,types)],[`类型置信度`,selected.recognition?.confidence?`${Math.round(selected.recognition.confidence*100)}%`:''],[`系统置信度`,selected.recognition?.os_family&&selected.recognition?.os_family_confidence?`${Math.round(selected.recognition.os_family_confidence*100)}%`:''],[`识别规则`,selected.recognition?.rule_version],[`识别依据`,(selected.recognition?.evidence??[]).join('；')],[`品牌推断`,selected.recognition?.brand_inference_status==='inferred'&&selected.recognition?.brand_inference_brand?`${selected.recognition.brand_inference_brand} · 设备服务线索推断${selected.recognition.brand_inference_confidence?`（${Math.round(selected.recognition.brand_inference_confidence*100)}%）`:''}`:''],[`制造商`,selected.manufacturer],[`型号`,selected.hardware_type_status?selected.hardware_model:selected.model_name],[`MAC`,selected.mac],[`MAC 类型`,selected.mac?(isRandomizedMAC(selected.mac)?'随机（地址可能轮换）':'固定'):''],[`当前地址`,(selected.current_addresses??[]).join('、')||selected.primary_ip],[`最后观测地址`,selected.last_observed_ip],[`网络域`,selected.domain],[`VLAN`,selected.vlan],[`采集传感器`,selected.sensor_id],[`窗口内首次观测`,selected.first_seen?observedTimeTitle(selected.first_seen):''],[`最近观测`,observedTimeTitle(selected.last_seen)],[`证据数`,selected.evidence_count?String(selected.evidence_count):'']].filter(([,value])=>value).map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>{dhcpFieldEvidenceFor(signalFor(selected)).length>0&&<section className="discovery-client-clues"><Typography.Text type="secondary">DHCP 字段证据（各字段保留对应原始报文引用）</Typography.Text>{dhcpFieldEvidenceFor(signalFor(selected)).map(entry=><article key={entry.field}><strong>{entry.label}</strong><span>{entry.value}</span><Typography.Text type="secondary">{[entry.ref.event_id?`事件 ${entry.ref.event_id}`:entry.ref.raw_sha256?`原文 SHA256 ${entry.ref.raw_sha256}`:'',entry.ref.historical?'历史线索':'',observedTimeTitle(entry.ref.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}{selected?.endpoint_id&&fingerprintDetail.data?.profile?.recognition?.source_matches?.length?<section className="discovery-client-clues"><Typography.Text type="secondary">指纹库命中（端点识别）</Typography.Text>{fingerprintDetail.data.profile.recognition.source_matches.slice(0,6).map(m=><article key={`${m.source_id}:${m.rule_id}`}><strong>{m.name}</strong><span>{m.strength==='auxiliary'?'辅助线索':'自报证据'} · {m.source_id}</span><Typography.Text type="secondary">{[m.fields.join('、'),Object.values(m.observed??{}).join('；')].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>:null}{clientFor(selected)?.client_clues?.length&&<section className="discovery-client-clues"><Typography.Text type="secondary">HTTP / TLS 客户端弱线索（仅按当前 IP 关联，地址共享或复用时需核对）</Typography.Text>{clientFor(selected)?.client_clues?.map((clue,index)=><article key={`${clue.kind}:${clue.evidence_id}:${index}`}><strong>{clue.kind==='user_agent'?'HTTP User-Agent':clue.kind.toUpperCase()}</strong><span>{clue.value}</span><Typography.Text type="secondary">{[clue.evidence_id,observedTimeTitle(clue.observed_at)].filter(Boolean).join(' · ')}</Typography.Text></article>)}</section>}<Typography.Paragraph>{selected.classification?.reason}</Typography.Paragraph>{selected.type_sources?.length?<section className="discovery-hardware-evidence" aria-label="硬件类型证据"><Typography.Title level={5}>硬件类型证据</Typography.Title><Typography.Paragraph type="secondary">类型保留已确认的硬件事实；服务公告和地址绑定的有效期单独判断。</Typography.Paragraph>{selected.type_sources.map(source=><article key={`${source.source}:${source.rule_id}:${source.evidence_id}`}><strong>{protocols[source.source]??source.source}</strong><span>{source.rule_id} · {source.rule_version}</span><span>{source.evidence_id}</span><time>{observedTimeTitle(source.observed_at)}</time></article>)}</section>:null}<DiscoveryEvidenceSummary observations={selected.observations}/>
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
