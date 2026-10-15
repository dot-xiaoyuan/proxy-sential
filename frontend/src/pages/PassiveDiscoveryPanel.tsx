import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Collapse, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { DeviceAddress } from '../entities/device/DeviceAddress'
import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'

type Device = components['schemas']['DiscoveryDevice']
type Page = components['schemas']['DiscoveryDevicePage']
type Coverage = components['schemas']['DiscoveryCoverage']
type Statistics = components['schemas']['DiscoveryStatistics']
type Catalogue = components['schemas']['DiscoveryTypeCatalogue']
type History = components['schemas']['DiscoveryHistoryPage']
const protocols: Record<string,string> = { dhcp:'DHCP', dhcpv6:'DHCPv6', dns_sd:'DNS-SD', ssdp:'SSDP', ws_discovery:'WS-Discovery', arp:'ARP', ndp:'NDP', ieee1905_client:'IEEE 1905', ieee1905_client_association:'IEEE 1905', lldp:'LLDP', cdp:'CDP', snmp:'SNMP', ipp:'IPP', onvif:'ONVIF', nbns:'NBNS', llmnr:'LLMNR', bacnet:'BACnet/IP', coap:'CoAP', mqtt:'MQTT', http:'HTTP', tls:'TLS', rtsp:'RTSP', fdb:'交换机 MAC 表', neighbor:'邻居表', active:'探测响应' }
const capabilities: Record<string,string> = { printing:'打印', scanning:'扫描', casting:'投屏', network_video:'网络视频', media_rendering:'媒体播放' }
const states: Record<string,string> = { identified:'证据有效', expired:'证据已过期', conflict:'类型证据冲突', candidate:'发现线索' }

export function PassiveDiscoveryPanel({view}:{view:'iot'|'records'}) {
  const [params,setParams] = useSearchParams()
  const search = params.get('discovery_search') || ''
  const [draft,setDraft] = useState(search)
  const filterKey = [view,search,...['category','type','protocol','state','domain','vlan','window'].map(k=>params.get(`discovery_${k}`)||'')].join('|')
  const [paging,setPaging] = useState({key:filterKey,cursors:[''],page:0})
  const cursors=paging.key===filterKey?paging.cursors:['']
  const page=paging.key===filterKey?paging.page:0
  const [selected,setSelected] = useState<Device>()
  const [historyCursor,setHistoryCursor] = useState('')
  useEffect(()=>setDraft(search),[search])
  const change = (key:string,value:string) => {
    setParams(current=>{const next=new URLSearchParams(current);if(value)next.set(`discovery_${key}`,value);else next.delete(`discovery_${key}`);if(key==='type')next.delete('discovery_category');return next},{replace:true})
  }
  const query = new URLSearchParams({mode:'passive',limit:'20'})
  if(view==='iot')query.set('view','iot')
  if(search)query.set('search',search)
  for(const key of ['category','type','protocol','state','domain','vlan','window']){const value=params.get(`discovery_${key}`);if(value)query.set(key,value)}
  if(cursors[page])query.set('cursor',cursors[page])
  const devices = useQuery({queryKey:['discovery-center',query.toString()],queryFn:({signal})=>request<Page>(`/discovery/devices?${query}`,{signal}),refetchInterval:5000})
  const catalogue=useQuery({queryKey:['discovery-types'],queryFn:({signal})=>request<Catalogue>('/discovery/types',{signal})})
  const coverage=useQuery({queryKey:['discovery-coverage'],queryFn:({signal})=>request<Coverage>('/discovery/coverage',{signal}),refetchInterval:10000})
  const statistics=useQuery({queryKey:['discovery-statistics'],queryFn:({signal})=>request<Statistics>('/discovery/statistics',{signal}),refetchInterval:10000,enabled:coverage.data?.enabled===true})
  const history=useQuery({queryKey:['discovery-history',selected?.id,historyCursor],queryFn:({signal})=>request<History>(`/discovery/history?device_id=${encodeURIComponent(selected!.id)}&cursor=${historyCursor}&limit=20`,{signal}),enabled:!!selected&&coverage.data?.enabled===true})
  const types=Object.fromEntries((catalogue.data?.items??[]).map(t=>[t.id,t.label]))
  const items=devices.data?.items??[]
  const fresh=devices.data?.freshness
  const identity=(item:Device)=><><DeviceAddress ip={item.current_addresses?item.current_addresses[0]:item.primary_ip} name={item.name} mac={item.mac} addresses={item.current_addresses??item.addresses}/>{item.current_addresses?.length===0&&item.last_observed_ip&&<Typography.Text type="secondary">最后观测地址 · {item.last_observed_ip}</Typography.Text>}</>
  const kind=(item:Device)=><Space orientation="vertical" size={0}><Typography.Text strong={item.classification_status!=='expired'}>{types[item.device_type||item.last_device_type||'']??''}</Typography.Text><Typography.Text type="secondary">{[item.manufacturer,item.model_name].filter(Boolean).join(' · ')}</Typography.Text></Space>
  const clues=(item:Device)=><Space wrap>{item.capabilities.filter(c=>capabilities[c]).map(c=><Tag key={c}>{capabilities[c]}</Tag>)}{item.protocols.map(p=><Tag key={p}>{protocols[p]??p}</Tag>)}</Space>
  const state=(item:Device)=><Typography.Text type={item.classification_status==='conflict'?'warning':'secondary'}>{states[item.classification_status??'']??(item.current?'证据有效':'证据已过期')}</Typography.Text>
  const show=(item:Device)=>{setHistoryCursor('');setSelected(item)}
  const columns=[
    {title:'地址 / 名称 / MAC',key:'identity',render:(_:unknown,item:Device)=>identity(item)},
    {title:'设备类型 / 型号',key:'type',render:(_:unknown,item:Device)=>kind(item)},
    {title:'发现依据',key:'clues',render:(_:unknown,item:Device)=>clues(item)},
    {title:'证据状态',key:'state',render:(_:unknown,item:Device)=>state(item)},
    {title:'最近观测',key:'seen',width:115,render:(_:unknown,item:Device)=><span title={observedTimeTitle(item.last_seen)}>{observedTimeLabel(item.last_seen)}</span>},
    {title:'操作',key:'action',width:100,render:(_:unknown,item:Device)=><Button type="link" onClick={()=>show(item)}>查看证据</Button>},
  ]
  return <section className="passive-discovery-panel">
    <section className="surface center-list-toolbar">
      <div className="passive-discovery-controls">
        <Input.Search aria-label="搜索发现设备" placeholder="搜索 IP、MAC、名称或型号" allowClear value={draft} onChange={e=>setDraft(e.target.value)} onSearch={value=>change('search',value.trim())}/>
        {view==='iot'&&<Select aria-label="设备类型" value={params.get('discovery_type')||''} options={[{value:'',label:'全部类型'},...(catalogue.data?.items??[]).map(t=>({value:t.id,label:t.label}))]} onChange={value=>change('type',value)}/>}
        <Select aria-label="发现协议" value={params.get('discovery_protocol')||''} options={[{value:'',label:'全部协议'},...Object.entries(protocols).map(([value,label])=>({value,label}))]} onChange={v=>change('protocol',v)}/>
        <Select aria-label="证据状态" value={params.get('discovery_state')||''} options={[{value:'',label:'全部证据状态'},...Object.entries(states).filter(([k])=>view!=='iot'||k!=='candidate').map(([value,label])=>({value,label}))]} onChange={v=>change('state',v)}/>
        <Select aria-label="最近观测范围" value={params.get('discovery_window')||''} options={[{value:'',label:'全部观测时间'},{value:'24h',label:'近 24 小时'},{value:'168h',label:'近 7 天'},{value:'720h',label:'近 30 天'}]} onChange={v=>change('window',v)}/>
        <Input aria-label="网络域" placeholder="网络域" allowClear value={params.get('discovery_domain')||''} onChange={e=>change('domain',e.target.value)}/>
        <Input aria-label="VLAN" placeholder="VLAN" allowClear value={params.get('discovery_vlan')||''} onChange={e=>change('vlan',e.target.value)}/>
        <Button icon={<ReloadOutlined/>} loading={devices.isFetching} onClick={()=>void devices.refetch()}>刷新</Button>
      </div>
      <Typography.Paragraph type="secondary">{view==='iot'?'展示有明确设备类型依据的档案；一般服务能力和待核实记录保留在发现线索中。':'保留设备发现与关联线索，按来源查看证据。'}服务证据有效不代表设备在线。名称少于三个字符按前缀搜索，三个及以上按包含搜索。</Typography.Paragraph>
      {catalogue.isError&&<Alert type="error" showIcon title="读取设备类型失败" description={catalogue.error.message}/>}
      {fresh&&fresh.status!=='ready'&&<Alert type={fresh.status==='failed'?'error':'warning'} showIcon title={fresh.status==='failed'?'设备数据处理失败':fresh.status==='delayed'?'设备数据更新延迟':'设备数据处理中'} description={fresh.oldest_pending_at?`最早待处理时间：${observedTimeTitle(fresh.oldest_pending_at)}`:undefined}/>}
      {statistics.isError&&<Alert type="error" showIcon title="读取设备统计失败" description={statistics.error.message}/>}
      {statistics.data&&<div className="discovery-statistics" aria-label="设备类型统计">{statistics.data.items.filter(item=>item.count>0&&item.state!=='candidate').map(item=><span className="discovery-statistics-item" title={`统计更新于 ${observedTimeTitle(item.updated_at)}`} key={`${item.device_type}:${item.state}`}>{types[item.device_type]??item.device_type} · {states[item.state]??''} {item.count}</span>)}{statistics.data.pending_updates>0&&<Typography.Text type="secondary">统计处理中 {statistics.data.pending_updates}</Typography.Text>}</div>}
      <Collapse ghost items={[{key:'coverage',label:'采集覆盖与处理状态',children:coverage.isError?<Alert type="error" title="读取采集状态失败"/>:coverage.data?.enabled===false?<Typography.Text>当前运行旧版发现路径</Typography.Text>:<div className="iot-coverage-grid">{coverage.data?.items.map(p=><article className="iot-coverage-item" key={`${p.sensor_id}:${p.protocol}`}><strong>{protocols[p.protocol]??p.protocol}</strong><Typography.Text type="secondary">{p.sensor_id}</Typography.Text><span>{p.error?'采集异常':!p.enabled?'未启用':p.received===0?'暂未捕获协议流量':'正在采集'}</span><span>捕获 {p.received} · 解析 {p.parsed} · 处理 {p.admitted}</span></article>)}</div>}]} />
    </section>
    {devices.isError?<Alert type="error" showIcon title="读取发现设备失败" description={devices.error.message}/>:<section className="surface center-list-surface">
      <div className="center-discovery-desktop"><Table rowKey="id" columns={columns} dataSource={items} size="small" tableLayout="fixed" pagination={false} loading={devices.isPending} locale={{emptyText:'没有符合条件的设备'}}/></div>
      <div className="center-discovery-mobile">{items.map(item=><article key={item.id} className="discovery-card">{identity(item)}{kind(item)}{clues(item)}{state(item)}<Typography.Text type="secondary">{observedTimeLabel(item.last_seen)}</Typography.Text><Button onClick={()=>show(item)}>查看证据</Button></article>)}{!devices.isPending&&items.length===0&&<Typography.Text>没有符合条件的发现记录</Typography.Text>}</div>
      <div className="center-cursor-pagination"><Button disabled={page===0||devices.isFetching} onClick={()=>setPaging({key:filterKey,cursors,page:page-1})}>上一页</Button><Typography.Text>第 {page+1} 页</Typography.Text><Button disabled={!devices.data?.has_more||!devices.data.next_cursor||devices.isFetching} onClick={()=>setPaging({key:filterKey,cursors:[...cursors.slice(0,page+1),devices.data!.next_cursor],page:page+1})}>下一页</Button></div>
    </section>}
    <Modal title="设备证据与变化历史" open={!!selected} footer={null} onCancel={()=>setSelected(undefined)}>{selected&&<>{identity(selected)}{kind(selected)}<Typography.Paragraph>{selected.classification?.reason}</Typography.Paragraph><Typography.Paragraph type="secondary">最近证据摘要</Typography.Paragraph>{selected.observations.map(o=><article key={o.id} className="discovery-card"><strong>{protocols[o.origin]??o.origin}</strong><span className="discovery-identifier">{[o.ip,o.mac,o.name].filter(Boolean).join(' · ')}</span><span>{o.explanation}</span><Typography.Text type="secondary">{observedTimeTitle(o.observed_at)}</Typography.Text>{o.withdrawn&&<Tag color="warning">已撤销</Tag>}</article>)}
      {history.isError&&<Alert type="error" title="读取设备历史失败"/>}
      {history.data&&<><Typography.Title level={5}>变化历史</Typography.Title>{history.data.items.map(row=><article className="discovery-card" key={row.id}><strong>{protocols[row.evidence.origin]??row.evidence.origin}</strong><span>{row.evidence.explanation}</span><Typography.Text type="secondary">观测于 {observedTimeTitle(row.observed_at)}</Typography.Text></article>)}<Space wrap><Button disabled={historyCursor===''||history.isFetching} onClick={()=>setHistoryCursor('')}>最新记录</Button><Button disabled={!history.data.has_more||history.isFetching} onClick={()=>setHistoryCursor(history.data!.next_cursor)}>更早记录</Button></Space></>}
    </>}</Modal>
  </section>
}
