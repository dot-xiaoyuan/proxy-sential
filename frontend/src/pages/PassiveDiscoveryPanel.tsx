import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import { DeviceAddress } from '../entities/device/DeviceAddress'
import { observedTimeLabel, observedTimeTitle } from '../shared/ui/observedTime'

type Device = components['schemas']['DiscoveryDevice']
type Page = components['schemas']['DiscoveryDevicePage']
const protocols: Record<string,string> = { dhcp:'DHCP', dns_sd:'DNS-SD', ssdp:'SSDP', ws_discovery:'WS-Discovery', arp:'ARP', ndp:'NDP', ieee1905_client:'IEEE 1905', lldp:'LLDP', cdp:'CDP', fdb:'交换机 MAC 表', neighbor:'邻居表', active:'探测响应' }
const capabilities: Record<string,string> = { printing:'打印', scanning:'扫描', casting:'投屏', network_video:'网络视频', media_rendering:'媒体播放' }
const categories: Record<string,string> = { printer:'打印设备', camera:'摄像设备', media:'媒体设备' }

export function PassiveDiscoveryPanel({view}:{view:'iot'|'records'}) {
  const [params,setParams] = useSearchParams()
  const search = params.get('discovery_search') || ''
  const category = params.get('discovery_category') || ''
  const [draft,setDraft] = useState(search)
  const [cursors,setCursors] = useState([''])
  const [page,setPage] = useState(0)
  const [selected,setSelected] = useState<Device>()
  const change = (key:string,value:string) => {
    setCursors(['']); setPage(0)
    setParams(current=>{const next=new URLSearchParams(current);if(value)next.set(key,value);else next.delete(key);return next},{replace:true})
  }
  const query = new URLSearchParams({mode:'passive',window:'24h',limit:'20'})
  if(view==='iot')query.set('view','iot')
  if(search)query.set('search',search)
  if(category)query.set('category',category)
  if(cursors[page])query.set('cursor',cursors[page])
  const devices = useQuery({queryKey:['discovery-center',query.toString()],queryFn:({signal})=>request<Page>(`/discovery/devices?${query}`,{signal})})
  const items=devices.data?.items??[]
  const identity=(item:Device)=><DeviceAddress ip={item.primary_ip} name={item.name} mac={item.mac} addresses={item.addresses}/>
  const clues=(item:Device)=><Space wrap>{item.capabilities.filter(c=>capabilities[c]).map(c=><Tag key={c}>{capabilities[c]}</Tag>)}{item.protocols.map(p=><Tag key={p}>{protocols[p]??p}</Tag>)}</Space>
  const columns=[
    {title:'地址 / 名称 / MAC',key:'identity',render:(_:unknown,item:Device)=>identity(item)},
    {title:'发现依据',key:'clues',render:(_:unknown,item:Device)=>clues(item)},
    {title:'证据状态',key:'state',render:(_:unknown,item:Device)=><Typography.Text type="secondary">{item.current?'证据有效':'证据已过期'}</Typography.Text>},
    {title:'最近观测',key:'seen',width:130,render:(_:unknown,item:Device)=><span title={observedTimeTitle(item.last_seen)}>{observedTimeLabel(item.last_seen)}</span>},
    {title:'操作',key:'action',width:100,render:(_:unknown,item:Device)=><Button type="link" onClick={()=>setSelected(item)}>查看证据</Button>},
  ]
  return <section className="passive-discovery-panel">
    <section className="surface center-list-toolbar">
      <div className="passive-discovery-controls">
        <Input.Search aria-label="搜索发现设备" placeholder="搜索 IP、MAC 或名称" allowClear value={draft} onChange={e=>setDraft(e.target.value)} onSearch={value=>change('discovery_search',value.trim())}/>
        {view==='iot'&&<Select aria-label="设备类型" value={category} options={[{value:'',label:'全部类型'},...Object.entries(categories).map(([value,label])=>({value,label}))]} onChange={value=>change('discovery_category',value)}/>}
        <Button icon={<ReloadOutlined/>} loading={devices.isFetching} onClick={()=>void devices.refetch()}>刷新</Button>
      </div>
      <Typography.Paragraph type="secondary">{view==='iot'?'依据设备自身的服务公告归类，保留待核实线索；仅有 DHCP 地址绑定的手机、电脑不进入此列表。':'近 24 小时被动发现线索。'}记录有效不代表设备在线。</Typography.Paragraph>
    </section>
    {devices.isError?<Alert type="error" showIcon title="读取发现设备失败" description={devices.error.message}/>:<section className="surface center-list-surface">
      <div className="center-discovery-desktop"><Table rowKey="id" columns={columns} dataSource={items} size="small" tableLayout="fixed" pagination={false} loading={devices.isPending} locale={{emptyText:view==='iot'?'近 24 小时没有符合条件的设备':'没有发现记录'}}/></div>
      <div className="center-discovery-mobile">{items.map(item=><article key={item.id} className="discovery-card">{identity(item)}{clues(item)}<Typography.Text type="secondary">{observedTimeLabel(item.last_seen)} · {item.current?'证据有效':'证据已过期'}</Typography.Text><Button onClick={()=>setSelected(item)}>查看证据</Button></article>)}{!devices.isPending&&items.length===0&&<Typography.Text>没有符合条件的发现记录</Typography.Text>}</div>
      <div className="center-cursor-pagination"><Button disabled={page===0||devices.isFetching} onClick={()=>setPage(page-1)}>上一页</Button><Typography.Text>第 {page+1} 页</Typography.Text><Button disabled={!devices.data?.has_more||!devices.data.next_cursor||devices.isFetching} onClick={()=>{setCursors([...cursors.slice(0,page+1),devices.data!.next_cursor]);setPage(page+1)}}>下一页</Button></div>
    </section>}
    <Modal title="发现证据" open={!!selected} footer={null} onCancel={()=>setSelected(undefined)}>{selected&&<>{identity(selected)}<Typography.Paragraph type="secondary">以下为当前列表采用的最近证据。</Typography.Paragraph>{selected.observations.map(o=><article key={o.id} className="discovery-card"><strong>{protocols[o.origin]??o.origin}</strong><span className="discovery-identifier">{[o.ip,o.mac,o.name].filter(Boolean).join(' · ')}</span><span>{o.explanation}</span><Typography.Text type="secondary">{observedTimeTitle(o.observed_at)}</Typography.Text>{o.withdrawn&&<Tag color="warning">已撤销</Tag>}</article>)}</>}</Modal>
  </section>
}
