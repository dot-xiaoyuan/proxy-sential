import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Empty, Pagination, Tag, Typography } from 'antd'
import { request } from '../shared/api/client'

type HistoryItem={id:string;stream:string;first_seen:string;last_seen:string;count:number;content:Record<string,unknown>}
type HistoryPage={items:HistoryItem[];total:number;as_of:string}
const labels:Record<string,string>={source_family:'证据来源',raw_value:'原始值',score:'分数',explanation:'说明',conflict:'冲突',exclusion:'排除',access_id:'接入标识',ap:'AP',switch_id:'交换机',switch_port:'端口',vlan:'VLAN',ip:'IP',mac:'MAC',name:'名称',display_name:'名称',manufacturer:'厂商',model_name:'型号',account_id:'账号',latest_account_id:'账号',device_type:'类型线索',role:'角色',status:'判定',router_status:'路由判定',confidence:'可信度',rule_version:'规则',capabilities:'能力',withdrawn:'撤回',current_shared:'当前共享',conflicts:'冲突',identity_conflict:'身份冲突',account_conflict:'账号冲突',address_state:'地址状态',signal_groups:'依据',source:'来源',origin:'协议',endpoint_id:'终端身份',entity_role:'身份类型',coverage_state:'采集覆盖',device_lower_bound:'设备下界'}
const values:Record<string,string>={confirmed:'明确',likely:'较强',candidate:'候选',clue:'初步线索',strong:'较强证据',router:'路由器',ap:'接入点',switch:'交换机',firewall:'防火墙',endpoint:'终端',dns_sd:'DNS-SD',dhcp:'DHCP',ssdp:'SSDP',printing:'打印',scanning:'扫描',casting:'投屏',media_rendering:'媒体播放',network_video:'网络视频',verified:'已核验',stale:'已过期',reassigned:'已转移'}
const time=(v:string)=>new Date(v).toLocaleString('zh-CN',{hour12:false})
const renderValue=(value:unknown):string=>Array.isArray(value)?value.map(renderValue).filter(Boolean).join('、'):typeof value==='boolean'?(value?'是':'否'):value==null||value===''||value==='unknown'?'':typeof value==='object'?JSON.stringify(value):values[String(value)]??String(value)
export function DeviceHistoryPanel({kind,id}:{kind:'router'|'router_evidence'|'profile'|'shared'|'discovery'|'endpoint'|'access'|'endpoint_discovery';id:string}) {
 const [page,setPage]=useState(1);const [asOf,setAsOf]=useState('')
 const url=`/device-history/${kind}/${encodeURIComponent(id)}`
 const query=useQuery({queryKey:['device-history',kind,id,page,asOf],queryFn:()=>request<HistoryPage>(`${url}?limit=20&offset=${(page-1)*20}${asOf?`&as_of=${encodeURIComponent(asOf)}`:''}`)})
 return <section className="center-history"><div className="center-history-toolbar"><Typography.Text type="secondary">连续相同观测合并；记录时间不代表在线状态</Typography.Text><Button size="small" onClick={()=>{setPage(1);setAsOf('');void query.refetch()}}>刷新历史</Button></div>{query.isError?<Alert type="error" title="历史读取失败" description={String(query.error)}/>:query.isPending?<Typography.Text>加载历史…</Typography.Text>:<>{query.data.items.length===0&&<Empty description="没有变化记录"/>}{query.data.items.map(item=><HistoryRow key={item.id} item={item} url={url} asOf={query.data.as_of}/>)}<Pagination size="small" current={page} pageSize={20} total={query.data.total} showSizeChanger={false} onChange={value=>{setAsOf(query.data.as_of);setPage(value)}}/></>}</section>
}
function HistoryRow({item,url,asOf}:{item:HistoryItem;url:string;asOf:string}){
 const [open,setOpen]=useState(false)
 return <article className="center-history-row"><div className="center-history-meta"><strong>{time(item.last_seen)}</strong><Tag>{item.count} 次观测</Tag></div><div className="center-history-content">{Object.entries(labels).map(([key,label])=>{const value=renderValue(item.content[key]);return value?<span key={key}><b>{label}</b> {value}</span>:null})}</div><Typography.Text type="secondary">首次 {time(item.first_seen)} · 最近 {time(item.last_seen)}</Typography.Text><Button type="link" size="small" onClick={()=>setOpen(!open)}>{open?'收起原始记录':'查看原始记录'}</Button>{open&&<RawHistory url={url} group={item.id} asOf={asOf}/>}</article>
}
function RawHistory({url,group,asOf}:{url:string;group:string;asOf:string}){
 const [page,setPage]=useState(1)
 const query=useQuery({queryKey:['raw-device-history',url,group,page,asOf],queryFn:()=>request<HistoryPage>(`${url}?group=${group}&as_of=${encodeURIComponent(asOf)}&limit=10&offset=${(page-1)*10}`)})
 return <div className="center-raw-history">{query.isError?<Alert type="error" title="原始记录读取失败"/>:query.isPending?'加载原始记录…':<>{query.data.items.map(item=><details key={item.id}><summary>{time(item.last_seen)} · {item.id}</summary><pre>{JSON.stringify(item.content,null,2)}</pre></details>)}<Pagination size="small" current={page} total={query.data.total} pageSize={10} showSizeChanger={false} onChange={setPage}/></>}</div>
}
