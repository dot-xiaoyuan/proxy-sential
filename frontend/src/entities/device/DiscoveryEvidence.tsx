import {useState} from 'react'
import {useQuery} from '@tanstack/react-query'
import {Alert,Button,Pagination,Tag,Typography} from 'antd'
import {request} from '../../shared/api/client'
export function DiscoveryEvidence({endpointId}:{endpointId:string}){
 const[page,setPage]=useState(1);const[open,setOpen]=useState(false)
 const q=useQuery({queryKey:['discovery','endpoint',endpointId,page],queryFn:()=>request<{total:number;items:{id:string;origin:string;ip?:string;mac?:string;port?:string;vlan?:string;explanation:string;observed_at:string}[]}>(`/discovery/endpoint-evidence?endpoint_id=${encodeURIComponent(endpointId)}&limit=20&offset=${(page-1)*20}`),enabled:open})
 return <div><Button onClick={()=>setOpen(!open)}>{open?'收起发现证据':'查看网络发现证据'}</Button>{open&&<>{q.error&&<Alert type="error" title="读取发现证据失败"/>}{q.data?.items.map(o=><div className="discovery-card" key={o.id}><Tag>{o.origin}</Tag><Typography.Text>{o.ip} {o.mac}</Typography.Text>{o.port&&<div>路径线索 {o.port} {o.vlan&&`VLAN ${o.vlan}`}</div>}<div>{o.explanation}</div><div>{new Date(o.observed_at).toLocaleString()}</div></div>)}{!!q.data?.total&&<Pagination current={page} total={q.data.total} pageSize={20} onChange={setPage}/>}</>}</div>
}
