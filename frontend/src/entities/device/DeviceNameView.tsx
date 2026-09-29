import { Link } from 'react-router-dom'
import { useState } from 'react'
import { Button, Input, Modal, Typography, Pagination, Alert, Tag, Tooltip } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../shared/api/client'
import type { EndpointDeviceInventory } from '../../shared/api/types'

const sources: Record<string,string> = {manual:'人工备注',dhcp_fqdn:'DHCP FQDN',dhcp_hostname:'DHCP 主机名',mdns_hostname:'mDNS 主机名',mdns_service:'DNS-SD 服务'}
export function DeviceNameView({name,compact=false}: {name?: EndpointDeviceInventory['device_name'];compact?:boolean}) {
 if(compact) return <div className="device-name-view device-name-compact">
   <Tooltip title={name?[sources[name.source]||name.source,name.status==='historical'?'历史观测，尚未重新确认':'当前有效名称',name.multiple_names?'其他名称可在详情中查看':''].filter(Boolean).join(' · '):undefined}><Typography.Text className="device-name-label">{name?.value || ''}</Typography.Text></Tooltip>
   {name&&(name.manual||name.status==='historical')&&<span className="device-name-caption">{[name.manual?'人工备注':'',name.status==='historical'?'历史名称':''].filter(Boolean).join(' · ')}</span>}
 </div>

 return <div className="device-name-view"><Typography.Text strong>{name?.value || ''}</Typography.Text>{name && <div className="device-name-meta"><Typography.Text type="secondary">{sources[name.source] || name.source}</Typography.Text>{name.status==='historical'&&<Tag>历史名称</Tag>}{name.multiple_names&&<Tag>多个名称</Tag>}</div>}</div>
}
export function DeviceNamePanel({endpointId,name,canEdit=false}: {endpointId:string;name?:EndpointDeviceInventory['device_name'];canEdit?:boolean}) {
 const [editing,setEditing]=useState(false),[value,setValue]=useState(''),[page,setPage]=useState(1)
 const client=useQueryClient()
 const evidence=useQuery({queryKey:['device-name-evidence',endpointId,page],queryFn:()=>api.deviceNameEvidence(endpointId,(page-1)*20),refetchInterval:15000,refetchIntervalInBackground:false})
 const update=useMutation({mutationFn:(next:string)=>api.updateDeviceName(endpointId,next),onSuccess:()=>{setEditing(false);void client.invalidateQueries({queryKey:['endpoint-identity',endpointId]});void client.invalidateQueries({queryKey:['devices']})}})
 return <section className="surface device-name-panel"><div className="device-name-heading"><Typography.Title level={4}>设备名称</Typography.Title>{canEdit&&<div className="device-name-actions"><Button onClick={()=>{setValue(name?.manual?name.value:'');setEditing(true)}}>编辑备注</Button>{name?.manual&&<Button loading={update.isPending} onClick={()=>update.mutate('')}>清除备注</Button>}</div>}</div><DeviceNameView name={name}/>{update.isError&&<Alert type="error" title={update.error.message}/>}<Typography.Paragraph type="secondary">名称用于辨认设备，不作为唯一身份。以下保留名称来源和原始事件引用。</Typography.Paragraph>{evidence.isError?<Alert type="error" title="名称证据加载失败"/>:evidence.data?.items.map((item,i)=><article className="device-name-evidence" key={`${item.event_id}-${item.source}-${i}`}><Typography.Text strong>{item.value}</Typography.Text><span>{sources[item.source]||item.source} · {item.kind==='service'?'服务名称':'主机名'} · {new Date(item.observed_at).toLocaleString('zh-CN')}</span><span>地址：{item.address||''} · 归属：{item.attribution}</span><span>传感器：{item.sensor_id||'历史属性'} · 事件：{item.event_id?<Link to={`/events/${encodeURIComponent(item.event_id)}`}>{item.event_id}</Link>:'无原始事件引用'}</span></article>)}{evidence.data?.total===0&&<Typography.Text type="secondary">暂无名称证据</Typography.Text>}<Pagination current={page} pageSize={20} total={evidence.data?.total||0} onChange={setPage} showSizeChanger={false}/><Modal title="编辑设备备注" open={editing} onCancel={()=>setEditing(false)} onOk={()=>update.mutate(value.trim())} confirmLoading={update.isPending}><Input aria-label="设备备注" value={value} maxLength={255} onChange={e=>setValue(e.target.value)}/></Modal></section>
}
