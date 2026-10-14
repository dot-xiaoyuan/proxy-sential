import { useState } from 'react'
import { Alert, Button, Input, Select, Tag, Typography, Modal } from 'antd'
import { Link } from 'react-router-dom'
import { useEndpointObservations } from '../../shared/api/queries'
import { api, ApiError, request } from '../../shared/api/client'
import type { InventoryDetail, EndpointObservation, EndpointObservationQuery } from '../../shared/api/types'

const labels={account:'账号',ip:'IP',access:'接入位置'}
const time=(value?:string)=>value?new Date(value).toLocaleString('zh-CN'):''

export function AssociationOverview({detail}:{detail?:InventoryDetail}) {
 if(!detail?.state.complete)return <Alert showIcon type="info" title="关联概览回填中" description="覆盖完成后显示历史关联数量；此时不将缺失结果显示为 0 条。"/>
 return <section className="surface endpoint-association-overview"><div className="surface-title-row"><Typography.Title level={4}>关联概览</Typography.Title><Typography.Text type="secondary">更新时间 {time(detail.state.as_of)}{detail.state.updating?' · 物化更新中':''}</Typography.Text></div><Typography.Paragraph type="secondary">首次与最近观测是证据时间点，不表示期间持续有效。此处展示最近 20 项；完整记录在「身份溯源」中按值查询。</Typography.Paragraph><div className="endpoint-association-grid">{(detail.associations??[]).map(a=><article key={JSON.stringify([a.kind,a.value,a.source])} className="endpoint-association-card"><span className="endpoint-trace-label">{labels[a.kind]}</span><Typography.Text strong className="detail-value-wrap">{a.value}</Typography.Text><span className="endpoint-trace-label">{a.source}</span><div className="endpoint-trace-times"><span>首次 {time(a.first_seen)}</span><span>最近 {time(a.last_seen)}</span></div><span>{a.observation_count} 次观测{a.session_count>0?` · ${a.session_count} 个会话`:''}</span></article>)}</div></section>
}

export function EndpointTracePanel({endpointId}:{endpointId:string}) {
 const [filters,setFilters]=useState<EndpointObservationQuery>({kind:'account',limit:20})
 const [value,setValue]=useState(''),[source,setSource]=useState('')
 const [cursors,setCursors]=useState<string[]>([''])
 const page=useEndpointObservations(endpointId,{...filters,cursor:cursors.at(-1)||undefined})
 const update=(next:Partial<EndpointObservationQuery>)=>{setFilters({...filters,...next});setCursors([''])}
 return <section className="surface endpoint-trace-panel"><div className="surface-title-row"><Typography.Title level={4}>身份溯源</Typography.Title><Typography.Text type="secondary">按终端限定 · 每页 20 条</Typography.Text></div><Typography.Paragraph type="secondary">账号、IP 与接入记录均为历史证据，不代表当前在线或使用人。仅认证证据明确给出起止时间时展示会话区间。</Typography.Paragraph><div className="endpoint-trace-filters"><Select aria-label="溯源类别" value={filters.kind} options={Object.entries(labels).map(([value,label])=>({value,label}))} onChange={kind=>{setValue('');update({kind,value:undefined})}}/><Input.Search aria-label="精确关联值" allowClear placeholder={`精确${labels[filters.kind]}`} value={value} onChange={e=>setValue(e.target.value)} onSearch={v=>update({value:v.trim()||undefined})}/><Button loading={page.isFetching} onClick={()=>void page.refetch()}>刷新明细</Button></div><details className="filter-disclosure endpoint-trace-more"><summary>来源与时间筛选</summary><div className="endpoint-trace-filters"><Input.Search aria-label="证据来源" allowClear placeholder="精确来源" value={source} onChange={e=>setSource(e.target.value)} onSearch={v=>update({source:v.trim()||undefined})}/><label>开始时间<input aria-label="溯源开始时间" type="datetime-local" onChange={e=>update({start:e.target.value?new Date(e.target.value).toISOString():undefined})}/></label><label>结束时间<input aria-label="溯源结束时间" type="datetime-local" onChange={e=>update({end:e.target.value?new Date(e.target.value).toISOString():undefined})}/></label></div></details>
 {page.isError&&<Alert showIcon type="error" title="溯源明细加载失败" description={page.error.message}/>}
 {page.data&&!page.data.state.complete&&<Alert showIcon type="info" title="历史覆盖回填中" description="当前结果尚不完整，不作为完整历史数量。"/>}
 {page.isFetching&&<Typography.Paragraph type="secondary">正在读取所选溯源条件</Typography.Paragraph>}
 {page.data?.state&&<Typography.Paragraph className="endpoint-trace-state" type="secondary">明细投影更新时间 {time(page.data.state.as_of)}{page.data.state.updating?' · 关联物化更新中':''}</Typography.Paragraph>}
 <div className="endpoint-observation-list" aria-busy={page.isFetching}>{(page.data?.items??[]).map(row=><ObservationCard key={row.record_id} row={row}/>)}</div>
 {page.data?.state.complete&&!page.isFetching&&!page.isError&&(page.data.items??[]).length===0&&<Typography.Paragraph type="secondary">所选条件没有观测记录</Typography.Paragraph>}
 <div className="endpoint-trace-pagination"><Button disabled={cursors.length===1||page.isFetching} onClick={()=>setCursors(cursors.slice(0,-1))}>上一页</Button><Typography.Text>第 {cursors.length} 页</Typography.Text><Button disabled={!page.data?.next_cursor||page.isFetching||page.isError} onClick={()=>setCursors([...cursors,page.data!.next_cursor!])}>下一页</Button></div></section>
}

function ObservationCard({row}:{row:EndpointObservation}) {
 const [checking,setChecking]=useState(false),[checked,setChecked]=useState(false),[notice,setNotice]=useState('')
 const [snapshot,setSnapshot]=useState<unknown>(),[open,setOpen]=useState(false)
 const inspect=async()=>{setChecking(true);setNotice('');try{if(row.evidence_url){setSnapshot(await request(row.evidence_url));setOpen(true)}else{await api.event(row.event_id!)}setChecked(true)}catch(err){setNotice(err instanceof ApiError&&err.status===404?'原始证据不在当前保留库中；关联事实仍留存。':'原始证据读取失败，可重试。')}finally{setChecking(false)}}
 return <article className="endpoint-observation-card"><div className="endpoint-observation-identity"><Typography.Text strong className="detail-value-wrap">{row.value}</Typography.Text><span className="endpoint-trace-label">{row.source}</span></div><div className="endpoint-observation-evidence"><span>观测 {time(row.observed_at)}</span><span>置信度 {Math.round(row.confidence*100)}%</span>{row.started_at&&<span>会话起点 {time(row.started_at)}{row.ended_at?` · 终点 ${time(row.ended_at)}`:' · 证据未提供终点'}</span>}{row.session_id&&<Typography.Text className="detail-value-wrap" copyable>会话 {row.session_id}</Typography.Text>}{row.event_id&&<Typography.Text className="detail-value-wrap" copyable>{row.event_id}</Typography.Text>}{row.evidence_state==='outside_retention'?<Tag>原始事件超出 7 天保留期</Tag>:(row.event_id||row.evidence_url)&&<div className="endpoint-evidence-actions">{checked?(row.evidence_url?<Button size="small" onClick={()=>setOpen(true)}>打开关联证据</Button>:<Link to={`/events/${encodeURIComponent(row.event_id||'')}`}>打开原始证据</Link>):<Button size="small" loading={checking} onClick={()=>void inspect()}>检查原始证据</Button>}</div>}{notice&&<Typography.Text type="secondary">{notice}</Typography.Text>}</div><Modal open={open} onCancel={()=>setOpen(false)} footer={null} title="原始关联证据"><pre className="endpoint-snapshot-evidence">{JSON.stringify(snapshot,null,2)}</pre></Modal></article>
}
