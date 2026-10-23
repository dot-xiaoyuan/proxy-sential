import { AppErrorAlert, AppServerPagination, AppTable, formatDateTime, useMediaQuery } from '../../shared/ui'
import { Notice as Alert } from '../../shared/ui/Notice'
import { useState } from 'react'
import type { ColumnsType } from 'antd/es/table'
import { Button, Input, Select, Tag, Timeline, Typography, Modal } from 'antd'
import { Link } from 'react-router-dom'
import { useEndpointObservations } from '../../shared/api/queries'
import { api, ApiError, request } from '../../shared/api/client'
import type { InventoryDetail, EndpointObservation, EndpointObservationQuery } from '../../shared/api/types'

const labels={account:'账号',ip:'IP',access:'接入位置'}
const time=formatDateTime

export function AssociationOverview({detail}:{detail?:InventoryDetail}) {
 if(!detail?.state.complete)return <Alert showIcon type="info" title="关联概览回填中" description="覆盖完成后显示历史关联数量；此时不将缺失结果显示为 0 条。"/>
 const associations=[...(detail.associations??[])].sort((a,b)=>Date.parse(b.last_seen)-Date.parse(a.last_seen))
 if(!associations.length)return null
 const items=associations.map(item=>({key:JSON.stringify([item.kind,item.value,item.source]),color:item.kind==='account'?'blue':item.kind==='ip'?'green':'gray',content:<div className="endpoint-association-item">
  <div className="endpoint-association-head"><Tag>{labels[item.kind]}</Tag><Typography.Text strong className="detail-value-wrap">{item.value}</Typography.Text><span className="endpoint-trace-label">{item.source}</span></div>
  <div className="endpoint-association-range"><span>首次 {time(item.first_seen)}</span><span>最近 {time(item.last_seen)}</span></div>
  <div className="endpoint-association-counts"><span>观测 {item.observation_count} 次</span>{item.session_count>0&&<span>{item.session_count} 个会话</span>}<span>置信度 {Math.round(item.confidence*100)}%</span></div>
 </div>}))
 return <section className="surface endpoint-association-overview"><div className="surface-title-row"><Typography.Title level={4}>关联概览</Typography.Title><Typography.Text type="secondary">更新时间 {time(detail.state.as_of)}{detail.state.updating?' · 物化更新中':''}</Typography.Text></div><Typography.Paragraph type="secondary">按最近观测排序，一条关联只出现一次；首次与最近表示证据覆盖范围，不代表持续在线或持续有效。完整逐条记录在「身份溯源」中查询。</Typography.Paragraph><div className="endpoint-scroll-list endpoint-association-timeline-scroll"><Timeline className="endpoint-association-timeline" items={items}/></div></section>
}

export function EndpointTracePanel({endpointId}:{endpointId:string}) {
 const [filters,setFilters]=useState<EndpointObservationQuery>({kind:'account',limit:20})
 const [value,setValue]=useState(''),[source,setSource]=useState('')
 const [cursors,setCursors]=useState<string[]>([''])
 const [pageSize,setPageSize]=useState(20)
 const tracePage=cursors.length
 const showTraceDetail=useMediaQuery('(min-width: 1200px)')||useMediaQuery('(max-width: 559px)')
 const page=useEndpointObservations(endpointId,{...filters,limit:pageSize,cursor:cursors.at(-1)||undefined})
 const items=page.data?.items??[]
 const update=(next:Partial<EndpointObservationQuery>)=>{setFilters({...filters,...next});setCursors([''])}
 const changePage=(nextPage:number,nextSize:number)=>{
  if(nextSize!==pageSize){setPageSize(nextSize);setCursors(['']);return}
  if(nextPage===tracePage)return
  if(nextPage<tracePage){setCursors(current=>current.slice(0,nextPage));return}
  if(nextPage===tracePage+1&&page.data?.next_cursor)setCursors(current=>[...current,page.data!.next_cursor!])
 }
 const columns:ColumnsType<EndpointObservation>=[
  {title:'观测时间',dataIndex:'observed_at',width:145,render:(value:string)=>time(value)},
  {title:'类别',dataIndex:'kind',width:72,render:(kind:EndpointObservation['kind'])=><Tag>{labels[kind]}</Tag>},
  {title:'关联值',dataIndex:'value',width:155,render:(value:string)=><Typography.Text strong className="detail-value-wrap">{value}</Typography.Text>},
  ...(showTraceDetail?[
   {title:'来源',dataIndex:'source',width:85},
   {title:'置信度',dataIndex:'confidence',width:60,render:(value:number)=>`${Math.round(value*100)}%`},
  ] as ColumnsType<EndpointObservation>:[]),
  {title:'会话区间',key:'session',width:185,onCell:(row)=>({className:row.started_at||row.session_id?'':'mobile-empty-cell'}),render:(_,row)=>row.started_at?<span className="endpoint-trace-session">起点 {time(row.started_at)}<br/>终点 {row.ended_at?time(row.ended_at):'证据未提供'}</span>:row.session_id?<Typography.Text className="endpoint-trace-session-id" copyable>会话 {row.session_id}</Typography.Text>:''},
  {title:'证据',key:'evidence',width:165,render:(_,row)=><ObservationEvidence row={row}/>},
 ]
 const loaded=(tracePage-1)*pageSize+items.length
 return <section className="surface endpoint-trace-panel"><div className="surface-title-row"><Typography.Title level={4}>身份溯源</Typography.Title><Typography.Text type="secondary">按终端限定 · 最新观测在上</Typography.Text></div><Typography.Paragraph type="secondary">账号、IP 与接入记录均为历史证据，不代表当前在线或使用人。仅认证证据明确给出起止时间时展示会话区间。</Typography.Paragraph><div className="endpoint-trace-filters"><Select aria-label="溯源类别" value={filters.kind} options={Object.entries(labels).map(([value,label])=>({value,label}))} onChange={kind=>{setValue('');update({kind,value:undefined})}}/><Input.Search aria-label="精确关联值" allowClear placeholder={`精确${labels[filters.kind]}`} value={value} onChange={e=>setValue(e.target.value)} onSearch={v=>update({value:v.trim()||undefined})}/><Button loading={page.isFetching} onClick={()=>void page.refetch()}>刷新明细</Button></div><details className="filter-disclosure endpoint-trace-more"><summary>来源与时间筛选</summary><div className="endpoint-trace-filters"><Input.Search aria-label="证据来源" allowClear placeholder="精确来源" value={source} onChange={e=>setSource(e.target.value)} onSearch={v=>update({source:v.trim()||undefined})}/><label>开始时间<input aria-label="溯源开始时间" type="datetime-local" onChange={e=>update({start:e.target.value?new Date(e.target.value).toISOString():undefined})}/></label><label>结束时间<input aria-label="溯源结束时间" type="datetime-local" onChange={e=>update({end:e.target.value?new Date(e.target.value).toISOString():undefined})}/></label></div></details>
 {page.isError&&<AppErrorAlert title="溯源明细读取失败" message={page.error.message} />}
 {page.data&&!page.data.state.complete&&<Alert showIcon type="info" title="历史覆盖回填中" description="当前结果尚不完整，不作为完整历史数量。"/>}
 {page.isFetching&&<Typography.Paragraph type="secondary">正在读取所选溯源条件</Typography.Paragraph>}
 {page.data?.state&&<Typography.Paragraph className="endpoint-trace-state" type="secondary">明细投影更新时间 {time(page.data.state.as_of)}{page.data.state.updating?' · 关联物化更新中':''}</Typography.Paragraph>}
 <div className="endpoint-trace-table-wrap endpoint-tab-table-wrap" aria-busy={page.isFetching}>
  <AppTable<EndpointObservation> className="endpoint-trace-table" columns={columns} dataSource={items} rowKey="record_id" tableLayout="fixed" scroll={{x:showTraceDetail?867:722}} locale={{emptyText:page.data?.state.complete?'所选条件没有观测记录':' '}} />
 </div>
 <AppServerPagination disabled={page.isFetching} page={tracePage} pageSize={pageSize} total={loaded+(page.data?.next_cursor?1:0)} onChange={changePage} cursorMode totalText={`第 ${tracePage} 页 · 已加载 ${loaded} 条`} />
 </section>
}

function ObservationEvidence({row}:{row:EndpointObservation}) {
 const [checking,setChecking]=useState(false),[checked,setChecked]=useState(false),[notice,setNotice]=useState('')
 const [snapshot,setSnapshot]=useState<unknown>(),[open,setOpen]=useState(false)
 const inspect=async()=>{setChecking(true);setNotice('');try{if(row.evidence_url){setSnapshot(await request(row.evidence_url));setOpen(true)}else{await api.event(row.event_id!)}setChecked(true)}catch(err){setNotice(err instanceof ApiError&&err.status===404?'原始证据不在当前保留库中；关联事实仍留存。':'原始证据读取失败，可重试。')}finally{setChecking(false)}}
 return <div className="endpoint-trace-evidence-cell">
  {row.evidence_state==='outside_retention'?<Tag>原始事件超出 7 天保留期</Tag>:<>
   {row.event_id&&<Link className="endpoint-trace-event-id mono" to={`/events/${encodeURIComponent(row.event_id)}`}>{row.event_id}</Link>}
   {(row.event_id||row.evidence_url)&&<div className="endpoint-evidence-actions">{checked?(row.evidence_url?<Button size="small" onClick={()=>setOpen(true)}>查看证据</Button>:<Button size="small" onClick={()=>void inspect()}>重新检查</Button>):<Button size="small" loading={checking} onClick={()=>void inspect()}>检查原始证据</Button>}</div>}
  </>}
  {notice&&<span className="endpoint-trace-notice">{notice}</span>}
  <Modal open={open} onCancel={()=>setOpen(false)} footer={null} title="原始关联证据"><pre className="endpoint-snapshot-evidence">{JSON.stringify(snapshot,null,2)}</pre></Modal>
 </div>
}
