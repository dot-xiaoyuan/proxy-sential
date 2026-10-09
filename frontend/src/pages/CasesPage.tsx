import { detailPath } from '../app/navigation'
import { useUrlState } from '../shared/ui/useUrlState'
import { Link,useLocation,useSearchParams } from 'react-router-dom'
import { App as AntApp, Button, Card, Checkbox, Input, List, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import { useMemo, useState } from 'react'

import { useCases, useCasesBatchMutation, useSession } from '../shared/api/queries'
import type { RiskCase } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppServerPagination, AppTableBar, UniversityDimensionFilters, useServerPagination, type UniversityDimensions } from '../shared/ui'
import { CaseAssessment } from '../entities/risk/CaseAssessment'
import { can } from '../shared/auth/permissions'

const statusNames: Record<string,string> = {new:'新建',assigned:'已分派',investigating:'调查中',waiting_data:'等待数据',resolved:'已解决',closed:'已关闭',reopened:'重新打开'}

export function CasesPage() {
  const [q,setQ]=useUrlState('q','');const location=useLocation();const [params,setParams]=useSearchParams()
  const [status,setStatus]=useUrlState('status','')
	const includeRouterObservations=params.get('include_router_observations')!=='false'
	const setIncludeRouterObservations=(checked:boolean)=>setParams(current=>{const next=new URLSearchParams(current);if(checked)next.delete('include_router_observations');else next.set('include_router_observations','false');next.delete('page');next.delete('cursor');return next})
	const pagination=useServerPagination()
  const dimensions=Object.fromEntries(['sensor_id','campus_id','department','person_type','ssid','vlan','ap','nas_ip'].map(key=>[key,params.get(key)||undefined])) as UniversityDimensions;
 const setDimensions=(value:UniversityDimensions)=>setParams(current=>{const next=new URLSearchParams(current);Object.entries(value).forEach(([key,value])=>value?next.set(key,value):next.delete(key));next.delete('page');next.delete('cursor');return next})
  const [selected,setSelected]=useState<string[]>([])
  const [assignee,setAssignee]=useState('')
  const batch=useCasesBatchMutation();const session=useSession();const {message}=AntApp.useApp();const writable=can(session.data,'cases:write')
  const query=useCases({q,status:status||undefined,...dimensions,cursor:pagination.cursor,limit:pagination.pageSize,window:'7d',include_router_observations:includeRouterObservations})
  const columns=useMemo(()=>[
    {title:'风险对象',dataIndex:'ip',render:(value:string,item:RiskCase)=><div className="case-subject-cell"><Link className="mono" title={value||item.subject_id} to={detailPath(`/cases/${encodeURIComponent(item.case_id)}`,location.pathname+location.search)}>{value||item.subject_id}</Link><Typography.Text title={item.account_id||''} type="secondary">{item.account_id||''}</Typography.Text></div>},
    {title:'评估',render:(_:unknown,item:RiskCase)=><CaseAssessment item={item}/>},
    {title:'置信度',dataIndex:'risk_confidence',render:(value:number,item:RiskCase)=><Typography.Text type={item.assessment_current===false?'secondary':undefined}>{Math.round(value*100)}%</Typography.Text>},
    {title:'位置/院系',render:(_:unknown,item:RiskCase)=><span className="ellipsis-cell" title={[item.campus_id,item.department].filter(Boolean).join(' / ')}>{[item.campus_id,item.department].filter(Boolean).join(' / ')||''}</span>},
    {title:'负责人',dataIndex:'assignee_id',render:(value?:string)=>value||''},
    {title:'状态',dataIndex:'status',render:(value:string)=><Tag>{statusNames[value]??value}</Tag>},
    {title:'SLA 截止',dataIndex:'due_at',render:(value:string)=>{const time=formatCompactTime(value);return <span className="nowrap-cell" title={time?new Date(value).toLocaleString():undefined}>{time}</span>}},
  ],[location.pathname,location.search])
  if(query.isLoading)return <AppLoadingState rows={8}/>
  if(query.isError||!query.data)return <AppErrorAlert title="风险处置队列加载失败"/>
  return <main className="page">
    <AppPageHeader title="风险案件" subtitle="按案件完成分派、调查、复核、处置与审计闭环" loading={query.isFetching} onRefresh={()=>void query.refetch()} />
    <AppTableBar searchPlaceholder="搜索 IP、账号、终端或院系" searchValue={q} onSearchChange={value=>{setQ(value)}} totalCount={query.data.page.total} extra={<Space wrap><span className="case-router-toggle"><Switch aria-label="显示路由器观察" checked={includeRouterObservations} onChange={setIncludeRouterObservations}/><Typography.Text>显示路由器观察</Typography.Text></span><Select aria-label="案件状态" value={status} onChange={value=>{setStatus(value)}} options={[{value:'',label:'全部状态'},...Object.entries(statusNames).map(([value,label])=>({value,label}))]} /></Space>} />
    {writable&&<section className="surface case-batch-toolbar"><Typography.Text>已选 {selected.length} 项</Typography.Text><Input aria-label="批量负责人" placeholder="负责人账号" value={assignee} onChange={event=>setAssignee(event.target.value)}/><Button disabled={selected.length===0||!assignee.trim()} loading={batch.isPending} onClick={()=>batch.mutate({caseIds:selected,operation:'assign',assigneeId:assignee.trim()},{onSuccess:()=>{setSelected([]);void message.success('案件已批量分派')}})}>批量分派</Button><Button danger disabled={selected.length===0} loading={batch.isPending} onClick={()=>batch.mutate({caseIds:selected,operation:'close'},{onSuccess:()=>{setSelected([]);void message.success('已批量关闭符合条件的案件')}})}>批量关闭</Button></section>}
    <details className="surface filter-disclosure"><summary>高校维度筛选</summary><div className="filter-disclosure-content"><UniversityDimensionFilters value={dimensions} onChange={(next)=>{setDimensions(next)}} /></div></details>
    <div className="desktop-only"><Table className="compact-list-table" columns={columns} dataSource={query.data.items} pagination={false} rowKey="case_id" rowSelection={writable?{selectedRowKeys:selected,onChange:(keys)=>setSelected(keys.map(String))}:undefined} tableLayout="fixed" /></div>
    <List className="mobile-only mobile-case-list" dataSource={query.data.items} renderItem={item=><List.Item><Card className="mobile-case-card" size="small"><div className="mobile-case-head">{writable&&<Checkbox aria-label={`选择案件 ${item.case_id}`} checked={selected.includes(item.case_id)} onChange={event=>setSelected(current=>event.target.checked?[...current,item.case_id]:current.filter(id=>id!==item.case_id))}/>}<Link to={detailPath(`/cases/${encodeURIComponent(item.case_id)}`,location.pathname+location.search)}>{item.ip||item.subject_id}</Link><CaseAssessment item={item}/></div><div className="mobile-case-row"><span>{item.account_id||''}</span><span>{statusNames[item.status]}</span></div><div className="mobile-case-row"><span>{item.campus_id||''}</span><span>{item.assignee_id||''}</span></div></Card></List.Item>} />
    <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={query.data.page.total} onChange={pagination.update} />
  </main>
}

function formatCompactTime(value:string) {
  if(!value)return ''
  const date = new Date(value)
  if(!Number.isFinite(date.getTime()))return ''
  const pad = (part:number) => String(part).padStart(2,'0')
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}
