import { Link } from 'react-router-dom'
import { App as AntApp, Button, Card, Checkbox, Input, List, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import { useMemo, useState } from 'react'

import { useCases, useCasesBatchMutation, useSession } from '../shared/api/queries'
import type { RiskCase } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppServerPagination, AppTableBar, UniversityDimensionFilters, useServerPagination, type UniversityDimensions } from '../shared/ui'
import { can } from '../shared/auth/permissions'

const statusNames: Record<string,string> = {new:'新建',assigned:'已分派',investigating:'调查中',waiting_data:'等待数据',resolved:'已解决',closed:'已关闭',reopened:'重新打开'}
const priorityColors: Record<string,string> = {high:'red',medium:'orange',low:'blue'}

export function CasesPage() {
  const [q,setQ]=useState('')
  const [status,setStatus]=useState('')
	const [includeRouterObservations,setIncludeRouterObservations]=useState(true)
	const pagination=useServerPagination()
  const [dimensions,setDimensions]=useState<UniversityDimensions>({})
  const [selected,setSelected]=useState<string[]>([])
  const [assignee,setAssignee]=useState('')
  const batch=useCasesBatchMutation();const session=useSession();const {message}=AntApp.useApp();const writable=can(session.data,'cases:write')
  const query=useCases({q,status:status||undefined,...dimensions,cursor:pagination.cursor,limit:pagination.pageSize,window:'7d',include_router_observations:includeRouterObservations})
  const columns=useMemo(()=>[
    {title:'风险对象',dataIndex:'ip',render:(value:string,item:RiskCase)=><div className="case-subject-cell"><Link className="mono" title={value||item.subject_id} to={`/cases/${encodeURIComponent(item.case_id)}`}>{value||item.subject_id}</Link>{item.account_id&&<Typography.Text title={item.account_id} type="secondary">{item.account_id}</Typography.Text>}</div>},
    {title:'评估',render:(_:unknown,item:RiskCase)=><Space wrap size={4} className="case-assessment-cell"><Tag color={priorityColors[item.priority]}>{caseAssessmentText(item)}</Tag><Typography.Text>{item.risk_score} 分</Typography.Text></Space>},
    {title:'置信度',dataIndex:'risk_confidence',render:(value:number)=>`${Math.round(value*100)}%`},
    {title:'位置/院系',render:(_:unknown,item:RiskCase)=><span className="ellipsis-cell" title={[item.campus_id,item.department].filter(Boolean).join(' / ')}>{[item.campus_id,item.department].filter(Boolean).join(' / ')}</span>},
    {title:'负责人',dataIndex:'assignee_id',render:(value?:string)=>value||''},
    {title:'状态',dataIndex:'status',render:(value:string)=><Tag>{statusNames[value]??value}</Tag>},
    {title:'SLA 截止',dataIndex:'due_at',render:(value:string)=><span className="nowrap-cell" title={new Date(value).toLocaleString()}>{formatCompactTime(value)}</span>},
  ],[])
  if(query.isLoading)return <AppLoadingState rows={8}/>
  if(query.isError||!query.data)return <AppErrorAlert title="风险处置队列加载失败"/>
  return <main className="page">
    <AppPageHeader title="风险处置" subtitle="按案件完成分派、调查、复核、处置与审计闭环" loading={query.isFetching} onRefresh={()=>void query.refetch()} />
    <AppTableBar searchPlaceholder="搜索 IP、账号、终端或院系" searchValue={q} onSearchChange={value=>{setQ(value);pagination.reset()}} totalCount={query.data.page.total} extra={<Space wrap className="case-queue-filters"><Space size={6}><Typography.Text>包含路由设备观察</Typography.Text><Switch aria-label="包含路由设备观察" checked={includeRouterObservations} onChange={checked=>{setIncludeRouterObservations(checked);pagination.reset()}} /></Space><Select aria-label="案件状态" value={status} onChange={value=>{setStatus(value);pagination.reset()}} options={[{value:'',label:'全部状态'},...Object.entries(statusNames).map(([value,label])=>({value,label}))]} /></Space>} />
    {writable&&<section className="surface case-batch-toolbar"><Typography.Text>已选 {selected.length} 项</Typography.Text><Input aria-label="批量负责人" placeholder="负责人账号" value={assignee} onChange={event=>setAssignee(event.target.value)}/><Button disabled={selected.length===0||!assignee.trim()} loading={batch.isPending} onClick={()=>batch.mutate({caseIds:selected,operation:'assign',assigneeId:assignee.trim()},{onSuccess:()=>{setSelected([]);void message.success('案件已批量分派')}})}>批量分派</Button><Button danger disabled={selected.length===0} loading={batch.isPending} onClick={()=>batch.mutate({caseIds:selected,operation:'close'},{onSuccess:()=>{setSelected([]);void message.success('已批量关闭符合条件的案件')}})}>批量关闭</Button></section>}
    <details className="surface filter-disclosure"><summary>高校维度筛选</summary><div className="filter-disclosure-content"><UniversityDimensionFilters value={dimensions} onChange={(next)=>{setDimensions(next);pagination.reset()}} /></div></details>
    <div className="desktop-only"><Table className="compact-list-table" columns={columns} dataSource={query.data.items} pagination={false} rowKey="case_id" rowSelection={writable?{selectedRowKeys:selected,onChange:(keys)=>setSelected(keys.map(String))}:undefined} tableLayout="fixed" /></div>
    <List className="mobile-only mobile-case-list" dataSource={query.data.items} renderItem={item=><List.Item><Card className="mobile-case-card" size="small"><div className="mobile-case-head">{writable&&<Checkbox aria-label={`选择案件 ${item.case_id}`} checked={selected.includes(item.case_id)} onChange={event=>setSelected(current=>event.target.checked?[...current,item.case_id]:current.filter(id=>id!==item.case_id))}/>}<Link to={`/cases/${encodeURIComponent(item.case_id)}`}>{item.ip||item.subject_id}</Link><Tag color={priorityColors[item.priority]}>{caseAssessmentText(item)} · {item.risk_score} 分</Tag></div><div className="mobile-case-row">{item.account_id&&<span>{item.account_id}</span>}<span>{statusNames[item.status]}</span></div><div className="mobile-case-row">{item.campus_id&&<span>{item.campus_id}</span>}{item.assignee_id&&<span>{item.assignee_id}</span>}</div></Card></List.Item>} />
    <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={query.data.page.total} onChange={pagination.update} />
  </main>
}

function caseAssessmentText(item:RiskCase) {
  if(item.risk_kind==='router_observation')return item.assessment_level==='confirmed'?'已确认路由器':'较可信路由器观察'
  return item.assessment_level==='confirmed'?'已确认共享':item.assessment_level==='high'?'高风险':'可疑'
}

function formatCompactTime(value:string) {
  const date = new Date(value)
  const pad = (part:number) => String(part).padStart(2,'0')
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}
