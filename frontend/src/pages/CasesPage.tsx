import { Link } from 'react-router-dom'
import { Card, List, Select, Space, Table, Tag, Typography } from 'antd'
import { useMemo, useState } from 'react'

import { useCases } from '../shared/api/queries'
import type { RiskCase } from '../shared/api/types'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppTableBar, UniversityDimensionFilters, type UniversityDimensions } from '../shared/ui'

const statusNames: Record<string,string> = {new:'新建',assigned:'已分派',investigating:'调查中',waiting_data:'等待数据',resolved:'已解决',closed:'已关闭',reopened:'重新打开'}
const priorityColors: Record<string,string> = {high:'red',medium:'orange',low:'blue'}

export function CasesPage() {
  const [q,setQ]=useState('')
  const [status,setStatus]=useState('')
  const [cursor,setCursor]=useState<string|undefined>()
  const [dimensions,setDimensions]=useState<UniversityDimensions>({})
  const query=useCases({q,status:status||undefined,...dimensions,cursor,limit:20,window:'7d'})
  const columns=useMemo(()=>[
    {title:'风险对象',dataIndex:'ip',render:(value:string,item:RiskCase)=><div className="case-subject-cell"><Link className="mono" title={value||item.subject_id} to={`/cases/${encodeURIComponent(item.case_id)}`}>{value||item.subject_id}</Link><Typography.Text title={item.account_id||'身份待关联'} type="secondary">{item.account_id||'身份待关联'}</Typography.Text></div>},
    {title:'评估',render:(_:unknown,item:RiskCase)=><Space size={4}><Tag color={priorityColors[item.priority]}>{item.assessment_level==='high'?'高风险':'可疑'}</Tag><Typography.Text>{item.risk_score} 分</Typography.Text></Space>},
    {title:'置信度',dataIndex:'risk_confidence',render:(value:number)=>`${Math.round(value*100)}%`},
    {title:'位置/院系',render:(_:unknown,item:RiskCase)=><span className="ellipsis-cell" title={[item.campus_id,item.department].filter(Boolean).join(' / ')}>{[item.campus_id,item.department].filter(Boolean).join(' / ')||'待关联'}</span>},
    {title:'负责人',dataIndex:'assignee_id',render:(value?:string)=>value||'未分派'},
    {title:'状态',dataIndex:'status',render:(value:string)=><Tag>{statusNames[value]??value}</Tag>},
    {title:'SLA 截止',dataIndex:'due_at',render:(value:string)=><span className="nowrap-cell">{new Date(value).toLocaleString()}</span>},
  ],[])
  if(query.isLoading)return <AppLoadingState rows={8}/>
  if(query.isError||!query.data)return <AppErrorAlert title="风险处置队列加载失败"/>
  return <main className="page">
    <AppPageHeader title="风险处置" subtitle="按案件完成分派、调查、复核、处置与审计闭环" loading={query.isFetching} onRefresh={()=>void query.refetch()} />
    <AppTableBar searchPlaceholder="搜索 IP、账号、终端或院系" searchValue={q} onSearchChange={value=>{setQ(value);setCursor(undefined)}} totalCount={query.data.page.total} extra={<Select aria-label="案件状态" value={status} onChange={value=>{setStatus(value);setCursor(undefined)}} options={[{value:'',label:'全部状态'},...Object.entries(statusNames).map(([value,label])=>({value,label}))]} />} />
    <section className="surface filter-surface"><UniversityDimensionFilters value={dimensions} onChange={(next)=>{setDimensions(next);setCursor(undefined)}} /></section>
    <div className="desktop-only"><Table className="compact-list-table" columns={columns} dataSource={query.data.items} pagination={false} rowKey="case_id" tableLayout="fixed" /></div>
    <List className="mobile-only mobile-case-list" dataSource={query.data.items} renderItem={item=><List.Item><Card className="mobile-case-card" size="small"><div className="mobile-case-head"><Link to={`/cases/${encodeURIComponent(item.case_id)}`}>{item.ip||item.subject_id}</Link><Tag color={priorityColors[item.priority]}>{item.risk_score} 分</Tag></div><div className="mobile-case-row"><span>{item.account_id||'身份待关联'}</span><span>{statusNames[item.status]}</span></div><div className="mobile-case-row"><span>{item.campus_id||'校区待关联'}</span><span>{item.assignee_id||'未分派'}</span></div></Card></List.Item>} />
    <div className="list-pagination"><Typography.Text>第 {Math.floor((Number(cursor??0))/20)+1} 页</Typography.Text><Space><a onClick={()=>setCursor(undefined)}>回到第一页</a>{query.data.page.next_cursor&&<a onClick={()=>setCursor(query.data.page.next_cursor??undefined)}>下一页</a>}</Space></div>
  </main>
}
