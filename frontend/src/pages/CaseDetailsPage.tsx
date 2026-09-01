import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Alert, Button, Card, Descriptions, Divider, Input, Select, Space, Tag, Timeline, Typography, message } from 'antd'

import { can } from '../shared/auth/permissions'
import { useCase, useCaseMutation, useSession } from '../shared/api/queries'
import { AppErrorAlert, AppLoadingState, AppPageHeader } from '../shared/ui'

export function CaseDetailsPage(){
  const {caseId=''}=useParams();const item=useCase(caseId);const mutation=useCaseMutation();const session=useSession();const [comment,setComment]=useState('')
  if(item.isLoading)return <AppLoadingState rows={8}/>
  if(item.isError||!item.data)return <AppErrorAlert title="案件不存在或已超过保留期"/>
  const data=item.data;const writable=can(session.data,'cases:write')
  const mutate=(operation:'assign'|'status'|'disposition'|'comment',value:string)=>mutation.mutate({caseId:data.case_id,operation,value},{onSuccess:()=>message.success('案件已更新')})
  return <main className="page">
    <AppPageHeader title={`案件 ${data.case_id}`} subtitle="风险、身份、证据、复核结论与处置动作统一留痕" extra={<Link to="/cases">返回案件队列</Link>} />
    {!writable&&<Alert showIcon title="当前角色只有查看权限" type="info"/>}
    <section className="case-layout">
      <Card className="surface-card" title="案件摘要"><Space wrap><Tag color="red">{data.assessment_level}</Tag><Tag>{data.status}</Tag><Typography.Text strong>{data.risk_score} 分 / {Math.round(data.risk_confidence*100)}%</Typography.Text></Space><Descriptions className="margin-top-md" column={{xs:1,md:2}} items={[{key:'ip',label:'IP',children:<Link to={`/ips/${encodeURIComponent(data.ip??'')}`}>{data.ip||'-'}</Link>},{key:'account',label:'账号',children:data.account_id||'待关联'},{key:'endpoint',label:'终端',children:data.endpoint_id||'待关联'},{key:'campus',label:'校区',children:data.campus_id||'待关联'},{key:'department',label:'院系',children:data.department||'待关联'},{key:'due',label:'SLA 截止',children:new Date(data.due_at).toLocaleString()}]} /></Card>
      <Card className="surface-card" title="协同处置"><Space wrap><Input aria-label="负责人" className="case-assignee-input" disabled={!writable} placeholder="负责人账号" onPressEnter={event=>mutate('assign',event.currentTarget.value)} /><Select aria-label="案件状态" disabled={!writable} value={data.status} onChange={value=>mutate('status',value)} options={['new','assigned','investigating','waiting_data','resolved','closed','reopened'].map(value=>({value,label:value}))}/><Select aria-label="复核结论" disabled={!writable} placeholder="选择复核结论" onChange={value=>mutate('disposition',value)} options={[{value:'confirmed_proxy',label:'确认代理'},{value:'false_positive',label:'误报'},{value:'benign',label:'良性'},{value:'needs_more_data',label:'需要更多数据'}]}/></Space><Divider/><Input.TextArea disabled={!writable} placeholder="补充调查记录" value={comment} onChange={event=>setComment(event.target.value)} /><Button className="margin-top-sm" disabled={!writable||comment.trim().length<2} onClick={()=>{mutate('comment',comment);setComment('')}}>添加记录</Button></Card>
    </section>
    <Card className="surface-card margin-top-md" title="证据快照"><Typography.Paragraph>{data.evidence_snapshot?.event_count ? `共 ${data.evidence_snapshot.event_count} 条事件，TLS ${data.evidence_snapshot.tls_count}，QUIC ${data.evidence_snapshot.quic_count}，明确规则命中 ${data.evidence_snapshot.rule_matches?.length??0} 条。` : '暂无证据快照'}</Typography.Paragraph><Typography.Text type="secondary">案件保存发现时证据，规则更新不会覆盖历史判断。</Typography.Text></Card>
    <Card className="surface-card margin-top-md" title="案件时间线"><Timeline items={(data.timeline??[]).slice().reverse().map(event=>({children:<div><Typography.Text strong>{event.type}</Typography.Text><div><Typography.Text type="secondary">{event.actor_id} · {new Date(event.created_at).toLocaleString()}</Typography.Text></div></div>}))}/></Card>
  </main>
}
