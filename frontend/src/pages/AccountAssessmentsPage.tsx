import { CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import { App as AntApp, Alert, Button, Form, Input, Modal, Select, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useState } from 'react'

import { useAccountAssessment, useAccountAssessments, useAccountTagReview, useSession } from '../shared/api/queries'
import type { AccountAssessmentPage, AccountTagAssessment, AccountTagReviewRequest, AccountTagType } from '../shared/api/types'
import { can } from '../shared/auth/permissions'
import { AppErrorAlert, AppLoadingState, AppPageHeader, AppServerPagination, useServerPagination } from '../shared/ui'

const tagLabels: Record<AccountTagType,string>={proxy:'代理',router:'路由器',mobile:'手机',pc:'PC'}
const evidenceLabels={confirmed:'已确认',likely:'较可信',clue:'线索'}
const reviewLabels={pending:'待复核',confirm:'已确认',reject:'已否决'}
const conclusionKey=(item:AccountTagAssessment)=>[item.tag_type,item.evidence_level,item.source_type,item.reason,item.rule_version].join('\u0000')

function AssessmentTags({items}:{items:AccountTagAssessment[]}) {
  return <div className="account-tag-list">{items.map(item=><Tag className={`account-tag account-tag-${item.tag_type}`} key={`${item.tag_type}:${item.assessment_version}`}>{tagLabels[item.tag_type]}<span>{evidenceLabels[item.evidence_level]}</span></Tag>)}</div>
}

export function AccountAssessmentsPage(){
  const [params,setParams]=useSearchParams();const pagination=useServerPagination('accounts_');const [search,setSearch]=useState(params.get('q')||'')
  const tags=params.get('tag')||undefined;const review=params.get('review_state') as 'pending'|'confirm'|'reject'|null
  const query={q:params.get('q')||undefined,tag:tags,review_state:review||undefined,limit:pagination.pageSize,cursor:pagination.cursor}
  const result=useAccountAssessments(query)
  const change=(key:string,value?:string)=>setParams(current=>{const next=new URLSearchParams(current);if(value)next.set(key,value);else next.delete(key);next.set('accounts_page','1');return next},{replace:true})
  if(result.isLoading)return <AppLoadingState rows={7}/>
  if(result.isError)return <AppErrorAlert title="用户研判读取失败"/>
  const data=result.data as AccountAssessmentPage
  const columns:ColumnsType<AccountAssessmentPage['items'][number]>=[
    {title:'认证账号',dataIndex:'account_id',render:value=><Link className="account-id" to={`/accounts/${encodeURIComponent(value)}`}>{value}</Link>},
    {title:'当前标签',dataIndex:'tags',render:items=><AssessmentTags items={items}/>},
    {title:'关联终端',dataIndex:'endpoint_count',width:100,render:value=>`${value} 台`},
    {title:'主要依据',dataIndex:'primary_reason',render:value=><Typography.Text className="account-reason">{value}</Typography.Text>},
    {title:'复核状态',dataIndex:'review_state',width:100,render:value=><Tag>{reviewLabels[value as keyof typeof reviewLabels]}</Tag>},
    {title:'最近研判',dataIndex:'last_assessed_at',width:170,render:value=>time(value)},
  ]
  return <main className="page account-assessment-page">
    <AppPageHeader title="用户研判" subtitle="按认证账号查看近 7 天的终端类型、路由设备关联和代理风险标签" onRefresh={()=>void result.refetch()}/>
    <section className="surface account-assessment-help">这里按账号汇总已关联终端和风险线索，供人工核对。手机、PC、路由器标签表示设备识别或绑定关系，不等于该账号正在路由共享；是否确认共享及是否触发仅记录策略，请查看 <Link to="/shared-access?tab=observations">共享发现</Link>。</section>
    {data.state==='processing'&&<Alert showIcon type="info" title="标签投影处理中" description="已完成结果可以查询，未处理任务不会显示为完成。"/>}
    {data.state==='failed'&&<Alert showIcon type="warning" title="标签投影更新异常" description="当前展示最近一次成功结果，请核对后台任务。"/>}
    <section className="surface account-assessment-filters">
      <Input.Search allowClear placeholder="搜索认证账号" value={search} onChange={event=>setSearch(event.target.value)} onSearch={value=>change('q',value.trim()||undefined)}/>
      <Select allowClear aria-label="用户标签" placeholder="用户标签" value={tags} onChange={value=>change('tag',value)} options={Object.entries(tagLabels).map(([value,label])=>({value,label}))}/>
      <Select allowClear aria-label="复核状态" placeholder="复核状态" value={review||undefined} onChange={value=>change('review_state',value)} options={Object.entries(reviewLabels).map(([value,label])=>({value,label}))}/>
    </section>
    <section className="surface account-assessment-table desktop-only"><Table columns={columns} dataSource={data.items} pagination={false} rowKey="account_id"/></section>
    <div className="mobile-only account-assessment-mobile">{data.items.map(item=><article className="account-assessment-card" key={item.account_id}><div className="account-assessment-card-head"><Link className="account-id" to={`/accounts/${encodeURIComponent(item.account_id)}`}>{item.account_id}</Link><Tag>{reviewLabels[item.review_state]}</Tag></div><AssessmentTags items={item.tags}/><p>{item.primary_reason}</p><div className="account-assessment-meta"><span>{item.endpoint_count} 台终端</span><span>{time(item.last_assessed_at)}</span></div></article>)}</div>
    <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={data.page.total} onChange={pagination.update}/>
  </main>
}

export function AccountAssessmentDetailsPage(){
  const accountId=decodeURIComponent(useParams().accountId||'');const result=useAccountAssessment(accountId);const session=useSession();const review=useAccountTagReview(accountId);const {message}=AntApp.useApp();const [selected,setSelected]=useState<AccountTagAssessment>();const [decision,setDecision]=useState<'confirm'|'reject'>('confirm');const [form]=Form.useForm<{reason:string}>()
  if(result.isLoading)return <AppLoadingState rows={7}/>
  if(result.isError||!result.data)return <AppErrorAlert title="用户研判详情读取失败"/>
  const data=result.data
  const submit=async()=>{if(!selected)return;const values=await form.validateFields();const payload:AccountTagReviewRequest={tag_type:selected.tag_type,assessment_version:selected.assessment_version,decision,reason:values.reason};review.mutate(payload,{onSuccess:()=>{message.success(decision==='confirm'?'标签已确认':'标签已否决');setSelected(undefined);form.resetFields()},onError:()=>message.error('提交失败，研判版本可能已经变化，请刷新后重试')})}
  const currentConclusions=new Set(data.tags.map(conclusionKey));const seenConclusions=new Set<string>()
  const historical=data.history.filter(item=>{const key=conclusionKey(item);if(currentConclusions.has(key)||seenConclusions.has(key))return false;seenConclusions.add(key);return true})
  const historyItems=[...data.reviews.map(item=>({key:item.review_id,time:item.created_at,title:`${tagLabels[item.tag_type]} · ${reviewLabels[item.decision]}`,reason:item.reason})),...historical.map(item=>({key:item.assessment_version,time:item.recorded_at||item.last_seen,title:`${tagLabels[item.tag_type]} · ${evidenceLabels[item.evidence_level]}`,reason:item.reason}))].sort((a,b)=>b.time.localeCompare(a.time))
  return <main className="page account-assessment-detail">
    <AppPageHeader title={accountId} subtitle="认证账号关联的终端标签与依据；标签不等于当前共享确认" extra={<Link to="/accounts">返回用户研判</Link>} onRefresh={()=>void result.refetch()}/>
    {data.state!=='ready'&&<Alert showIcon type={data.state==='failed'?'warning':'info'} title={data.state==='failed'?'标签投影更新异常':'标签投影处理中'}/>} 
    <section className="surface account-tag-summary"><div className="surface-title-row"><Typography.Title level={4}>当前标签</Typography.Title><Typography.Text type="secondary">更新于 {time(data.as_of)}</Typography.Text></div>{data.tags.length?<div className="account-tag-detail-list">{data.tags.map(item=><article className="account-tag-detail" key={item.tag_type}><div className="account-tag-detail-head"><AssessmentTags items={[item]}/><Tag>{reviewLabels[item.review_state]}</Tag></div><Typography.Paragraph>{item.reason}</Typography.Paragraph><dl><div><dt>证据等级</dt><dd>{evidenceLabels[item.evidence_level]}</dd></div><div><dt>观测窗口</dt><dd>{time(item.first_seen)} 至 {time(item.last_seen)}</dd></div>{item.rule_version&&<div><dt>规则版本</dt><dd className="account-version">{item.rule_version}</dd></div>}</dl><details><summary>查看依据</summary><div className="account-evidence-list">{item.evidence_ids.map(id=><span key={id}>{id}</span>)}</div></details>{can(session.data,'labels:create')&&<div className="account-review-actions"><Button icon={<CheckCircleOutlined/>} onClick={()=>{setDecision('confirm');setSelected(item)}}>确认</Button><Button danger icon={<CloseCircleOutlined/>} onClick={()=>{setDecision('reject');setSelected(item)}}>否决</Button></div>}</article>)}</div>:<Typography.Text type="secondary"></Typography.Text>}</section>
    <section className="surface"><Typography.Title level={4}>关联终端</Typography.Title><div className="account-endpoint-grid">{data.endpoints.map(item=><article className="account-endpoint" key={item.endpoint_id}><Link to={`/devices/${encodeURIComponent(item.endpoint_id)}`}>{item.primary_mac||item.endpoint_id}</Link><strong>{[item.brand,item.model].filter(Boolean).join(' ')}</strong><span>{item.device_type?deviceType(item.device_type):''}</span><span>{time(item.last_seen)}</span></article>)}</div></section>
    <section className="surface account-history-section"><Typography.Title level={4}>研判历史</Typography.Title>{historyItems.length?<div className="account-history">{historyItems.map(item=><article key={item.key}><time>{time(item.time)}</time><strong>{item.title}</strong><span>{item.reason}</span></article>)}</div>:<Typography.Text type="secondary">暂无不同于当前标签的历史结论或人工复核；重复刷新记录已归并。</Typography.Text>}{data.history_has_more&&<Typography.Text type="secondary">仅显示最近 50 种历史结论。</Typography.Text>}</section>
    <Modal title={decision==='confirm'?'确认用户标签':'否决用户标签'} open={Boolean(selected)} confirmLoading={review.isPending} okText="提交复核" cancelText="取消" onCancel={()=>setSelected(undefined)} onOk={()=>void submit()}><Typography.Paragraph>本次操作仅针对当前研判版本，不改变识别算法，也不会触发处罚。</Typography.Paragraph><Form form={form} layout="vertical"><Form.Item name="reason" label="复核原因" rules={[{required:true,min:2,message:'请填写至少 2 个字符的复核原因'}]}><Input.TextArea rows={4}/></Form.Item></Form></Modal>
  </main>
}

function time(value?:string){return value?new Date(value).toLocaleString():''}
function deviceType(value:string){return ({mobile:'手机',tablet:'平板',desktop:'PC',pc:'PC',laptop:'PC',router:'路由器'} as Record<string,string>)[value]||value}
