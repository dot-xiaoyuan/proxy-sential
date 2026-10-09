import { reasonNames } from '../features/policies/reasonMeta'
import { Link } from 'react-router-dom'
import { PolicyStrategyEditor } from '../features/policies/PolicyStrategyEditor'
import { ProxyProtocolView } from '../entities/evidence/ProxyProtocolView'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Empty, Input, Switch, Tag, Typography, message } from 'antd'
import { policiesAPI, type Policy, type Simulation } from '../features/policies/api'
import { useActionConnectors, useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppPageHeader, AppLoadingState, AppErrorAlert } from '../shared/ui'

const triggerNames: Record<string,string> = {quota_exceeded:'设备配额',session_quota_exceeded:'认证会话配额',shared_access:'共享上网风险',explicit_proxy:'明确代理风险'}
const modeNames: Record<string,string> = {observe:'仅观测',manual:'人工确认',automatic:'自动执行'}
const emptyPolicy = (): Policy => ({policy_id:'',name:'',enabled:false,priority:0,mode:'automatic',trigger:'quota_exceeded',scope:{},exempt:{},limits:{total:null,mobile:null,pc:null,sessions:null},sustain_seconds:0,window_seconds:86400,recovery_seconds:0,cooldown_seconds:0,stages:[]})
export function PoliciesPage(){
 const query = useQuery({queryKey:['policies'],queryFn:policiesAPI.list})
 const executions = useQuery({queryKey:['policy-executions'],queryFn:policiesAPI.executions})
 const cache = useQueryClient(); const session = useSession()
 const writable=can(session.data,'policies:manage')
 const [editing,setEditing]=useState<Policy|null>(null);const [creating,setCreating]=useState(false)
 const directory=useQuery({queryKey:['four-k-directory'],queryFn:policiesAPI.fourKDirectory,retry:false,enabled:!!editing})
 const connectors=useActionConnectors(!!editing&&can(session.data,'actions:read'))
 const [account,setAccount]=useState('');const [simulation,setSimulation]=useState<Simulation|null>(null)
 const save=useMutation({mutationFn:(p:Policy)=>policiesAPI.save(p,creating),onSuccess:()=>{setEditing(null);void cache.invalidateQueries({queryKey:['policies']});message.success('策略已保存')},onError:(e:Error)=>message.error(e.message)})
 const toggle=useMutation({mutationFn:(p:Policy)=>policiesAPI.save(p,false),onSuccess:()=>{void cache.invalidateQueries({queryKey:['policies']});message.success('策略开关已更新')},onError:(e:Error)=>message.error(e.message)})
 const simulate=useMutation({mutationFn:(id:string)=>policiesAPI.simulate(id,account),onSuccess:setSimulation,onError:(e:Error)=>message.error(e.message)})
 if(query.isLoading)return <AppLoadingState rows={5}/>
 if(query.isError)return <AppErrorAlert title="策略加载失败"/>
 const edit=(p:Policy,isNew=false)=>{setCreating(isNew);setEditing(p)}
 return <div className="policies-page">
 <AppPageHeader title="防代理策略" subtitle="设备配额、共享上网和明确代理分别评估，处置范围为账号全部在线会话。"/>
 <div className="policy-toolbar"><Input aria-label="试算账号" placeholder="输入认证账号进行试算" value={account} onChange={e=>setAccount(e.target.value)}/><Button type="primary" disabled={!writable} onClick={()=>edit(emptyPolicy(),true)}>新建设备配额策略</Button></div>
 <Alert type="info" showIcon title="新建策略默认停用" description="保存时选择真实执行或仅记录；打开策略开关后才生效。身份或事件通道不完整时，真实动作由服务端阻断并记录原因。"/>
 <div className="policy-cards">{query.data?.items.map(p=><Card key={p.policy_id} title={p.name} extra={<Switch aria-label={`${p.name}策略开关`} checked={p.enabled} disabled={!writable||toggle.isPending||Boolean(p.origin)} onChange={enabled=>toggle.mutate({...p,enabled})}/>}>
 <div className="policy-tags"><Tag>{triggerNames[p.trigger]}</Tag><Tag>{modeNames[p.mode]}</Tag><Tag>{p.enabled?'已启用':'已停用'}</Tag></div>
 {p.trigger==='quota_exceeded'&&<Typography.Paragraph>认定条件：{[p.limits.total!=null&&`全部设备数 > ${p.limits.total}`,p.limits.pc!=null&&`电脑数量 > ${p.limits.pc}`,p.limits.mobile!=null&&`移动设备数量 > ${p.limits.mobile}`].filter(Boolean).join('，')}</Typography.Paragraph>}
 {p.stages.length>0&&<Typography.Paragraph>处理动作：{p.stages.length?p.stages.map(stage=>({notify:'消息提醒',disconnect:'强制下线',rate_limit:'带宽降速',disable_account:'用户封禁',record:'仅记录'}[stage.action]??stage.action)).join('，'):''}</Typography.Paragraph>}
 {p.trigger==='session_quota_exceeded'?<Typography.Paragraph>认证会话上限：{p.limits.sessions}</Typography.Paragraph>:p.trigger==='quota_exceeded'?<Typography.Paragraph>设备上限：总数 {p.limits.total??'不限'} / 手机 {p.limits.mobile??'不限'} / 电脑 {p.limits.pc??'不限'}</Typography.Paragraph>:null}
 {p.origin&&<Typography.Paragraph type="secondary">来源：{p.origin.source} · 快照 {p.origin.snapshot_id}</Typography.Paragraph>}
 <Typography.Text type="secondary" className="policy-identifier">{p.policy_id}</Typography.Text>
 {(p.trigger!=='quota_exceeded'||p.origin)&&<Typography.Paragraph type="secondary">{p.origin?'此策略由来源系统同步，当前页面仅供查看。':'此类策略编辑尚未开放，现有评估和复核流程继续生效。'}</Typography.Paragraph>}<div className="policy-toolbar"><Button disabled={!writable||p.trigger!=='quota_exceeded'||Boolean(p.origin)} onClick={()=>edit(p)}>编辑策略</Button><Button disabled={!account.trim()} loading={simulate.isPending} onClick={()=>simulate.mutate(p.policy_id)}>策略试算</Button></div>
 </Card>)}</div>{!query.data?.items.length&&<Empty description="尚未配置防代理策略"/>}
 {simulation&&<Card title={`账号 ${simulation.account_id} 的试算结果`}>
 <Typography.Paragraph>已确认终端 {simulation.inventory.total} 台 · 手机 {simulation.inventory.mobile} · 电脑 {simulation.inventory.pc} · 其他 {simulation.inventory.other} · 不确定会话 {simulation.inventory.uncertain_sessions}</Typography.Paragraph>
 {!simulation.inventory.coverage_complete&&<Alert type="warning" title="覆盖不足，无法完整判断在线设备数"/>}
 {simulation.explanations.map(e=><p key={e.policy_id} className="policy-identifier">{e.policy_id}：{reasonNames[e.reason]??e.reason}</p>)}
 {simulation.evaluations.map(e=><div key={e.policy_id}><p>{e.shared_evaluation ? (e.input.known ? (e.input.violated ? '存在共享依据' : '当前未命中') : '证据不足') : e.input.known?(e.input.violated?'违规成立':'未超限'):'等待数据'}：{e.input.reasons.map(r=>reasonNames[r]??r).join('、')}</p>{e.proxy_evidence?.map(proof=><ProxyProtocolView key={proof.evidence_id} evidence={proof}/>)}{e.shared_error&&<Alert type="warning" title="共享证据读取失败" description="本次保留证据不足，不作为恢复依据。"/>}{e.shared_evaluation?.map((proof,index)=><div className="policy-execution policy-identifier" key={proof.id??`${proof.ip}-${proof.sensor_id}-${index}`}><strong>{proof.ip} · {{basis_present:'存在共享依据',not_matched:'当前未命中',insufficient:'证据不足'}[proof.state]}</strong>{(proof.account_id||proof.campus_id||proof.access_domain)&&<p>{[proof.account_id&&`事件时账号：${proof.account_id}`,proof.campus_id&&`园区：${proof.campus_id}`,proof.access_domain&&`接入域：${proof.access_domain}`].filter(Boolean).join(' · ')}</p>}{(proof.quantity_known||proof.sensor_id)&&<p>{[proof.quantity_known&&`已确认设备下界：${proof.device_lower_bound}`,proof.sensor_id&&`传感器：${proof.sensor_id}`].filter(Boolean).join(' · ')}</p>}{proof.from&&proof.to&&<p>观测窗口：{proof.from} 至 {proof.to}</p>}{proof.signal_groups?.length?<p>信号：{proof.signal_groups.map(group=>({ua_os:'UA 系统差异',ttl_path:'TTL 路径差异',tls_stack:'TLS 特征差异',dhcp_stack:'DHCP 特征差异',confirmed_same_exit_endpoints:'同出口已确认终端'}[group]??group)).join('、')}</p>:null}{(proof.rule_version||proof.config_version)&&<p>{[proof.rule_version&&`规则：${proof.rule_version}`,proof.config_version&&`来源配置：${proof.config_version}`].filter(Boolean).join(' · ')}</p>}<p>{proof.reasons.map(reason=>reasonNames[reason]??reason).join('、')}</p>{proof.records?.length?<details><summary>原始记录依据</summary>{proof.records.map(record=><p key={`${record.source}-${record.collector_instance_id}-${record.event_id}`}>{[record.source,record.collector_instance_id,record.event_id].filter(Boolean).join(' · ')}</p>)}</details>:null}</div>)}</div>)}
 </Card>}
 <Card title="执行摘要"><Typography.Paragraph>当前记录 {executions.data?.items.length ?? 0} 条</Typography.Paragraph><Link to="/actions?tab=executions">查看策略执行与审批记录</Link></Card>
 {editing&&<PolicyStrategyEditor policy={editing} creating={creating} directory={directory.data} connectors={connectors.data?.items??[]} saving={save.isPending} onCancel={()=>setEditing(null)} onSave={policy=>save.mutate(policy)}/>}
 </div>
}
