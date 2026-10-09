import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Empty, Select, Statistic, Tag, Typography, message } from 'antd'
import { policiesAPI, type ImportBatch } from './api'

const dispositionNames: Record<string,string> = {direct:'可直接转换',reference_only:'仅作参考',configuration_required:'需要补充配置',rejected:'拒绝转换'}
const reasonNames: Record<string,string> = {maximum_positive_max_online_num:'已采用正数会话上限的最大值',product_baseline_only:'账号个性化上限未纳入，本项仅为产品基线',unsupported_fields_preserved_as_reference:'旧防代理字段仅保留为来源参考',positive_max_online_num_missing:'没有可转换的正数会话上限',referenced_control_missing:'关联的控制策略不在完整快照内',device_quota_fields_missing:'规范化设备配额字段为空',session_quota_exceeded:'认证会话数超限',identity_coverage_incomplete:'身份覆盖不足',product_policy_catalog_unavailable:'产品策略目录读取失败',product_policy_snapshot_stale:'产品策略快照已过期',product_missing:'产品已从完整目录停用'}

export function PolicyImportPanel({writable}:{writable:boolean}) {
 const cache=useQueryClient()
 const status=useQuery({queryKey:['product-policy-status'],queryFn:policiesAPI.productPolicyStatus,retry:false})
 const catalog=useQuery({queryKey:['product-policy-catalog'],queryFn:policiesAPI.productCatalog,retry:false})
 const decisions=useQuery({queryKey:['policy-decisions'],queryFn:policiesAPI.decisions,retry:false})
 const sources=useMemo(()=>Array.from(new Set((catalog.data?.items??[]).map(item=>item.source))).sort(),[catalog.data])
 const [source,setSource]=useState<string>()
 const [batch,setBatch]=useState<ImportBatch>()
 const selectedSource=source??sources[0]
 const preview=useMutation({mutationFn:()=>policiesAPI.previewImport(selectedSource),onSuccess:setBatch,onError:(error:Error)=>message.error(error.message)})
 const publish=useMutation({mutationFn:()=>policiesAPI.publishImport(batch!.batch_id),onSuccess:result=>{setBatch(current=>current?{...current,status:'published'}:current);void cache.invalidateQueries({queryKey:['policies']});message.success(`已发布 ${result.policies.length} 条仅观测策略`)},onError:(error:Error)=>message.error(error.message)})
 return <div className="policy-import-section">
  <Card title="产品策略接入状态">
   {status.isError?<Alert type="warning" title="产品策略目录尚未就绪"/>:<div className="policy-stat-grid">
    <Statistic title="有效产品" value={status.data?.active_products??0}/><Statistic title="有效控制策略" value={status.data?.active_controls??0}/><Statistic title="不可变快照" value={status.data?.snapshots??0}/>
   </div>}
   {status.data?.last_received_at&&<Typography.Text type="secondary">最近接收：{new Date(status.data.last_received_at).toLocaleString()}</Typography.Text>}
   <div className="policy-toolbar"><Select aria-label="策略来源" value={selectedSource} onChange={setSource} options={sources.map(value=>({value,label:value}))} className="policy-source-select"/><Button type="primary" disabled={!writable||!selectedSource} loading={preview.isPending} onClick={()=>preview.mutate()}>生成导入预览</Button></div>
   <div className="policy-catalog-list">{catalog.data?.items.filter(item=>item.active).map(item=><article key={`${item.source}:${item.product_id}`} className="policy-catalog-item"><strong>{item.name}</strong><Typography.Text className="policy-identifier" type="secondary">{item.product_id}</Typography.Text>{item.document.control_ids?.length?<Tag>{item.document.control_ids.length} 条关联控制策略</Tag>:null}</article>)}</div>
  </Card>
  {batch&&<Card title="导入差异预览" extra={<Tag>{batch.status==='published'?'已发布':'待发布'}</Tag>}>
   <Alert type="info" title="发布结果固定为启用、仅观测" description="旧系统动作字段不会改变风险结论，也不会创建真实处置动作。"/>
   {batch.preview.items.map(item=><article className="policy-import-item" key={`${item.external_type}:${item.external_id}`}><div className="policy-tags"><strong>{item.name}</strong><Tag>{dispositionNames[item.disposition]??item.disposition}</Tag></div><Typography.Text className="policy-identifier" type="secondary">{item.external_id}</Typography.Text>{item.policy?.limits.sessions!=null&&<p>认证会话上限：{item.policy.limits.sessions}</p>}<p>{item.reasons.map(reason=>reasonNames[reason]??reason).join('；')}</p>{item.policy?.origin?.reference_fields?.length?<p className="policy-identifier">来源参考字段：{item.policy.origin.reference_fields.join('、')}</p>:null}</article>)}
   <div className="policy-toolbar"><Button type="primary" disabled={!writable||batch.status==='published'} loading={publish.isPending} onClick={()=>publish.mutate()}>发布仅观测策略</Button></div>
  </Card>}
  <Card title="影子判定记录">{decisions.data?.items.length?decisions.data.items.map(item=><article className="policy-decision-item" key={item.decision_id}><div className="policy-tags"><strong>{item.account_id}</strong><Tag color={item.known?(item.violated?'orange':'green'):'default'}>{item.known?(item.violated?'影子命中':'未命中'):'等待数据'}</Tag></div><Typography.Text className="policy-identifier" type="secondary">{item.policy_id}</Typography.Text>{item.product_ids.length>0&&<p>产品：{item.product_ids.join('、')}</p>}{item.group_ids.length>0&&<p>用户组：{item.group_ids.join('、')}</p>}{item.identity_snapshot_ids?.length?<p className="policy-identifier">身份快照：{item.identity_snapshot_ids.join('、')}</p>:null}<p>{item.reasons.map(reason=>reasonNames[reason]??reason).join('、')}</p><Typography.Text type="secondary">{new Date(item.evaluated_at).toLocaleString()}</Typography.Text></article>):<Empty description="尚无影子判定记录"/>}</Card>
 </div>
}
