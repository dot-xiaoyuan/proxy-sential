import { reasonNames } from '../features/policies/reasonMeta'
import { statusColor, statusText } from '../shared/ui/status'
import { useState } from 'react'
import { useMutation,useQuery,useQueryClient } from '@tanstack/react-query'
import { Button, Tag, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApprovalPreview } from '../features/policies/ApprovalPreview'
import { ProxyProtocolView } from '../entities/evidence/ProxyProtocolView'
import { policiesAPI, type Execution } from '../features/policies/api'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppEmptyState, AppErrorAlert, AppFormModal, AppListHeader, AppLoadingState, AppServerPagination, AppTable, useServerPagination } from '../shared/ui'

export function PolicyExecutions(){
 const pagination=useServerPagination('executions_')
 const cache=useQueryClient();const session=useSession();const [approvalId,setApprovalId]=useState<string>()
 const executions=useQuery({queryKey:['policy-executions'],queryFn:policiesAPI.executions})
 const operation=useMutation({mutationFn:({id,op}:{id:string;op:'approve'|'revoke'})=>policiesAPI.operation(id,op),onSuccess:()=>{void cache.invalidateQueries({queryKey:['policy-executions']})},onError:(e:Error)=>message.error(e.message)})
 if(executions.isLoading)return <AppLoadingState rows={5}/>
 const items=executions.data?.items ?? []
 const pageItems=items.slice((pagination.page-1)*pagination.pageSize,pagination.page*pagination.pageSize)
 const stageSummary=(execution:Execution)=>{
  if(execution.stages.some(stage=>stage.status==='awaiting_approval'))return '等待确认'
  if(execution.stages.every(stage=>['succeeded','completed'].includes(stage.status)))return '已完成'
  return '进行中'
 }
 const columns: ColumnsType<Execution> = [
  {title:'账号 / 策略',key:'identity',width:260,render:(_,execution)=><div className="policy-execution-id"><strong className="policy-identifier">{execution.account_id}</strong><span className="shared-access-muted">{execution.policy_id}</span></div>},
  {title:'轮次',dataIndex:'episode',width:80,render:(value:number)=>`第 ${value} 轮`},
  {title:'状态',dataIndex:'state',width:120,render:(value:string)=><Tag color={statusColor(value)}>{statusText(value)}</Tag>},
  {title:'原因',dataIndex:'reasons',render:(values:string[])=>{const text=values.map(reason=>reasonNames[reason]??reason).join('、');return <span className="policy-reason-inline" title={text}>{text}</span>}},
  {title:'阶段',dataIndex:'stages',width:130,render:(_:Execution['stages'],execution:Execution)=>`${execution.stages.length} 个 · ${stageSummary(execution)}`},
  {title:'操作',key:'actions',width:180,render:(_,execution)=><div className="policy-toolbar"><Button size="small" disabled={!can(session.data,'policies:authorize')||!execution.stages.some(stage=>stage.status==='awaiting_approval')} onClick={()=>setApprovalId(execution.execution_id)}>确认执行</Button><Button size="small" danger disabled={!can(session.data,'actions:revoke')} onClick={()=>operation.mutate({id:execution.execution_id,op:'revoke'})}>撤销本轮</Button></div>},
 ]
 return <>
  <AppFormModal title="确认策略执行" open={Boolean(approvalId)} footer={null} destroyOnHidden onCancel={()=>setApprovalId(undefined)}>{approvalId&&<ApprovalPreview key={approvalId} id={approvalId} onComplete={()=>{setApprovalId(undefined);void cache.invalidateQueries({queryKey:['policy-executions']})}}/>}</AppFormModal>
  <section className="surface">
    <AppListHeader title="策略执行记录" count={`${items.length} 条`} />
    {executions.isError?<AppErrorAlert title="执行记录读取失败"/>:items.length?<AppTable
      rowKey="execution_id"
      columns={columns}
      dataSource={pageItems}
      scroll={{x:1000}}
      expandable={{expandedRowRender:(execution)=><div className="policy-execution-expanded">
        {!!execution.proxy_evidence?.length&&<div className="policy-execution-evidence">{execution.proxy_evidence.map(proof=><ProxyProtocolView key={proof.evidence_id} evidence={proof}/>)}</div>}
        {execution.stages.map(stage=><p key={stage.index}>阶段 {stage.index+1}：{statusText(stage.status)} · {stage.action_ids.length} 个子动作</p>)}
      </div>}}
    />:<AppEmptyState description="暂无执行记录"/>}
    <AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={items.length} onChange={pagination.update}/>
  </section>
 </>
}
