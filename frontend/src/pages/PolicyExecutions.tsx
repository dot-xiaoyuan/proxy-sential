import { reasonNames } from '../features/policies/reasonMeta'
import { statusText } from '../shared/ui/status'
import { useState } from 'react'
import { useMutation,useQuery,useQueryClient } from '@tanstack/react-query'
import { Button,Card,Empty,Modal,message } from 'antd'
import { ApprovalPreview } from '../features/policies/ApprovalPreview'
import { ProxyProtocolView } from '../entities/evidence/ProxyProtocolView'
import { policiesAPI } from '../features/policies/api'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppErrorAlert,AppLoadingState,AppServerPagination,useServerPagination } from '../shared/ui'
export function PolicyExecutions(){
const pagination=useServerPagination('executions_');
const cache=useQueryClient();const session=useSession();const [approvalId,setApprovalId]=useState<string>();
const executions=useQuery({queryKey:['policy-executions'],queryFn:policiesAPI.executions});
const operation=useMutation({mutationFn:({id,op}:{id:string;op:'approve'|'revoke'})=>policiesAPI.operation(id,op),onSuccess:()=>{void cache.invalidateQueries({queryKey:['policy-executions']})},onError:(e:Error)=>message.error(e.message)});
if(executions.isLoading)return <AppLoadingState rows={5}/>
return <> <Modal title="确认策略执行" open={Boolean(approvalId)} footer={null} destroyOnHidden onCancel={()=>setApprovalId(undefined)}>{approvalId&&<ApprovalPreview key={approvalId} id={approvalId} onComplete={()=>{setApprovalId(undefined);void cache.invalidateQueries({queryKey:['policy-executions']})}}/>}</Modal>
 <Card title="策略执行记录" extra={<Button onClick={()=>void executions.refetch()} loading={executions.isFetching}>刷新执行</Button>}>{executions.isError?<AppErrorAlert title="执行记录加载失败"/>:executions.data?.items.length?executions.data.items.slice((pagination.page-1)*pagination.pageSize,pagination.page*pagination.pageSize).map(e=><div className="policy-execution" key={e.execution_id}><strong className="policy-identifier">{e.account_id} · {e.policy_id}</strong><p>第 {e.episode} 轮 · {statusText(e.state)}</p><p>{e.reasons.map(r=>reasonNames[r]??r).join('、')}</p>{e.proxy_evidence?.map(proof=><ProxyProtocolView key={proof.evidence_id} evidence={proof}/>)}{e.stages.map(st=><p key={st.index}>阶段 {st.index+1}：{statusText(st.status)} · {st.action_ids.length} 个子动作</p>)}<div className="policy-toolbar"><Button disabled={!can(session.data,'policies:authorize')||!e.stages.some(st=>st.status==='awaiting_approval')} onClick={()=>setApprovalId(e.execution_id)}>确认执行</Button><Button disabled={!can(session.data,'actions:revoke')} onClick={()=>operation.mutate({id:e.execution_id,op:'revoke'})}>撤销本轮</Button></div></div>):<Empty description="暂无执行记录"/>}</Card>
<AppServerPagination page={pagination.page} pageSize={pagination.pageSize} total={executions.data?.items.length??0} onChange={pagination.update}/>
</>
}
