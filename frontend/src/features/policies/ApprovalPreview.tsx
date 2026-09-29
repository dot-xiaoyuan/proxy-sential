import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Spin } from 'antd'
import { policiesAPI } from './api'

export function ApprovalPreview({ id, onComplete }: { id: string; onComplete: () => void }) {
 const preview=useQuery({queryKey:['policy-approval-preview',id],queryFn:()=>policiesAPI.approvalPreview(id),retry:false})
 const approve=useMutation({mutationFn:()=>policiesAPI.operation(id,'approve',preview.data?.fingerprint),onSuccess:onComplete})
 const actions:Record<string,string>={disconnect:'下线',rate_limit:'限速',notify:'通知',disable_account:'停用账号'}
 return <section className="native-observations" aria-label="策略执行确认">
  <Alert type="warning" showIcon title="确认前核对账号、会话和动作参数" description="提交时将重新校验策略、证据和会话。下线是一次性动作，不禁止再次登录，也无法恢复原会话。" />
  {preview.isFetching?<Spin aria-label="加载确认内容"/>:preview.isError?<Alert type="error" title="确认内容加载失败" description="请刷新重试；身份信息不完整时无法确认。"/>:preview.data&&<>
   <strong className="native-observation-id">账号：{preview.data.account_id}</strong>
   <p>阶段 {preview.data.stage_index+1} · {actions[preview.data.stage.action]??preview.data.stage.action} · 连接器 {preview.data.stage.connector_id}</p>
   {preview.data.stage.action==='disconnect'?<p>执行方式：一次性下线当前确认的会话</p>:<p>持续时间：{preview.data.stage.duration_seconds} 秒{preview.data.stage.action==='rate_limit'&&` · 限速：${preview.data.stage.rate_kbps} Kbps`}</p>}
   {preview.data.sessions.map((s,i)=><article key={`${s.session_id}-${s.ip}-${i}`} className="native-observation"><strong>会话：{s.session_id}</strong><p>园区：{s.campus_id} · 接入域：{s.access_domain}</p><p>地址：{s.ip}</p></article>)}
   <p className="native-observation-id">证据：{preview.data.evidence_ids.join('、')||'以当前配额评估为依据'}</p>
  </>}
  {approve.isError&&<Alert type="error" title="确认未完成" description="内容可能已变化或执行准入未满足，请刷新并重新核对。"/>}
  <div className="native-observation-controls"><Button disabled={approve.isPending} onClick={()=>{approve.reset();void preview.refetch()}}>刷新确认内容</Button><Button type="primary" loading={approve.isPending} disabled={!preview.data||preview.isFetching||preview.isError||approve.isError} onClick={()=>approve.mutate()}>确认上述内容并提交</Button></div>
 </section>
}
