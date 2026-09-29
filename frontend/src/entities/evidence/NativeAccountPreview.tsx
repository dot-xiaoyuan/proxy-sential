import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Empty, Input, Spin, Tag } from 'antd'
import { request } from '../../shared/api/client'

type Preview = {
  coverage: 'configured_source_only' | 'account_observation_only'; observed_at: string; complete?: boolean; absence_verified?: boolean
  plan: { account: string; campus_id: string; access_domain: string; fingerprint: string; sessions: { target: { session_id: string; source_session_id?: string; login_generation?: string }; addresses: string[] }[] }
}

export function NativeAccountPreview({ connectorId }: { connectorId: string }) {
  const [input, setInput] = useState('')
  const [account, setAccount] = useState('')
  const query = useQuery({ queryKey: ['native-account-preview', connectorId, account], enabled: Boolean(account), retry: false, queryFn: () => request<Preview>(`/actions/connectors/${encodeURIComponent(connectorId)}/account-preview?account_id=${encodeURIComponent(account)}`) })
  const load = () => { if (input.trim() === account) void query.refetch(); else setAccount(input.trim()) }
  return <section className="native-observations" aria-label="账号会话预览">
    <Alert type="info" showIcon title="仅预览当前认证源，不会执行下线" description="其他认证源可能还有在线会话。这份清单不能证明已覆盖账号全部会话，也不代表账号违规。" />
    <div className="native-observation-controls">
      <Input className="native-preview-account" aria-label="预览账号" value={input} maxLength={256} onChange={event => setInput(event.target.value)} onPressEnter={() => { if (input.trim()) load() }} placeholder="输入认证账号" />
      <Button disabled={!input.trim() || query.isFetching} onClick={load}>查询会话</Button>
    </div>
    {query.data?.coverage === 'account_observation_only' && <Alert type="warning" showIcon title="仅为账号条件查询，无法证明清单完整或用户离线" description="完整权威身份验收前不能提交处置；空结果不表示用户已经离线。" />}
    {query.isFetching ? <Spin aria-label="正在查询会话" /> : query.isError ? <Alert type="error" showIcon title="无法生成会话预览" description="请确认原生连接器配置、账号在线状态和身份来源是否可用。查询失败不表示账号没有在线会话。" /> : account && query.data ? <>
      <div className="native-observation-id"><strong>账号：{query.data.plan.account}</strong><p>园区：{query.data.plan.campus_id} · 接入域：{query.data.plan.access_domain}</p><p>{query.data.coverage==='account_observation_only'?'查询完成时间':'源观测时间'}：{new Date(query.data.observed_at).toLocaleString()}</p></div>
      <Tag>本次查询返回 {query.data.plan.sessions.length} 个会话</Tag>
      {query.data.plan.sessions.map(session => <article className="native-observation" key={session.target.session_id}><strong>会话：{session.target.session_id}</strong><p>地址：{session.addresses.join('、')}</p>{session.target.source_session_id && <p>原始在线 ID：{session.target.source_session_id} · 登录代次：{session.target.login_generation}</p>}</article>)}
      {query.data.plan.fingerprint && <p className="native-observation-id">清单指纹：{query.data.plan.fingerprint}</p>}
      <p>新登录或身份绑定变化后需重新预览；双栈地址不重复计为两个会话。</p>
    </> : <Empty description="输入账号后查询当前来源的会话" />}
  </section>
}
