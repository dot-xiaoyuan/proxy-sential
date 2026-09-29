import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Checkbox, Modal, Space, Tag } from 'antd'
import { request } from '../shared/api/client'
import type { components } from '../shared/api/generated'
import type { OperationTask } from '../shared/api/operationTasks'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'

export type SharedDisconnectPreview = components['schemas']['SharedDisconnectPreview']
const reasons: Record<string, string> = { designated_test_account_required: '仅允许本轮指定测试账号 yuantong', current_shared_conclusion_required: '请先对当前依据版本保存“共享依据成立”结论', authoritative_inventory_unavailable: '完整权威身份来源不可用', authoritative_inventory_query_failed: '权威身份查询失败，不能据此认定离线', identity_source_not_configured: '尚未配置身份来源与范围', current_account_sessions_unavailable: '当前账号完整会话无法确认', shared_evidence_expired_or_coverage_insufficient: '证据过期或采集覆盖不足', shared_evidence_not_actionable: '共享依据或配置版本未通过准入', session_generation_changed: '认证会话代次已变化', manual_controller_gate_unavailable: '控制器须启用并保持影子模式，紧急停止必须关闭', manual_exception_applied: '目标受到例外保护', multiple_authorities_require_review: '存在多个身份来源，需要分别复核', subject_cooldown_active: '本账号范围处于五分钟冷却期', controller_circuit_open: '控制器熔断中' }
const taskStates: Record<string, string> = { queued: '等待处理', running: '正在核对身份与依据', completed: '检查完成', failed: '处理失败', cancelled: '已取消' }

export function SharedDisconnectPanel({ id }: { id: string }) {
  const session = useSession(); const cache = useQueryClient()
  const [preview, setPreview] = useState<SharedDisconnectPreview>()
  const [job, setJob] = useState<OperationTask>(); const [phase, setPhase] = useState<'preview' | 'confirm'>('preview')
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [open, setOpen] = useState(false); const [authorize, setAuthorize] = useState(false)
  const handled = useRef('')
  const confirmationKey = useRef('')
  const root = `/shared-access/reviews/${encodeURIComponent(id)}`
  const task = useQuery({ queryKey: ['shared-disconnect-task', job?.task_id], enabled: !!job, queryFn: () => request<OperationTask>(`/tasks/${encodeURIComponent(job!.task_id)}`), refetchInterval: q => ['queued', 'running'].includes(q.state.data?.status ?? job?.status ?? '') ? 1000 : false })
  const progress = task.data ?? job; const pending = busy || !!progress && ['queued', 'running'].includes(progress.status)
  const allowed = can(session.data, 'integrations:write') && can(session.data, 'actions:execute') && can(session.data, 'cases:write')
  useEffect(() => {
    if (!task.data || ['queued', 'running'].includes(task.data.status) || handled.current === task.data.task_id) return
    handled.current = task.data.task_id
    if (task.data.status === 'completed') {
      if (phase === 'preview') setPreview(task.data.result as SharedDisconnectPreview)
      else { setOpen(false); setPreview(undefined); setAuthorize(false); void cache.invalidateQueries({ queryKey: ['shared-review-executions', id] }) }
    } else { setError('核对或确认失败，请重新获取预览。此结果不代表用户离线。'); setPreview(undefined); setAuthorize(false) }
  }, [task.data, phase, cache, id])
  const start = async (confirm: boolean) => {
    setBusy(true); setError(''); setPhase(confirm ? 'confirm' : 'preview')
    if (!confirm) { setPreview(undefined); setAuthorize(false); confirmationKey.current = '' }
    if (confirm && !confirmationKey.current) confirmationKey.current = crypto.randomUUID()
    try { setJob(await request<OperationTask>(`${root}/${confirm ? 'disconnect' : 'disconnect-preview'}`, { method: 'POST', headers: { 'Idempotency-Key': confirm ? confirmationKey.current : crypto.randomUUID() }, deferTaskPolling: true, body: JSON.stringify(confirm ? { fingerprint: preview!.fingerprint, evidence_version: preview!.evidence_version, identity_version: preview!.identity_version, config_version: preview!.config_version, authorize_designated_test: authorize } : {}) })) }
    catch (e) { setError(e instanceof Error ? e.message : '请求失败') }
    finally { setBusy(false) }
  }
  const targets = preview?.plan.sessions.map(item => <article className="shared-access-item" key={item.target.session_id}><p className="shared-access-id">会话：{item.target.session_id}</p><p className="shared-access-id">原始在线 ID：{item.target.raw_online_id}</p><p className="shared-access-id">地址：{item.addresses.join('、')}</p></article>)
  return <Card title="指定账号人工下线">
    <Alert type="info" showIcon title="仅本轮 yuantong 测试；下线不会停用账号，原会话不能恢复" description="影响范围仅为本次预览明确列出的接入范围与会话。接口受理不表示会话已经消失。" />
    {error && <Alert type="error" showIcon title={error} />}
    {progress && <p><Tag>{taskStates[progress.status]}</Tag>{phase === 'confirm' && progress.status === 'completed' ? '动作已持久化，执行结果见下方逐会话记录' : '外部检查完成时间单独计算'}</p>}
    <Space wrap className="shared-access-actions"><Button loading={pending} disabled={!can(session.data, 'actions:execute')} onClick={() => void start(false)}>获取下线预览</Button><Button type="primary" disabled={!allowed || !preview?.ready || pending} onClick={() => { setOpen(true); setAuthorize(false) }}>确认指定会话下线</Button></Space>
    {!allowed && <p>需要管理员授权本轮人工测试。</p>}
    {preview && <><p>{preview.plan.account} · {preview.plan.campus_id} / {preview.plan.access_domain}</p><p>依据版本 {preview.evidence_version} · 身份配置版本 {preview.identity_version}</p>{preview.blockers.map(reason => <Alert key={reason} type="warning" showIcon title={reasons[reason] ?? '准入检查未通过'} />)}{targets?.length ? targets : <p>尚无可用于处置的完整会话清单；不能解释为账号离线。</p>}</>}
    <Modal title="确认本轮人工下线" open={open} onCancel={() => { if (!pending) setOpen(false) }} onOk={() => void start(true)} confirmLoading={pending} okText="提交人工下线" cancelText="取消" okButtonProps={{ disabled: !authorize || !preview?.ready || !allowed || pending }}>
      {error && <Alert type="error" title={error} />}{targets}<p>依据版本 {preview?.evidence_version}；授权有效15分钟，仅用于以上批准会话。出现新会话或依据变化后必须重新确认。</p><Checkbox checked={authorize} disabled={pending} onChange={e => setAuthorize(e.target.checked)}>我确认仅对本轮 yuantong 的上述会话人工下线</Checkbox>
    </Modal>
  </Card>
}
