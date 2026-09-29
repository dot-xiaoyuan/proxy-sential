import { SharedDisconnectPanel } from './SharedDisconnectPanel'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Empty, Form, Input, Modal, Select, Space, Tag } from 'antd'
import { request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { AppErrorAlert, AppLoadingState, AppPageHeader } from '../shared/ui'

type SharedResult = { state: string; reasons: string[]; signal_groups: string[]; quantity_known: boolean; device_lower_bound: number; confidence: number; from: string; to: string }
type SharedBehavior = {
  observation_id: string; ip: string; endpoint_id?: string; status: 'candidate' | 'likely' | 'confirmed'; confidence: number;
  signal_groups: string[]; reasons: string[]; conflicts: string[]; coverage_state: 'verified' | 'partial' | 'unknown';
  first_seen: string; last_seen: string; window_start: string; window_end: string; rule_version: string; event_ids: string[];
  router?: { assessment_id?: string; brand?: string; model?: string; role?: string; status?: string; confidence?: number };
  score_components: { signal: string; score: number; explanation: string }[];
  feature_samples: Record<string, Record<string, { count: number; buckets: number[] }>>;
}
type SharedBehaviorDetail = SharedBehavior & { history: { status: SharedBehavior['status']; confidence: number; signal_groups: string[]; coverage_state: SharedBehavior['coverage_state']; rule_version: string; observed_at: string; created_at: string }[] }
type Review = { review_id: string; account_id: string; campus_id: string; access_domain: string; session_generation: string; episode: number; latest_version: number; latest_result: SharedResult; coverage_state: string; last_conclusion?: { evidence_version: number; operator_id: string; conclusion: string; reason: string; created_at: string } }
type Page<T> = { items: T[]; next_cursor: string }
type OffsetPage<T> = { items: T[]; page: { total: number; limit: number; next_cursor?: string } }
type Status = { checked_at: string; identity: { connector_id: string; scope: { campus_id: string; access_domain: string }; state: string; blocker: string; fresh: boolean; observed_at: string; record_count: number }[]; collection: { state: string; blocker: string }; materialization: { state: string; blocker: string }; policy: { state: string; blocker: string }; controller: { state: string; blocker: string } }
const states: Record<string, string> = { healthy: '最近同步成功', pending: '等待检查', unavailable: '来源不可用', stale: '身份过期', disabled: '未启用', unknown: '尚未验证', blocked: '准入阻断', basis_present: '有共享候选依据', insufficient: '证据不足', not_matched: '未发现共享依据' }
const blockers: Record<string, string> = { inventory_completeness_unproven: '清单完整性尚未证明', capture_coverage_not_verified: '采集覆盖尚未验证', materialization_freshness_not_verified: '物化新鲜度尚未验证', shared_review_gate_not_verified: '共享复核准入尚未验收', manual_action_not_verified: '人工处置尚未验收', identity_source_disabled: '身份来源未启用', identity_source_stale: '身份来源过期' }
const behaviorStates: Record<string, string> = { candidate: '候选观察', likely: '较可信', confirmed: '高置信度' }
const behaviorSignals: Record<string, string> = { ua_os: '多操作系统', ttl_path: '多 TTL 路径', tcp_stack: '多 TCP 栈', tls_stack: '多 TLS 指纹', dhcp_stack: '多 DHCP 栈', router_identity: '路由器画像' }
const time = (value: string) => value && !value.startsWith('0001-') ? new Date(value).toLocaleString() : ''
function CursorButtons({ next, previous, onNext, onPrevious }: { next?: string; previous: boolean; onNext: () => void; onPrevious: () => void }) { return <Space wrap className="shared-access-actions"><Button disabled={!previous} onClick={onPrevious}>上一页</Button><Button disabled={!next} onClick={onNext}>下一页</Button></Space> }
function useCursor() { const [stack, setStack] = useState(['']); return { cursor: stack[stack.length - 1], previous: stack.length > 1, next: (value: string) => { if (value) setStack([...stack, value]) }, back: () => setStack(stack.slice(0, -1)) } }

export function SharedAccessPage() {
  const cursor = useCursor()
  const behaviorCursor = useCursor()
  const [behaviorStatus, setBehaviorStatus] = useState('')
  const [behaviorKeyword, setBehaviorKeyword] = useState('')
  const status = useQuery({ queryKey: ['shared-access-status'], queryFn: () => request<Status>('/shared-access/status'), refetchInterval: 5000 })
  const reviews = useQuery({ queryKey: ['shared-access-reviews', cursor.cursor], queryFn: () => request<Page<Review>>(`/shared-access/reviews?limit=20&cursor=${encodeURIComponent(cursor.cursor)}`) })
  const behavior = useQuery({ queryKey: ['shared-access-observations', behaviorCursor.cursor, behaviorStatus, behaviorKeyword], queryFn: () => request<OffsetPage<SharedBehavior>>(`/shared-access/observations?limit=20&cursor=${encodeURIComponent(behaviorCursor.cursor)}&status=${encodeURIComponent(behaviorStatus)}&keyword=${encodeURIComponent(behaviorKeyword)}`), refetchInterval: 30000 })
  return <section className="shared-access-page">
    <AppPageHeader title="共享发现与复核" subtitle="从共享依据到认证账号、人工复核与处置核验" extra={<Space wrap><Link to="/settings/actions">身份接入配置</Link><Link to="/policies">共享策略</Link><Link to="/cases">处置案件</Link><Link to="/audit">审计记录</Link></Space>} />
    <details className="surface filter-disclosure shared-health-disclosure"><summary>链路状态与处置准入说明</summary><div className="filter-disclosure-content"><Alert type="info" showIcon title="默认观测；未验收能力保持阻断" description="认证管理接口连通不代表权威身份完整，也不代表共享检测或处罚已经通过验收。真实操作仅限当轮明确指定的测试账号。" />
    {status.isError ? <AppErrorAlert title="链路状态读取失败" /> : status.isLoading ? <AppLoadingState rows={2} /> : status.data && <Card className="shared-health-card" title="链路状态" extra={<span className="shared-access-muted">检查时间：{time(status.data.checked_at)}</span>}>
      <div className="shared-access-grid">{(['collection', 'materialization', 'policy', 'controller'] as const).map((key, index) => <article className="shared-access-item" key={key}><strong>{['采集覆盖', '共享物化', '策略准入', '控制器'][index]}</strong><Tag>{states[status.data![key].state] ?? '尚未验证'}</Tag><p>{blockers[status.data![key].blocker] ?? '能力未验收'}</p></article>)}</div>
      <h3>认证身份</h3>{status.data.identity.length === 0 ? <Empty description="尚未配置身份来源，请在处置网关设置身份来源与范围" /> : status.data.identity.map(source => <article className="shared-access-item" key={source.connector_id}><strong>{source.scope.campus_id} / {source.scope.access_domain}</strong><Tag color={source.fresh ? 'green' : 'orange'}>{states[source.state] ?? '尚未验证'}</Tag><p>最近源观测：{time(source.observed_at)} · {source.record_count} 条地址关联</p>{source.blocker && <p>{blockers[source.blocker] ?? '身份同步未通过，处置保持阻断'}</p>}</article>)}
    </Card>}</div></details>
    <Card title="共享网关观察" extra={<span className="shared-access-muted">行为识别与账号处置严格分离</span>}>
      <div className="shared-behavior-filters"><Input.Search allowClear placeholder="IP、终端、品牌或型号" onSearch={value => setBehaviorKeyword(value.trim())} /><Select allowClear placeholder="置信状态" value={behaviorStatus || undefined} onChange={value => setBehaviorStatus(value || '')} options={Object.entries(behaviorStates).map(([value, label]) => ({ value, label }))} /></div>
      {behavior.isError ? <AppErrorAlert title="共享网关观察读取失败" /> : behavior.isLoading ? <AppLoadingState rows={4} /> : behavior.data?.items.length ? <div className="shared-behavior-list">{behavior.data.items.map(item => <article className={`shared-behavior-card shared-behavior-card-${item.status}`} key={item.observation_id}>
        <div className="shared-behavior-heading"><div><strong className="shared-behavior-ip">{item.ip}</strong>{item.endpoint_id && <span className="shared-access-muted">{item.endpoint_id}</span>}</div><Space wrap><Tag color={item.status === 'confirmed' ? 'green' : item.status === 'likely' ? 'gold' : 'default'}>{behaviorStates[item.status]}</Tag><strong>{item.confidence} 分</strong></Space></div>
        <Space wrap>{item.signal_groups.map(signal => <Tag key={signal}>{behaviorSignals[signal] || signal}</Tag>)}<Tag color={item.coverage_state === 'verified' ? 'green' : 'orange'}>{item.coverage_state === 'verified' ? '采集覆盖已验证' : '采集覆盖待完善'}</Tag></Space>
        {item.router?.assessment_id && <p>关联路由画像：<Link to={`/discovery/routers/${encodeURIComponent(item.router.assessment_id)}`}>{[item.router.brand, item.router.model, item.router.status && `${item.router.confidence} 分`].filter(Boolean).join(' · ')}</Link></p>}
        <p className="shared-access-muted">观察窗口：{time(item.window_start)} — {time(item.window_end)} · 最近证据：{time(item.last_seen)}</p>
        <details><summary>查看计分与原始证据引用</summary><div className="shared-behavior-evidence">{item.score_components.map(component => <p key={component.signal}><strong>{behaviorSignals[component.signal] || component.signal} +{component.score}</strong><span>{component.explanation}</span></p>)}{item.reasons.map(reason => <p key={reason}>{reason}</p>)}{item.conflicts.map(conflict => <p className="shared-behavior-conflict" key={conflict}>{conflict}</p>)}<p className="shared-access-id">规则：{item.rule_version}</p><p className="shared-access-id">事件：{item.event_ids.join('、')}</p><Link to={`/shared-access/observations/${encodeURIComponent(item.observation_id)}`}>查看完整识别记录</Link></div></details>
      </article>)}</div> : <Empty description="当前窗口没有满足双信号门槛的共享网关观察" />}
      <div className="shared-behavior-pagination"><span className="shared-access-muted">共 {behavior.data?.page.total || 0} 条记录</span><CursorButtons next={behavior.data?.page.next_cursor} previous={behaviorCursor.previous} onNext={() => behaviorCursor.next(behavior.data?.page.next_cursor ?? '')} onPrevious={behaviorCursor.back} /></div>
    </Card>
    <Card title="共享复核队列">
      {reviews.isError ? <AppErrorAlert title="复核队列读取失败" /> : reviews.isLoading ? <AppLoadingState rows={3} /> : reviews.data?.items.length ? <div className="shared-access-grid">{reviews.data.items.map(review => <article className="shared-access-item" key={review.review_id}><Link to={`/shared-access/reviews/${review.review_id}`}><strong>{review.account_id}</strong></Link><Tag>{states[review.latest_result.state] ?? '证据不足'}</Tag><p>{review.campus_id} / {review.access_domain}</p><p>独立轮次 {review.episode} · 依据版本 {review.latest_version}</p><p className="shared-access-muted">覆盖状态：{({unknown:'尚未验证，禁止处置',verified:'完整覆盖已验证',insufficient:'证据不足，禁止处置'} as Record<string,string>)[review.coverage_state] ?? '需结合详情核对'}</p></article>)}</div> : <Empty description="暂无复核记录；空队列不表示已证明不存在共享行为" />}
      <CursorButtons next={reviews.data?.next_cursor} previous={cursor.previous} onNext={() => cursor.next(reviews.data?.next_cursor ?? '')} onPrevious={cursor.back} />
    </Card>
  </section>
}

export function SharedBehaviorDetailsPage() {
  const { observationId } = useParams()
  const detail = useQuery({ queryKey: ['shared-access-observation', observationId], queryFn: () => request<SharedBehaviorDetail>(`/shared-access/observations/${encodeURIComponent(observationId ?? '')}`) })
  if (detail.isLoading) return <AppLoadingState rows={5} />
  if (detail.isError || !detail.data) return <AppErrorAlert title="共享网关识别记录读取失败" />
  const item = detail.data
  return <section className="shared-access-page">
    <AppPageHeader title={`共享网关识别记录：${item.ip}`} subtitle={`${behaviorStates[item.status]} · ${item.confidence} 分`} extra={<Link to="/shared-access">返回共享发现</Link>} />
    <Alert type="info" showIcon title="识别记录不等于处置授权" description="只有权威认证身份、完整采集覆盖、当前会话和人工复核同时通过，记录才可能进入后续策略流程。" />
    <Card title="判定摘要">
      <Space wrap><Tag color={item.status === 'confirmed' ? 'green' : item.status === 'likely' ? 'gold' : 'default'}>{behaviorStates[item.status]}</Tag><strong>{item.confidence} 分</strong>{item.signal_groups.map(signal => <Tag key={signal}>{behaviorSignals[signal] || signal}</Tag>)}<Tag color={item.coverage_state === 'verified' ? 'green' : 'orange'}>{item.coverage_state === 'verified' ? '采集覆盖已验证' : '采集覆盖待完善'}</Tag></Space>
      <p>观察窗口：{time(item.window_start)} — {time(item.window_end)}</p>
      <p>最近证据：{time(item.last_seen)} · 规则：{item.rule_version}</p>
      {item.endpoint_id && <p className="shared-access-id">终端：{item.endpoint_id}</p>}
      {item.router?.assessment_id && <p>关联路由画像：<Link to={`/discovery/routers/${encodeURIComponent(item.router.assessment_id)}`}>{[item.router.brand, item.router.model, item.router.status && `${item.router.confidence} 分`].filter(Boolean).join(' · ')}</Link></p>}
    </Card>
    <Card title="计分与冲突">
      <div className="shared-behavior-evidence">{item.score_components.map(component => <p key={component.signal}><strong>{behaviorSignals[component.signal] || component.signal} +{component.score}</strong><span>{component.explanation}</span></p>)}{item.reasons.map(reason => <p key={reason}>{reason}</p>)}{item.conflicts.map(conflict => <p className="shared-behavior-conflict" key={conflict}>{conflict}</p>)}</div>
    </Card>
    <Card title="特征样本与证据引用">
      <div className="shared-behavior-evidence">{Object.entries(item.feature_samples).map(([family, values]) => <section key={family}><strong>{behaviorSignals[family] || family}</strong>{Object.entries(values).map(([value, sample]) => <p className="shared-access-id" key={value}>{value} · {sample.count} 个去重观测 · {sample.buckets.length} 个共现桶</p>)}</section>)}<p className="shared-access-id">事件：{item.event_ids.join('、')}</p></div>
    </Card>
    <Card title="判定历史">
      <div className="shared-behavior-list">{item.history.map((entry, index) => <article className={`shared-behavior-card shared-behavior-card-${entry.status}`} key={`${entry.rule_version}-${entry.observed_at}-${index}`}><Space wrap><Tag color={entry.status === 'confirmed' ? 'green' : entry.status === 'likely' ? 'gold' : 'default'}>{behaviorStates[entry.status]}</Tag><strong>{entry.confidence} 分</strong>{entry.signal_groups.map(signal => <Tag key={signal}>{behaviorSignals[signal] || signal}</Tag>)}</Space><p>{time(entry.observed_at)} · {entry.rule_version}</p></article>)}</div>
    </Card>
  </section>
}

export function SharedReviewDetailsPage() {
  const session = useSession()
  const { id } = useParams(); const cache = useQueryClient()
  const evidenceCursor = useCursor(); const executionCursor = useCursor()
  const [confirmVersion, setConfirmVersion] = useState<number>()
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const [form] = Form.useForm<{ conclusion: string; reason: string }>()
  const root = `/shared-access/reviews/${encodeURIComponent(id ?? '')}`
  const identityStatus = useQuery({queryKey: ['shared-access-status'], queryFn: () => request<Status>('/shared-access/status'), refetchInterval: 5000})
  const detail = useQuery({ queryKey: ['shared-review', id], queryFn: () => request<Review>(root) })
  const evidence = useQuery({ queryKey: ['shared-review-evidence', id, evidenceCursor.cursor], queryFn: () => request<Page<{ version: number; evidence: { result: SharedResult; window: { feature_samples?: Record<string, Record<string, { count: number; buckets: number[] }>>; records?: { event_id: string; source: string }[] } }; created_at: string }>>(`${root}/evidence?limit=20&cursor=${encodeURIComponent(evidenceCursor.cursor)}`) })
  const executions = useQuery({ queryKey: ['shared-review-executions', id, executionCursor.cursor], queryFn: () => request<Page<{ action_id: string; status: string; mode: string }>>(`${root}/executions?limit=20&cursor=${encodeURIComponent(executionCursor.cursor)}`), refetchInterval: 5000 })
  if (detail.isLoading) return <AppLoadingState rows={4} />
  if (detail.isError || !detail.data) return <AppErrorAlert title="共享复核详情读取失败" />
  const review = detail.data
  const save = async () => {
    const values = await form.validateFields(); setBusy(true); setError('')
    try { await request(`${root}/conclusion`, { method: 'POST', body: JSON.stringify({ ...values, evidence_version: confirmVersion }) }); setConfirmVersion(undefined); form.resetFields(); await cache.invalidateQueries({ queryKey: ['shared-review', id] }) }
    catch (reason) { setError(reason instanceof Error ? reason.message : '复核保存失败') }
    finally { setBusy(false) }
  }
  return <section className="shared-access-page"><AppPageHeader title={`共享复核：${review.account_id}`} subtitle={`${review.campus_id} / ${review.access_domain}`} extra={<Space wrap><Link to="/shared-access">返回复核队列</Link>{can(session.data, 'cases:write') && <Button onClick={() => { setConfirmVersion(review.latest_version); setError('') }}>记录人工结论</Button>}</Space>} />
    <Alert type="warning" showIcon title="人工处置须通过身份、证据与指定账号授权检查" description="证据不足不能解释为恢复正常；人工结论不会自动执行处罚。" />
    {error && <Alert type="error" showIcon title={error} />}
    <Card title="身份来源">{identityStatus.isError ? <AppErrorAlert title="当前身份状态不可用，不能处置" /> : identityStatus.data?.identity.filter(source=>source.scope.campus_id===review.campus_id && source.scope.access_domain===review.access_domain).map(source=><article className="shared-access-item" key={source.connector_id}><Tag color={source.fresh?'green':'orange'}>{states[source.state]??'尚未验证'}</Tag><p>当前源观测：{time(source.observed_at)}</p><p>{blockers[source.blocker]??'需核对当前会话；历史代次不能授权新登录'}</p></article>)}</Card>
    <Card title="当前依据"><Space wrap><Tag>{states[review.latest_result.state] ?? '证据不足'}</Tag><Tag>版本 {review.latest_version}</Tag><Tag>独立轮次 {review.episode}</Tag></Space><p>时间范围：{time(review.latest_result.from)} — {time(review.latest_result.to)}</p><p>已确认设备下界：{review.latest_result.quantity_known ? review.latest_result.device_lower_bound : '未知，不能从画像推测设备数量'}</p><p>独立信号：{review.latest_result.signal_groups?.join('、') || '不足'}</p><p className="shared-access-id">会话代次：{review.session_generation}</p>{review.last_conclusion && <article className="shared-access-item"><strong>最近人工结论：{({shared:'共享依据成立',normal:'正常',insufficient:'证据不足'} as Record<string,string>)[review.last_conclusion.conclusion]??'未知'}</strong><p>{review.last_conclusion.reason}</p><p>操作者：{review.last_conclusion.operator_id} · 依据版本 {review.last_conclusion.evidence_version}</p>{review.last_conclusion.evidence_version!==review.latest_version && <Tag color="orange">依据已更新，需重新复核</Tag>}</article>}</Card>
    <Card title="证据版本与时间共现">{evidence.isError ? <AppErrorAlert title="证据历史读取失败" /> : evidence.isLoading ? <AppLoadingState rows={2} /> : evidence.data?.items.map(item => <article className="shared-access-item" key={item.version}><strong>依据版本 {item.version}</strong><p>{time(item.created_at)}</p>{Object.entries(item.evidence.window.feature_samples ?? {}).map(([family, features]) => <div key={family}><strong>{family}</strong>{Object.entries(features).map(([value, sample]) => <p className="shared-access-id" key={value}>{value}：{sample.count} 个去重观测，{sample.buckets.length} 个五秒桶；桶：{sample.buckets.join('、')}</p>)}</div>)}<details><summary>原始证据引用（有界摘要）</summary>{item.evidence.window.records?.map((record, index) => <p className="shared-access-id" key={index}>{record.source} / {record.event_id}</p>)}</details></article>)}<CursorButtons next={evidence.data?.next_cursor} previous={evidenceCursor.previous} onNext={() => evidenceCursor.next(evidence.data?.next_cursor ?? '')} onPrevious={evidenceCursor.back} /></Card>
    <SharedDisconnectPanel id={review.review_id} />
    <Card title="关联执行记录">{executions.isError ? <AppErrorAlert title="执行记录读取失败" /> : executions.isLoading ? <AppLoadingState rows={2} /> : executions.data?.items.length ? executions.data.items.map(item => <article className="shared-access-item" key={item.action_id}><p className="shared-access-id">{item.action_id}</p><Tag>{item.mode}</Tag><p>{item.status}</p>{can(session.data, 'actions:revoke') && ['pending','running','blocked'].includes(item.status) && <Button onClick={() => void request(`/actions/${encodeURIComponent(item.action_id)}/revoke`, { method: 'POST' }).then(() => cache.invalidateQueries({ queryKey: ['shared-review-executions', id] })).catch(reason => setError(reason instanceof Error ? reason.message : '撤销失败'))}>停止后续发送</Button>}</article>) : <Empty description="尚未关联执行；复核结论不会自动下线" />}<CursorButtons next={executions.data?.next_cursor} previous={executionCursor.previous} onNext={() => executionCursor.next(executions.data?.next_cursor ?? '')} onPrevious={executionCursor.back} /></Card>
    <Modal title={`人工复核 · 依据版本 ${confirmVersion ?? ''}`} open={confirmVersion !== undefined} onCancel={() => setConfirmVersion(undefined)} onOk={() => void save()} confirmLoading={busy} okText="保存结论" cancelText="取消">
      {error && <Alert type="error" showIcon title={error} />}<Form form={form} layout="vertical"><Form.Item name="conclusion" label="复核结论" rules={[{ required: true }]}><Select options={[{ value: 'shared', label: '共享依据成立' }, { value: 'normal', label: '正常' }, { value: 'insufficient', label: '证据不足' }]} /></Form.Item><Form.Item name="reason" label="复核理由" rules={[{ required: true }]}><Input.TextArea rows={3} maxLength={4096} /></Form.Item></Form>
    </Modal>
  </section>
}
