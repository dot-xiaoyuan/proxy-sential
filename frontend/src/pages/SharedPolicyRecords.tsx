import { Notice as Alert } from '../shared/ui/Notice'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Empty, Input, Select, Tag } from 'antd'
import { request } from '../shared/api/client'
import { AppErrorAlert, AppLoadingState } from '../shared/ui'

export type SharedPolicyDecision = {
 decision_id: string; observation_id: string; policy_revision: number; evidence_version: string;
 account_id: string; ip: string; campus_id: string; access_domain: string; evaluated_at: string;
 evidence_expires_at: string; mode: 'observe'; planned_action: string; delivery_status: 'not_sent';
 result: 'matched' | 'insufficient' | 'expired'; reasons: string[];
 evidence: { rule_version: string; from: string; to: string; device_lower_bound?: number; records?: { event_id: string; source: string; collector_instance_id?: string }[] };
}
const resultLabels = { matched: '策略命中', insufficient: '评估未通过', expired: '证据已过期' }
const reasons: Record<string, string> = {
 feature_value_limit: '特征数量达到采集上限',
 kernel_drops: '内核采集丢包',
 parse_truncated: '报文解析截断',
 output_truncated: '采集输出裁剪',
 gateway_ownership_unavailable: '网关 MAC 没有覆盖完整事件窗口的有效地址租约',
 gateway_ownership_conflicting: '同一 IP 对应多个网关，地址归属存在冲突',
 legacy_association_without_coverage: '接入关联摘要缺少有效的逐段采集覆盖证明',
 association_same_time_conflict: '相同观测时间的接入快照内容冲突',
 association_payload_invalid: '接入关联报文结构不完整',
 confirmed_shared_observation: '共享证据已确认，事件窗口内账号归责可靠',
 shared_identity_mapping_unavailable: '观察窗口没有唯一且全程有效的身份范围映射',
 shared_identity_unknown_or_conflicting: '事件窗口内账号缺失或存在冲突',
 shared_identity_changed_within_window: '事件窗口内 IP 已更换使用账号',
 shared_session_generation_missing: '认证会话缺少可核对的代次标识',
 shared_session_generation_changed_within_window: '观察窗口内认证会话发生换代',
 shared_observation_conflict: '采集覆盖或证据存在冲突',
 router_forwarding_not_verified: '接入关系可见，但缺少路由 / NAT 转发证据，不记共享命中',
 confirmed_shared_observation_required: '当前证据未达到确认共享标准',
 incomplete_shared_observation_window: '观察窗口覆盖不完整',
 stale_or_invalid_shared_window: '共享证据已过期或时间窗口无效',
 shared_evidence_expired: '证据已过期，保留历史记录，不代表恢复正常',
 identity_source_unregistered: '身份源未注册', identity_source_interrupted: '身份源中断',
 identity_window_uncovered: '事件窗口前缺少完整身份快照，等待快照之后的新观察窗口',
 identity_snapshot_index_pending: '身份快照索引尚未就绪，等待新快照', identity_processing_pending:'身份变化仍在处理，稍后复核',
 legacy_summary_without_timing: '旧摘要缺少逐特征时间，只作为线索',
 shared_anchor_not_verified: '强证据复核未通过',
}
export function sharedReason(value: string) {
 if (value.startsWith('capture_interval_incomplete:')) return `采集时间段覆盖不足：${value.split(':')[1]}`
 if (value.startsWith('capture_unlocated_loss:')) return `采集丢包或裁剪影响本窗口：${value.split(':')[1]}`
 if (value.startsWith('capture_source_unregistered:')) return `采集来源未注册：${value.split(':')[1]}`
 return reasons[value] || value
}
function RecordReasons({ values }: { values: string[] }) {
 const grouped = new Map<string, number>()
 for (const value of values) grouped.set(value, (grouped.get(value) ?? 0) + 1)
 const rows = [...grouped].map(([value, count]) => <p className="shared-record-reason" key={value}><span>{sharedReason(value)}</span>{count > 1 && <span className="shared-access-muted">共 {count} 次</span>}</p>)
 return <div className="shared-record-reasons">{rows.slice(0, 2)}{rows.length > 2 && <details><summary>其他原因（{rows.length - 2} 类）</summary><div className="shared-record-detail-scroll">{rows.slice(2)}</div></details>}</div>
}
const formatTime = (value?: string) => value && !value.startsWith('0001-') ? new Date(value).toLocaleString() : ''

export function SharedPolicyRecords() {
 const [params, setParams] = useSearchParams()
 const [processingOpen,setProcessingOpen]=useState(false)
 const [cursors, setCursors] = useState<string[]>([''])
 const requestedResult = params.get('decision_result') ?? 'matched'
 const result = ['matched', 'insufficient', 'expired', 'all'].includes(requestedResult) ? requestedResult : 'matched'
 const account = params.get('decision_account') ?? ''
 const ip = params.get('decision_ip') ?? ''
 const from = params.get('decision_from') ?? ''
 const to = params.get('decision_to') ?? ''
 const observation = params.get('observation_id') ?? ''
 const update = (key: string, value: string) => { setCursors(['']); setParams(current => { const next = new URLSearchParams(current); value ? next.set(key, value) : next.delete(key); return next }) }
 const queryParams = new URLSearchParams({ trigger: 'shared_access', result, limit: '30', cursor: cursors.at(-1) || '' })
 if (processingOpen) queryParams.set('include_processing','true')
 if (result === 'all') queryParams.delete('result')
 if (account) queryParams.set('account_id', account)
 if (ip) queryParams.set('ip', ip)
 if (observation) queryParams.set('observation_id', observation)
 const fromTime = from ? new Date(from).getTime() : undefined
 const toTime = to ? new Date(to).getTime() : undefined
 const invalidRange = (fromTime !== undefined && !Number.isFinite(fromTime)) || (toTime !== undefined && !Number.isFinite(toTime)) || (fromTime !== undefined && toTime !== undefined && fromTime >= toTime)
 if (fromTime !== undefined && Number.isFinite(fromTime)) queryParams.set('from', new Date(fromTime).toISOString())
 if (toTime !== undefined && Number.isFinite(toTime)) queryParams.set('to', new Date(toTime).toISOString())
 const query = useQuery({ queryKey: ['shared-policy-records', queryParams.toString()], queryFn: () => request<{ items: SharedPolicyDecision[]; next_cursor: string; processing?: {ip:string;state:string;first_received_at:string}[]; processing_has_more?:boolean }>(`/policy-decisions?${queryParams}`), enabled: !invalidRange, refetchInterval: 5000 })
 return <Card title="策略触发记录" className="shared-records">
  <div className="shared-record-intro"><Tag>仅记录，未执行</Tag><span>原定动作：下线</span><details><summary>判定与执行说明</summary><p>路由器身份、下游共享关系及事件时账号归责均核验通过后，才可记录策略命中。现有协议或接入线索不会直接生成命中，执行功能保持关闭。</p></details></div>
  <div className="shared-record-filters">
   <label>结果<Select aria-label="记录结果" value={result} onChange={value => update('decision_result', value)} options={[{ value: 'matched', label: '策略命中' }, { value: 'insufficient', label: '归责或覆盖不足' }, { value: 'expired', label: '证据已过期' }, { value: 'all', label: '全部评估' }]} /></label>
   <label>账号<Input aria-label="记录账号" value={account} allowClear onChange={e => update('decision_account', e.target.value)} /></label>
   <label>IP<Input aria-label="记录 IP" value={ip} allowClear onChange={e => update('decision_ip', e.target.value)} /></label>
   <label>开始时间<Input aria-label="记录开始时间" type="datetime-local" value={from} onChange={e => update('decision_from', e.target.value)} /></label>
   <label>结束时间<Input aria-label="记录结束时间" type="datetime-local" value={to} onChange={e => update('decision_to', e.target.value)} /></label>
  </div>

  {observation && <p className="shared-record-id">当前观察：{observation} <Button type="link" onClick={() => update('observation_id', '')}>清除关联筛选</Button></p>}
  {invalidRange ? <Alert type="warning" title="请填写有效时间，且结束时间晚于开始时间" /> : query.isError ? <AppErrorAlert title="策略记录读取失败" /> : query.isLoading ? <AppLoadingState rows={3} /> : !query.data?.items.length ? <div className="shared-record-empty"><Empty description={result==='matched'?'当前筛选暂无策略命中记录':'当前筛选暂无评估记录'} />{result==='matched'&&<><p className="shared-access-muted">已识别的路由器仍需核验共享关系，采集待办不属于策略命中。</p><Button onClick={()=>update('decision_result','insufficient')}>查看未通过评估</Button></>}</div> : <div className="shared-record-list">{query.data.items.map(item => <article key={item.decision_id} className="shared-record-item">
   <div className="shared-record-heading"><strong>{item.account_id || item.ip}</strong><Tag color={item.result === 'matched' ? 'green' : 'orange'}>{resultLabels[item.result]}</Tag><Tag>仅记录，未执行</Tag></div>
   <dl className="shared-record-facts"><div><dt>{item.result === 'matched' ? '命中时间' : '评估时间'}</dt><dd>{formatTime(item.evaluated_at)}</dd></div><div><dt>IP</dt><dd>{item.ip}</dd></div><div><dt>接入范围</dt><dd>{[item.campus_id, item.access_domain].filter(Boolean).join(' / ')}</dd></div><div><dt>原定动作</dt><dd>下线</dd></div></dl>
   <RecordReasons values={item.reasons} />
   {item.result === 'matched' && item.evidence_expires_at && new Date(item.evidence_expires_at).getTime() <= Date.now() && <p className="shared-access-muted">证据已过期，保留当时命中记录。</p>}
   <details><summary>查看证据与版本</summary><div className="shared-record-detail-scroll"><p>策略版本：{item.policy_revision} · 规则：{item.evidence.rule_version}</p><p className="shared-record-id">证据版本：{item.evidence_version}</p><p>观察窗口：{formatTime(item.evidence.from)} 至 {formatTime(item.evidence.to)}</p>{!!item.evidence.device_lower_bound && <p>设备数量下界：{item.evidence.device_lower_bound}</p>}{item.evidence.records?.map(ref => <p className="shared-record-id" key={`${ref.source}/${ref.event_id}`}>{[ref.source, ref.collector_instance_id, ref.event_id].filter(Boolean).join(' / ')}</p>)}<Link to={`/shared-access/observations/${encodeURIComponent(item.observation_id)}`}>查看共享详情</Link></div></details>
  </article>)}</div>}
  <div className="shared-record-pagination"><Button disabled={cursors.length === 1} onClick={() => setCursors(cursors.slice(0, -1))}>上一页</Button><Button disabled={!query.data?.next_cursor} onClick={() => setCursors([...cursors, query.data?.next_cursor || ''])}>下一页</Button></div>
  <details className="shared-record-processing" onToggle={e=>setProcessingOpen(e.currentTarget.open)}><summary>查看采集处理进度（不属于策略命中）</summary>
   {processingOpen&&(query.isFetching?<p>正在读取处理进度</p>:query.isError?<p>处理进度读取失败</p>:query.data?.processing?.length?<><p>本次返回 {query.data.processing.length} 项待办{query.data.processing_has_more?'，还有其他待办':''}。账号筛选只作用于已生成的记录。</p><ul>{query.data.processing.slice(0,5).map(item=><li key={item.ip}><span className="shared-record-id">{item.ip}</span><Tag>{item.state==='failed'?'失败待重试':'处理中'}</Tag></li>)}</ul>{query.data.processing.length>5&&<p className="shared-access-muted">仅展开前 5 项，其他待办仍继续处理。</p>}</>:<p>当前范围没有返回待办。此状态不代表已确认或排除共享。</p>)}
  </details>
 </Card>
}
