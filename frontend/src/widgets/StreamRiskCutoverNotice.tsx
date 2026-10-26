import { useStreamRiskCutover } from '../shared/api/queries'
import { AppErrorAlert } from '../shared/ui'

export function StreamRiskCutoverNotice() {
  const cutover = useStreamRiskCutover()
  if (cutover.isError) return <AppErrorAlert title="读取新风险链状态失败" message={cutover.error.message} />
  if (!cutover.data?.active || !cutover.data.status) return null
  const status = cutover.data.status
  return <section className="surface risk-cutover-status" aria-label="新存查链历史缺口">
    <strong>新存查链历史缺口</strong>
    <p>本次旧待办 {status.canceled_subjects.toLocaleString()} 个主体已审计取消，状态为未处理。{status.prior_canceled_subjects > 0 && <>此前审计取消 {status.prior_canceled_subjects.toLocaleString()} 个主体。</>}新输入从 {new Date(status.accepted_after).toLocaleString('zh-CN')} 起单独处理。</p>
    {(status.source_gaps?.length ? status.source_gaps : status.source_gap ? [status.source_gap] : []).map(gap => <p key={gap.epoch}>
      {gap.source_owner === 'packet-sidecar' ? 'packet/TTL' : gap.source_owner === 'handshake-sidecar' ? '握手摘要' : gap.source_owner} 旧来源 {gap.canceled_records.toLocaleString()} 条、{gap.canceled_bytes.toLocaleString()} 字节已分 {gap.audit_batches.toLocaleString()} 批审计取消，保留原始文件；新来源从 {new Date(gap.cutoff_at).toLocaleString('zh-CN')} 的文件截止点继续。历史缺口不计入新鲜输入达标统计。
    </p>)}
    {status.router_gap && <p>路由识别旧索引 {status.router_gap.canceled_index_rows.toLocaleString()} 条已审计取消，状态为未处理。{status.prior_router_canceled_index_rows > 0 && <>此前审计取消 {status.prior_router_canceled_index_rows.toLocaleString()} 条。</>}识别从 {new Date(status.router_gap.indexed_after).toLocaleString('zh-CN')} 的索引截止点继续；历史缺口不计入新鲜输入达标统计。</p>}
    <p>当前待处理 {status.pending_subjects.toLocaleString()} 个主体，其中 {status.pending_older_than_5s.toLocaleString()} 个已等待超过 5 秒。这里是主体队列状态，不代表逐条事件的 5 秒验收结果。</p>
  </section>
}
