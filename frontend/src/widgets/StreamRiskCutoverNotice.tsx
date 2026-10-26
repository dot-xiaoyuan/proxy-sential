import { useStreamRiskCutover } from '../shared/api/queries'
import { AppErrorAlert } from '../shared/ui'

export function StreamRiskCutoverNotice() {
  const cutover = useStreamRiskCutover()
  if (cutover.isError) return <AppErrorAlert title="读取新风险链状态失败" message={cutover.error.message} />
  if (!cutover.data?.active || !cutover.data.status) return null
  const status = cutover.data.status
  return <section className="surface risk-cutover-status" aria-label="新风险链历史缺口">
    <strong>新风险链历史缺口</strong>
    <p>旧待办 {status.canceled_subjects.toLocaleString()} 个主体已审计取消，状态为未处理；新输入从 {new Date(status.accepted_after).toLocaleString('zh-CN')} 起单独处理。</p>
    <p>当前待处理 {status.pending_subjects.toLocaleString()} 个主体，其中 {status.pending_older_than_5s.toLocaleString()} 个已等待超过 5 秒。这里是主体队列状态，不代表逐条事件的 5 秒验收结果。</p>
  </section>
}
