import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { Alert, Button, Typography } from 'antd'
import { request } from '../api/client'
import { awaitOperationTask, subscribeTasks, taskSnapshot, trackOperationTask, type OperationTask } from '../api/operationTasks'

const names: Record<string, string> = {
  '/application-library/pull': '应用规则拉取', '/application-library/import': '应用离线包导入',
  '/device-fingerprint-library/update': '终端特征库更新', '/device-fingerprint-library/import': '终端离线包导入',
  '/device-fingerprint-library/validate': '终端离线包校验',
}
const states = { queued: '等待执行', running: '正在执行', completed: '已完成', failed: '失败', cancelled: '已取消' }

export function OperationTaskProgress() {
  const jobs = useSyncExternalStore(subscribeTasks, taskSnapshot)
  const [error, setError] = useState('')
  const resumed = useRef(new Set<string>())
  useEffect(() => {
    for (const job of jobs.filter(job => ['queued', 'running'].includes(job.status)).slice(0, 8)) {
      if (resumed.current.has(job.task_id)) continue
      resumed.current.add(job.task_id)
      void awaitOperationTask(job, id => request<OperationTask>(`/tasks/${encodeURIComponent(id)}`)).catch(error => setError(String(error)))
    }
  }, [jobs])
  if (!jobs.length) return null
  return <section className="operation-task-progress" aria-label="后台任务进度">
    {error && <Alert type="error" title="任务状态查询或取消失败" description={error} />}
    {jobs.length > 8 && <Typography.Text type="secondary">共 {jobs.length} 项任务，展示最近 8 项；其余任务保留在后台执行。</Typography.Text>}
    {jobs.slice(0, 8).map(job => <div className="operation-task-row" key={job.task_id}>
      <Typography.Text>{names[job.kind] || (job.kind.endsWith('/test') ? '连接器测试' : '外部账号预览')} · {states[job.status]}</Typography.Text>
      <Typography.Text className="operation-task-id" type="secondary">{job.task_id}</Typography.Text>
      {['queued', 'running'].includes(job.status) && <Button size="small" onClick={() => { void request<OperationTask>(`/tasks/${encodeURIComponent(job.task_id)}/cancel`, { method: 'POST' }).then(trackOperationTask).catch(error => setError(String(error))) }}>取消任务</Button>}
      {job.error && <Typography.Text type="danger">{job.error}</Typography.Text>}
    </div>)}
  </section>
}
