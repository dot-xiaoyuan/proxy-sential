export interface OperationTask {
  task_id: string
  kind: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  created_at: string
  completed_at?: string
  result?: unknown
  error?: string
  response_status?: number
}

const storageKey = 'sentinel-pending-tasks'
const listeners = new Set<() => void>()
const polling = new Map<string, Promise<OperationTask>>()
let generation = 0
let reads = 0
const waitingReads: Array<() => void> = []
async function boundedRead(read: () => Promise<OperationTask>) {
  if (reads >= 4) await new Promise<void>(resolve => waitingReads.push(resolve))
  else reads++
  try { return await read() }
  finally {
    const next = waitingReads.shift()
    if (next) next()
    else reads--
  }
}
let snapshot: OperationTask[] = []
try {
  const stored: unknown = JSON.parse(localStorage.getItem(storageKey) || '[]')
  if (Array.isArray(stored)) snapshot = stored.filter(isOperationTask).filter(job => ['queued', 'running'].includes(job.status))
} catch { /* A disabled browser store does not prevent task submissions. */ }

export function isOperationTask(value: unknown): value is OperationTask {
  if (!value || typeof value !== 'object') return false
  const job = value as Partial<OperationTask>
  return typeof job.task_id === 'string' && typeof job.kind === 'string' && typeof job.created_at === 'string' && ['queued', 'running', 'completed', 'failed', 'cancelled'].includes(job.status || '')
}
export function trackOperationTask(job: OperationTask) {
  // The progress registry never persists business results or credentials.
  const { result: _result, ...progress } = job
  const updated = [progress, ...snapshot.filter(previous => previous.task_id !== job.task_id)]
  // Keep every pending task across reloads; only finished progress is bounded.
  // Display limits belong to the progress component, not this durable registry.
  const pending = updated.filter(job => ['queued', 'running'].includes(job.status))
  const finished = updated.filter(job => !['queued', 'running'].includes(job.status)).slice(0, 8)
  snapshot = [...pending, ...finished]
  try { localStorage.setItem(storageKey, JSON.stringify(snapshot.filter(job => ['queued', 'running'].includes(job.status)))) } catch { /* Optional browser persistence. */ }
  for (const listener of listeners) listener()
}
export const taskSnapshot = () => snapshot
export function subscribeTasks(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener) } }
export function clearOperationTasks() {
  generation++
  snapshot = []
  try { localStorage.removeItem(storageKey) } catch { /* Optional browser persistence. */ }
  for (const listener of listeners) listener()
}
export function awaitOperationTask(initial: OperationTask, read: (id: string) => Promise<OperationTask>): Promise<OperationTask> {
  const key = `${generation}:${initial.task_id}`
  const existing = polling.get(key)
  if (existing) return existing
  const startedGeneration = generation
  // Defer the first notification until the shared promise is registered.
  const pending = Promise.resolve().then(() => pollOperationTask(initial, read, startedGeneration)).finally(() => polling.delete(key))
  polling.set(key, pending)
  return pending
}
async function pollOperationTask(initial: OperationTask, read: (id: string) => Promise<OperationTask>, startedGeneration: number): Promise<OperationTask> {
  let job = initial
  const deadline = Date.now() + 30 * 60 * 1000
  for (;;) {
    if (generation !== startedGeneration) throw new Error('登录状态已变化，已停止查询此前的任务')
    trackOperationTask(job)
    if (['completed', 'failed', 'cancelled'].includes(job.status)) return job
    if (Date.now() >= deadline) throw new Error('任务仍可能在后台执行，请通过任务状态继续查看')
    await new Promise(resolve => setTimeout(resolve, 1000))
    job = await boundedRead(() => read(job.task_id))
  }
}
