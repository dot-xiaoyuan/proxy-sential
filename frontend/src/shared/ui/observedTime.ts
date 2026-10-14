/**
 * One relative-time formatter for every device list.
 *
 * 终端 / 网络设备 / 发现线索 previously rendered the same "最近观测" column with
 * different formats (relative in one list, absolute in another). Lists now share
 * this helper so a timestamp reads the same everywhere; the exact second stays in
 * the element title.
 */
export function observedTimeLabel(value?: string, now: Date = new Date()) {
  if (!value) return ''
  const at = new Date(value)
  if (!Number.isFinite(at.getTime())) return ''
  const minutes = Math.floor((now.getTime() - at.getTime()) / 60000)
  if (minutes >= 0 && minutes < 1) return '刚刚'
  if (minutes >= 1 && minutes < 60) return `${minutes} 分钟前`
  const clock = at.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })
  if (at.toDateString() === now.toDateString()) return `今天 ${clock}`
  const yesterday = new Date(now)
  yesterday.setDate(now.getDate() - 1)
  if (at.toDateString() === yesterday.toDateString()) return `昨天 ${clock}`
  return at.toLocaleString('zh-CN', {
    year: at.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

export function observedTimeTitle(value?: string) {
  if (!value) return undefined
  const at = new Date(value)
  return Number.isFinite(at.getTime()) ? at.toLocaleString('zh-CN', { hour12: false }) : undefined
}
