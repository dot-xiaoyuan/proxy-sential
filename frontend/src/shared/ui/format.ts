/**
 * 全站统一的展示格式化入口。
 *
 * 时间与计数的格式此前散落在各页面（`toLocaleString()` / `toLocaleString('zh-CN')` /
 * 自定义 `when`、`time`、`fmtTime`），同一字段在不同页面会出现不同格式，Go 零值时间
 * （`0001-01-01T00:00:00Z`）还会被渲染成 0001 年。这里统一为：
 * - 缺失、零值、非法值一律返回空串，交给调用方决定是否渲染（与 `displayField` 一致）；
 * - 时间固定 zh-CN、24 小时制，避免浏览器语言影响；
 * - 计数固定 zh-CN 千分位。
 */
const zeroTimePattern = /^000\d-/

function parse(value?: string | null): Date | undefined {
  if (!value || zeroTimePattern.test(value)) return undefined
  const at = new Date(value)
  if (!Number.isFinite(at.getTime()) || at.getFullYear() < 1900) return undefined
  return at
}

export function formatDateTime(value?: string | null): string {
  const at = parse(value)
  return at ? at.toLocaleString('zh-CN', { hour12: false }) : ''
}

export function formatDate(value?: string | null): string {
  const at = parse(value)
  return at ? at.toLocaleDateString('zh-CN') : ''
}

export function formatClock(value?: string | null): string {
  const at = parse(value)
  return at
    ? at.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })
    : ''
}

export function formatCount(value?: number | null): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString('zh-CN') : ''
}

export function formatPercent(value?: number | null, digits = 1): string {
  return typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(digits)}%` : ''
}
