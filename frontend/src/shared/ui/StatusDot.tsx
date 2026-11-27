import type { ReactNode } from 'react'

export type StatusTone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral'

export function StatusDot({
  tone = 'neutral',
  children,
}: {
  tone?: StatusTone
  children: ReactNode
}) {
  return (
    <span className={`ps-status-pill ps-status-${tone}`}>
      <span className="ps-status-dot" aria-hidden="true" />
      <span>{children}</span>
    </span>
  )
}
