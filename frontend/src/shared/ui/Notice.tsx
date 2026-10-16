import type { ReactNode } from 'react'

type NoticeProps = {
  title?: ReactNode
  description?: ReactNode
  type?: 'info' | 'success' | 'warning' | 'error'
  className?: string
  action?: ReactNode
  showIcon?: boolean
  closable?: boolean
  onClose?: () => void
}

/** A compact status note that sits in the reading flow instead of a banner. */
export function Notice({ title, description, type = 'info', className = '', action, closable, onClose }: NoticeProps) {
  return <aside className={`app-notice app-notice-${type} ${className}`.trim()} role={type === 'error' ? 'alert' : 'status'}>
    <div className="app-notice-content">
      {title && <strong className="app-notice-title">{title}</strong>}
      {description && <div className="app-notice-description">{description}</div>}
    </div>
    {action && <div className="app-notice-action">{action}</div>}
    {closable && <button type="button" className="app-notice-close" aria-label="关闭提示" onClick={onClose}>关闭</button>}
  </aside>
}
