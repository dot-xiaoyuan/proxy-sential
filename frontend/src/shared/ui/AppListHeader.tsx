import type { ReactNode } from 'react'

interface AppListHeaderProps {
  title: ReactNode
  /** 结果数量，例如「4 个终端身份」 */
  count?: ReactNode
  /** 可选的一行说明；没有说明时省略，保持一致的高度 */
  description?: ReactNode
  /** 右侧操作，例如列设置、视图切换 */
  actions?: ReactNode
}

/**
 * 列表面板统一头部：标题 + 数量 + 可选说明 + 右侧操作。
 * 说明不重复页面副标题；操作按钮统一靠右。
 */
export function AppListHeader({ title, count, description, actions }: AppListHeaderProps) {
  return (
    <div className="app-list-header">
      <div className="app-list-header-main">
        <h4 className="app-list-title">{title}</h4>
        {count !== undefined && <span className="app-list-count">{count}</span>}
        {description && <span className="app-list-description">{description}</span>}
      </div>
      {actions && <div className="app-list-actions">{actions}</div>}
    </div>
  )
}
