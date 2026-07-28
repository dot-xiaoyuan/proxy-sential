import type { ReactNode } from 'react'
import { Alert, Empty, Skeleton } from 'antd'

interface AppLoadingProps {
  active?: boolean
  rows?: number
}

export function AppLoadingState({ rows = 4 }: AppLoadingProps) {
  return (
    <div className="app-loading-state">
      <Skeleton active paragraph={{ rows }} />
    </div>
  )
}

interface AppErrorAlertProps {
  title?: string
  message?: string
  onRetry?: () => void
}

export function AppErrorAlert({
  title = '数据加载异常',
  message = '网络请求中断或 Backend 节点未响应，请检查链接或稍后重试。',
}: AppErrorAlertProps) {
  return (
    <Alert
      description={message}
      message={title}
      showIcon
      type="error"
    />
  )
}

interface AppEmptyProps {
  description?: ReactNode
}

export function AppEmptyState({ description = '暂无符合筛选条件的数据记录' }: AppEmptyProps) {
  return (
    <div className="app-empty-state">
      <Empty description={description} image={Empty.PRESENTED_IMAGE_SIMPLE} />
    </div>
  )
}
