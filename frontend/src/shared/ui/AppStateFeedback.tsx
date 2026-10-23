import { Notice as Alert } from './Notice'
import type { ReactNode } from 'react'
import { Empty, Skeleton } from 'antd'

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
  title?: ReactNode
  message?: ReactNode
  action?: ReactNode
  className?: string
}

export function AppErrorAlert({
  title = '数据加载异常',
  message = '请求未完成，请稍后重试；如持续失败，请检查网络连接与账号权限。',
  action,
  className,
}: AppErrorAlertProps) {
  return (
    <Alert action={action} className={className} description={message} showIcon title={title} type="error" />
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
