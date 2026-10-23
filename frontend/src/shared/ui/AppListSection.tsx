import type { ReactNode } from 'react'

import { AppEmptyState, AppErrorAlert, AppLoadingState } from './AppStateFeedback'

export interface AppListSectionProps {
  isLoading?: boolean
  isError?: boolean
  isEmpty?: boolean
  errorTitle?: ReactNode
  errorMessage?: ReactNode
  emptyText?: ReactNode
  loadingRows?: number
  children?: ReactNode
}

/**
 * 列表的加载 / 错误 / 空态三段式判断集中在这里，页面只关心列表本身。
 * 顺序与原有页面一致：错误优先于加载，加载优先于空态。
 */
export function AppListSection({
  isLoading,
  isError,
  isEmpty,
  errorTitle,
  errorMessage,
  emptyText,
  loadingRows = 4,
  children,
}: AppListSectionProps) {
  if (isError) return <AppErrorAlert message={errorMessage} title={errorTitle} />
  if (isLoading) return <AppLoadingState rows={loadingRows} />
  if (isEmpty) return <AppEmptyState description={emptyText} />
  return <>{children}</>
}
