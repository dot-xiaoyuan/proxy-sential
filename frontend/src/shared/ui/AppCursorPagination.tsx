import { Button, Space } from 'antd'
import type { ReactNode } from 'react'

interface AppCursorPaginationProps {
  previous: boolean
  next: boolean
  onPrevious: () => void
  onNext: () => void
  /** 可选的页码或结果说明，放在按钮左侧 */
  label?: ReactNode
  /** 数据刷新中或暂不可翻页时同时禁用两侧按钮 */
  disabled?: boolean
}

/**
 * 游标分页统一操作区。服务端分页使用 AppServerPagination，
 * 只有上一页/下一页的游标列表统一使用本组件，保证位置与间距一致。
 */
export function AppCursorPagination({ previous, next, onPrevious, onNext, label, disabled = false }: AppCursorPaginationProps) {
  return (
    <div className="list-pagination app-cursor-pagination">
      {label !== undefined && <span className="app-cursor-label">{label}</span>}
      <Space wrap>
        <Button disabled={disabled || !previous} onClick={onPrevious}>上一页</Button>
        <Button disabled={disabled || !next} onClick={onNext}>下一页</Button>
      </Space>
    </div>
  )
}
