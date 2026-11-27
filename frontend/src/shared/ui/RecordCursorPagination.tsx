import { useState } from 'react'
import { Button, Select } from 'antd'

/**
 * 纯游标分页状态管理：按查询范围（scope）隔离页码与游标栈，
 * 切换筛选条件或每页条数时自动重置回第一页。
 */
export function useRecordCursorPagination(scope: string) {
  const [pageSize, setPageSize] = useState(20)
  const [paging, setPaging] = useState({ scope: '', page: 1, cursors: [''] })
  const current = paging.scope === scope ? paging : { scope, page: 1, cursors: [''] }
  return {
    page: current.page,
    pageSize,
    cursor: current.cursors[current.page - 1] ?? '',
    first: () => {
      if (current.page > 1) setPaging({ ...current, page: 1 })
    },
    next: (cursor: string) => {
      if (cursor)
        setPaging({
          scope,
          page: current.page + 1,
          cursors: [...current.cursors.slice(0, current.page), cursor],
        })
    },
    previous: () => {
      if (current.page > 1) setPaging({ ...current, page: current.page - 1 })
    },
    changePageSize: (size: number) => {
      setPageSize(size)
      setPaging({ scope: '', page: 1, cursors: [''] })
    },
  }
}

export type RecordCursorPaginationProps = {
  page: number
  pageSize: number
  count: number
  nextCursor: string
  fetching: boolean
  onFirst?: () => void
  onNext: () => void
  onPrevious: () => void
  onPageSizeChange: (size: number) => void
}

/**
 * 统一游标分页栏：与 AppServerPagination 共享底部对齐与汇总视觉规范，
 * 左侧展示当前页与本页条数，右侧提供首页、上一页、当前页码徽标、下一页与每页条数选择。
 */
export function RecordCursorPagination({
  page,
  pageSize,
  count,
  nextCursor,
  fetching,
  onFirst,
  onNext,
  onPrevious,
  onPageSizeChange,
}: RecordCursorPaginationProps) {
  const isFirstPage = page <= 1
  return (
    <nav
      aria-busy={fetching}
      aria-label="列表分页"
      className="ps-pagination-bar ps-cursor-pagination shared-policy-cursor-pagination"
    >
      <span className="ps-pagination-summary tabular-num">
        第 {page} 页 · 本页 {count} 条
      </span>
      <div className="ps-pagination-controls">
        {onFirst && (
          <Button
            aria-label="首页"
            autoInsertSpace={false}
            disabled={isFirstPage || fetching}
            onClick={onFirst}
          >
            首页
          </Button>
        )}
        <Button aria-label="上一页" disabled={isFirstPage || fetching} onClick={onPrevious}>
          上一页
        </Button>
        <span aria-current="page" className="ps-pagination-page-badge tabular-num">
          第 {page} 页
        </span>
        <Button aria-label="下一页" disabled={!nextCursor || fetching} onClick={onNext}>
          下一页
        </Button>
        <Select
          aria-label="每页条数"
          className="ps-pagination-size-select"
          disabled={fetching}
          value={pageSize}
          options={[
            { value: 20, label: '20 条/页' },
            { value: 50, label: '50 条/页' },
          ]}
          onChange={onPageSizeChange}
        />
      </div>
    </nav>
  )
}
