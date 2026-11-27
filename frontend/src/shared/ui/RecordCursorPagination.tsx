import { useState } from 'react'
import { LeftOutlined, RightOutlined } from '@ant-design/icons'
import { Select } from 'antd'

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
 * 统一游标分页栏：视觉与 Ant Design Pagination 保持完全一致，
 * 左侧展示当前页与本页条数，右侧提供紧凑方块翻页按钮、高亮当前页码与每页条数选择。
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
  const showFirstJump = Boolean(onFirst) && page > 2
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
        <button
          aria-label="上一页"
          className="ps-pagination-btn ps-pagination-nav-btn"
          disabled={isFirstPage || fetching}
          title="上一页"
          type="button"
          onClick={onPrevious}
        >
          <LeftOutlined />
        </button>
        {showFirstJump && (
          <>
            <button
              aria-label="首页"
              className="ps-pagination-btn ps-pagination-item tabular-num"
              disabled={fetching}
              title="第 1 页"
              type="button"
              onClick={onFirst}
            >
              1
            </button>
            <span aria-hidden="true" className="ps-pagination-ellipsis">
              •••
            </span>
          </>
        )}
        <span
          aria-current="page"
          className="ps-pagination-item ps-pagination-item-active tabular-num"
        >
          {page}
        </span>
        <button
          aria-label="下一页"
          className="ps-pagination-btn ps-pagination-nav-btn"
          disabled={!nextCursor || fetching}
          title="下一页"
          type="button"
          onClick={onNext}
        >
          <RightOutlined />
        </button>
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
