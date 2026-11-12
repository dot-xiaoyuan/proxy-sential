import { useState } from 'react'
import { Button, Select } from 'antd'

export function useRecordCursorPagination(scope: string) {
  const [pageSize, setPageSize] = useState(20)
  const [paging, setPaging] = useState({ scope: '', page: 1, cursors: [''] })
  const current = paging.scope === scope ? paging : { scope, page: 1, cursors: [''] }
  return {
    page: current.page,
    pageSize,
    cursor: current.cursors[current.page - 1] ?? '',
    next: (cursor: string) => { if (cursor) setPaging({ scope, page: current.page + 1, cursors: [...current.cursors.slice(0, current.page), cursor] }) },
    previous: () => { if (current.page > 1) setPaging({ ...current, page: current.page - 1 }) },
    changePageSize: (size: number) => { setPageSize(size); setPaging({ scope: '', page: 1, cursors: [''] }) },
  }
}

export function RecordCursorPagination({ page, pageSize, count, nextCursor, fetching, onNext, onPrevious, onPageSizeChange }: {
  page: number; pageSize: number; count: number; nextCursor: string; fetching: boolean;
  onNext: () => void; onPrevious: () => void; onPageSizeChange: (size: number) => void;
}) {
  return <div className="shared-policy-cursor-pagination">
    <span>第 {page} 页 · 本页 {count} 条</span>
    <Select aria-label="每页条数" value={pageSize} options={[{ value: 20, label: '每页 20 条' }, { value: 50, label: '每页 50 条' }]} onChange={onPageSizeChange} />
    <Button disabled={page === 1 || fetching} onClick={onPrevious}>上一页</Button>
    <Button disabled={!nextCursor || fetching} onClick={onNext}>下一页</Button>
  </div>
}
