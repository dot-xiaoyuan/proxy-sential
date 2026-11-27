import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AppServerPagination } from './AppServerPagination'
import { RecordCursorPagination } from './RecordCursorPagination'

describe('AppServerPagination', () => {
  it('统一显示总数、页码和20/50页长', () => {
    const onChange = vi.fn()
    render(<AppServerPagination page={2} pageSize={20} total={88} onChange={onChange} />)
    expect(screen.getByText('共 88 条')).toBeInTheDocument()
    expect(screen.getByTitle('2')).toHaveClass('ant-pagination-item-active')
    expect(document.querySelector('.app-server-pagination')).toHaveClass('ps-pagination-bar')
    fireEvent.click(screen.getByTitle('3'))
    expect(onChange).toHaveBeenCalledWith(3, 20)
  })

  it('服务端分页加载期间禁用翻页操作并标注 aria-busy', () => {
    render(
      <AppServerPagination disabled page={2} pageSize={20} total={88} onChange={() => undefined} />,
    )
    const nav = document.querySelector('.app-server-pagination')
    expect(nav).toHaveClass('ant-pagination-disabled')
    expect(nav).toHaveAttribute('aria-busy', 'true')
  })

  it('直接跳到尚未访问的第42页', () => {
    const onChange = vi.fn()
    render(<AppServerPagination page={2} pageSize={20} total={98765} onChange={onChange} />)
    const jump = document.querySelector('.ant-pagination-options-quick-jumper input')!
    fireEvent.change(jump, { target: { value: '42' } })
    fireEvent.keyUp(jump, { key: 'Enter', keyCode: 13 })
    expect(onChange).toHaveBeenCalledWith(42, 20)
  })

  it('切换每页50条会回到第一页', () => {
    const onChange = vi.fn()
    render(<AppServerPagination page={3} pageSize={20} total={200} onChange={onChange} />)
    fireEvent.mouseDown(screen.getByRole('combobox'))
    fireEvent.click(screen.getByText('50 / page'))
    expect(onChange).toHaveBeenCalledWith(1, 50)
  })

  it('没有准确统计时不展示假总数或可跳转页', () => {
    render(<AppServerPagination page={1} pageSize={20} onChange={() => undefined} />)
    expect(screen.getByText('正在读取总数')).toBeVisible()
    expect(screen.queryByText('共 0 条')).not.toBeInTheDocument()
    expect(document.querySelector('.app-server-pagination')).toHaveClass('ant-pagination-disabled')
  })

  it('统计读取失败保留明确状态而不冒充空列表', () => {
    render(
      <AppServerPagination
        page={1}
        pageSize={20}
        totalText="数量读取失败"
        onChange={() => undefined}
      />,
    )
    expect(screen.getByText('数量读取失败')).toBeVisible()
    expect(screen.queryByText('共 0 条')).not.toBeInTheDocument()
  })

  it('真实空结果显示共0条并禁用下一页', () => {
    render(<AppServerPagination page={1} pageSize={20} total={0} onChange={() => undefined} />)
    expect(screen.getByText('共 0 条')).toBeVisible()
    expect(screen.getByTitle('Next Page')).toHaveClass('ant-pagination-disabled')
  })
})

describe('RecordCursorPagination', () => {
  it('统一展示汇总、紧凑方块翻页按钮、首页跳回省略与每页条数', () => {
    const onFirst = vi.fn()
    const onPrevious = vi.fn()
    const onNext = vi.fn()
    const onPageSizeChange = vi.fn()

    render(
      <RecordCursorPagination
        page={3}
        pageSize={20}
        count={20}
        nextCursor="cursor-4"
        fetching={false}
        onFirst={onFirst}
        onPrevious={onPrevious}
        onNext={onNext}
        onPageSizeChange={onPageSizeChange}
      />,
    )

    const nav = screen.getByRole('navigation', { name: '列表分页' })
    expect(nav).toHaveClass('ps-pagination-bar', 'ps-cursor-pagination')
    expect(nav).toHaveAttribute('aria-busy', 'false')
    expect(screen.getByText('第 3 页 · 本页 20 条')).toBeVisible()

    const currentPage = screen.getByText('3')
    expect(currentPage).toHaveAttribute('aria-current', 'page')
    expect(currentPage).toHaveClass('ps-pagination-item-active')
    expect(screen.getByText('•••')).toBeVisible()

    const firstBtn = screen.getByRole('button', { name: '首页' })
    expect(firstBtn).toHaveTextContent('1')
    fireEvent.click(firstBtn)
    expect(onFirst).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('button', { name: '上一页' }))
    expect(onPrevious).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(onNext).toHaveBeenCalledTimes(1)

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '每页条数' }))
    fireEvent.click(screen.getByText('50 条/页'))
    expect(onPageSizeChange).toHaveBeenCalledWith(50, expect.anything())
  })

  it('首页、第2页及加载态下正确控制首页跳回显示与按钮禁用', () => {
    const { rerender } = render(
      <RecordCursorPagination
        page={1}
        pageSize={20}
        count={5}
        nextCursor=""
        fetching={false}
        onFirst={() => undefined}
        onPrevious={() => undefined}
        onNext={() => undefined}
        onPageSizeChange={() => undefined}
      />,
    )

    expect(screen.queryByRole('button', { name: '首页' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    expect(screen.getByText('1')).toHaveAttribute('aria-current', 'page')

    rerender(
      <RecordCursorPagination
        page={2}
        pageSize={20}
        count={20}
        nextCursor="cursor-3"
        fetching
        onFirst={() => undefined}
        onPrevious={() => undefined}
        onNext={() => undefined}
        onPageSizeChange={() => undefined}
      />,
    )

    expect(screen.getByRole('navigation', { name: '列表分页' })).toHaveAttribute(
      'aria-busy',
      'true',
    )
    expect(screen.queryByRole('button', { name: '首页' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()

    rerender(
      <RecordCursorPagination
        page={3}
        pageSize={20}
        count={20}
        nextCursor="cursor-4"
        fetching
        onFirst={() => undefined}
        onPrevious={() => undefined}
        onNext={() => undefined}
        onPageSizeChange={() => undefined}
      />,
    )

    expect(screen.getByRole('button', { name: '首页' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
  })
})
