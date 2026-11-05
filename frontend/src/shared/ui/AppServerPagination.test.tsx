import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AppServerPagination } from './AppServerPagination'

describe('AppServerPagination', () => {
	it('统一显示总数、页码和20/50页长', () => {
		const onChange = vi.fn()
		render(<AppServerPagination page={2} pageSize={20} total={88} onChange={onChange} />)
		expect(screen.getByText('共 88 条')).toBeInTheDocument()
		expect(screen.getByTitle('2')).toHaveClass('ant-pagination-item-active')
		fireEvent.click(screen.getByTitle('3'))
		expect(onChange).toHaveBeenCalledWith(3, 20)
	})

	it('服务端分页加载期间禁用翻页操作', () => {
		render(<AppServerPagination disabled page={2} pageSize={20} total={88} onChange={() => undefined} />)
		expect(document.querySelector('.app-server-pagination')).toHaveClass('ant-pagination-disabled')
	})

	it('游标模式保留真实总数但不提供没有游标的数字跳页', () => {
		const onChange = vi.fn()
		render(<AppServerPagination cursorMode page={2} pageSize={20} total={98765} totalText="共 98765 条" hasMore={false} onChange={onChange} />)
		expect(screen.getByText('共 98765 条')).toBeVisible()
		expect(screen.getByText('第 2 页')).toBeVisible()
		expect(screen.queryByTitle('3')).not.toBeInTheDocument()
		expect(document.querySelector('.ant-pagination-options-quick-jumper')).not.toBeInTheDocument()
		expect(screen.getByTitle('Next Page')).toBeDisabled()
		fireEvent.click(screen.getByTitle('Next Page'))
		expect(onChange).not.toHaveBeenCalled()
		fireEvent.click(screen.getByTitle('Previous Page'))
		expect(onChange).toHaveBeenCalledWith(1, 20)
	})

	it('下一页只依赖服务端游标而不依赖统计大小', () => {
		const onChange = vi.fn()
		render(<AppServerPagination cursorMode page={1} pageSize={20} total={0} hasMore onChange={onChange} />)
		expect(screen.getByTitle('Previous Page')).toBeDisabled()
		expect(screen.getByTitle('Next Page')).toBeEnabled()
		fireEvent.click(screen.getByTitle('Next Page'))
		expect(onChange).toHaveBeenCalledWith(2, 20)
	})

	it('尚未取得下一页游标时不从总数推测可翻页', () => {
		render(<AppServerPagination cursorMode page={1} pageSize={20} total={999} onChange={() => undefined} />)
		expect(screen.getByTitle('Next Page')).toBeDisabled()
	})

	it('游标模式切换页长回到第一页', () => {
		const onChange = vi.fn()
		render(<AppServerPagination cursorMode page={3} pageSize={20} total={200} hasMore onChange={onChange} />)
		fireEvent.mouseDown(screen.getByRole('combobox', { name: '每页记录数' }))
		fireEvent.click(screen.getByText('50 条/页'))
		expect(onChange).toHaveBeenCalledWith(1, 50)
	})

	it('加载期间禁用游标翻页和页长选择', () => {
		render(<AppServerPagination cursorMode disabled page={2} pageSize={20} total={200} hasMore onChange={() => undefined} />)
		expect(screen.getByTitle('Previous Page')).toBeDisabled()
		expect(screen.getByTitle('Next Page')).toBeDisabled()
		expect(screen.getByRole('combobox', { name: '每页记录数' })).toBeDisabled()
	})
})
