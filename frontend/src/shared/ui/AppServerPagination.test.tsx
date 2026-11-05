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
		render(<AppServerPagination page={1} pageSize={20} totalText="数量读取失败" onChange={() => undefined} />)
		expect(screen.getByText('数量读取失败')).toBeVisible()
		expect(screen.queryByText('共 0 条')).not.toBeInTheDocument()
	})

	it('真实空结果显示共0条并禁用下一页', () => {
		render(<AppServerPagination page={1} pageSize={20} total={0} onChange={() => undefined} />)
		expect(screen.getByText('共 0 条')).toBeVisible()
		expect(screen.getByTitle('Next Page')).toHaveClass('ant-pagination-disabled')
	})
})
