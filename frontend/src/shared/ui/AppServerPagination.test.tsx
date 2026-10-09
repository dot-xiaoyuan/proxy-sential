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
})
