import { Button, Pagination, Select } from 'antd'
import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

type AppServerPaginationProps = {
	disabled?: boolean
	page: number
	pageSize: number
	total: number
	onChange: (page: number, pageSize: number) => void
	cursorMode?: boolean
	/** 游标模式的下一页由响应游标决定，与独立统计总数无关。 */
	hasMore?: boolean
	/** 可选的总量文案；游标分页没有准确总数时可传“已加载 N 条” */
	totalText?: string
	showSizeChanger?: boolean
}

export function AppServerPagination({ disabled = false, page, pageSize, total, onChange, cursorMode = false, hasMore = false, totalText, showSizeChanger = true }: AppServerPaginationProps) {
	if (cursorMode) {
		const previousDisabled = disabled || page <= 1
		const nextDisabled = disabled || !hasMore
		return <nav className="list-pagination app-server-pagination cursor-pagination" aria-label="游标分页">
			<span className="cursor-pagination-total">{totalText ?? `共 ${total} 条`}</span>
			<div className="cursor-pagination-controls">
				<Button title="Previous Page" aria-label="上一页" className={`ant-pagination-prev${previousDisabled ? ' ant-pagination-disabled' : ''}`} disabled={previousDisabled} onClick={() => onChange(page - 1, pageSize)}>上一页</Button>
				<span className="cursor-pagination-page" aria-current="page">第 {page} 页</span>
				<Button title="Next Page" aria-label="下一页" className={`ant-pagination-next${nextDisabled ? ' ant-pagination-disabled' : ''}`} disabled={nextDisabled} onClick={() => onChange(page + 1, pageSize)}>下一页</Button>
			</div>
			{showSizeChanger && <Select aria-label="每页记录数" value={pageSize} disabled={disabled} options={[{ value: 20, label: '20 条/页' }, { value: 50, label: '50 条/页' }]} onChange={value => onChange(1, value)} />}
		</nav>
	}
	return <Pagination
		className="list-pagination app-server-pagination"
		current={page}
		disabled={disabled}
		pageSize={pageSize}
		pageSizeOptions={[20, 50]}
		showQuickJumper
		showSizeChanger={showSizeChanger}
		showTotal={() => totalText ?? `共 ${total} 条`}
		total={total}
		onChange={(nextPage, nextSize) => onChange(nextSize !== pageSize ? 1 : nextPage, nextSize)}
	/>
}

export function useServerPagination(prefix = '') {
	const [params, setParams] = useSearchParams()
	const pageKey = `${prefix}page`
	const sizeKey = `${prefix}limit`
	const page = positiveInteger(params.get(pageKey), 1)
	const parsedSize = positiveInteger(params.get(sizeKey), 20)
	const pageSize = parsedSize === 50 ? 50 : 20
	const update = useCallback((nextPage: number, nextSize: number) => {
		setParams((current) => {
			const next = new URLSearchParams(current)
			next.set(pageKey, String(Math.max(1, nextPage)))
			next.set(sizeKey, String(nextSize === 50 ? 50 : 20))
			next.delete('cursor')
			return next
		}, { replace: true })
	}, [pageKey, setParams, sizeKey])
	const reset = useCallback(() => update(1, pageSize), [pageSize, update])
	return useMemo(() => ({ page, pageSize, cursor: String((page - 1) * pageSize), update, reset }), [page, pageSize, reset, update])
}

function positiveInteger(value: string | null, fallback: number) {
	const parsed = Number(value)
	return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}
