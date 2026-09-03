import { Pagination } from 'antd'
import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

type AppServerPaginationProps = {
	page: number
	pageSize: number
	total: number
	onChange: (page: number, pageSize: number) => void
}

export function AppServerPagination({ page, pageSize, total, onChange }: AppServerPaginationProps) {
	return <Pagination
		className="list-pagination app-server-pagination"
		current={page}
		pageSize={pageSize}
		pageSizeOptions={[20, 50]}
		showQuickJumper
		showSizeChanger
		showTotal={(count) => `共 ${count} 条`}
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
