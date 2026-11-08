import { useQuery, useQueryClient } from '@tanstack/react-query'
import { request } from '../api/client'

export type PaginationQuery = string | URLSearchParams | object
export function paginationParams(query: PaginationQuery) {
  return typeof query === 'string' || query instanceof URLSearchParams ? new URLSearchParams(query) : new URLSearchParams(Object.entries(query).filter(([, value]) => value !== undefined && value !== null && value !== '').map(([key, value]) => [key, String(value)]))
}

export function usePaginationMetadata(path: string, query: PaginationQuery, enabled = true) {
  const scope = paginationParams(query)
  for (const key of ['cursor', 'offset', 'limit', 'page']) scope.delete(key)
  const key = scope.toString()
  return useQuery({ queryKey: ['pagination-metadata', path, key], queryFn: ({ signal }) => request<{ total: number; as_of: string; snapshot?: string }>(`${path}?${key}`, { signal }), enabled, retry: false })
}

export type CursorPagePosition = { page: number; limit: number; cursor: string; as_of?: string }

/** Locate one page boundary without downloading earlier pages or their evidence. */
export function useCursorPagePosition({ path, query, page, pageSize, enabled = true }: {
  path: string
  query: PaginationQuery
  page: number
  pageSize: number
  enabled?: boolean
}) {
  const client=useQueryClient()
  const scope = paginationParams(query)
  scope.delete('cursor')
  scope.delete('offset')
  scope.set('page', String(page))
  scope.set('limit', String(pageSize))
  const key = scope.toString()
  const position = useQuery({
    queryKey: ['cursor-page-position', path, key],
    queryFn: async ({ signal }) => {
      const result = await request<CursorPagePosition>(`${path}?${key}`, { signal })
      if (result.page !== page || result.limit !== pageSize || (page > 1 && !result.cursor)) {
        throw new Error('目标页定位结果无效，请刷新后重试')
      }
      return result
    },
    enabled: enabled && page > 1,
    retry: false,
    placeholderData: undefined,
  })
  return {
    ...position,
    invalidate:()=>client.invalidateQueries({queryKey:['cursor-page-position',path],refetchType:'none'}),
    cursor: page > 1 ? position.data?.cursor : undefined,
    ready: enabled && (page === 1 || Boolean(position.data && !position.isError && !position.isFetching)),
    isLocating: enabled && page > 1 && position.isFetching,
  }
}
