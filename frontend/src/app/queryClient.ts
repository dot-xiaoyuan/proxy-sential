import { QueryClient, keepPreviousData } from '@tanstack/react-query'
import { queryKeys } from '../shared/api/queries'
import { ApiError, setUnauthorizedHandler } from '../shared/api/client'

// 对客户端错误、超时与服务过载禁止自动重试，避免机械盘高负载场景下并发雪崩。
const NON_RETRYABLE_STATUSES = new Set([400, 401, 403, 404, 408, 409, 422, 429, 503, 504])

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      refetchIntervalInBackground: false,
      retry: (failureCount, error) => {
        if (failureCount >= 1) return false
        if (error instanceof ApiError && NON_RETRYABLE_STATUSES.has(error.status)) {
          return false
        }
        return true
      },
      staleTime: 60_000,
      gcTime: 30 * 60_000,
      placeholderData: keepPreviousData,
    },
  },
})

setUnauthorizedHandler(() => {
  queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== queryKeys.session[0] })
  void queryClient.invalidateQueries({ queryKey: queryKeys.session })
})
