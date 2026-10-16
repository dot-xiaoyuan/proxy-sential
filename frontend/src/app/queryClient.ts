import { QueryClient, keepPreviousData } from '@tanstack/react-query'
import { queryKeys } from '../shared/api/queries'
import { setUnauthorizedHandler } from '../shared/api/client'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 60_000,
      gcTime: 30 * 60_000,
      placeholderData: keepPreviousData,
    },
  },
})

setUnauthorizedHandler(() => {
  queryClient.removeQueries({ predicate: query => query.queryKey[0] !== queryKeys.session[0] })
  void queryClient.invalidateQueries({ queryKey: queryKeys.session })
})
