import { QueryClient, keepPreviousData } from '@tanstack/react-query'

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
