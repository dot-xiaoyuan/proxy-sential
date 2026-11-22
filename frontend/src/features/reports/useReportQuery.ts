import { useQuery } from '@tanstack/react-query'

export function useReportQuery<T>(key: string, read: (signal: AbortSignal) => Promise<T>, enabled = true) {
  return useQuery({
    queryKey: ['reports', key],
    queryFn: ({ signal }) => read(signal),
    enabled,
    staleTime: 30_000,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
}
