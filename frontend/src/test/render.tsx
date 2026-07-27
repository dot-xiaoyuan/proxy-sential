import type { ReactElement } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConfigProvider } from 'antd'

export function renderWithProviders(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })

  return {
    client,
    wrapper: ({ children }: { children: React.ReactNode }) => (
      <ConfigProvider>
        <QueryClientProvider client={client}>{children}</QueryClientProvider>
      </ConfigProvider>
    ),
    ui,
  }
}
