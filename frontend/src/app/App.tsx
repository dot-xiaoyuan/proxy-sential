import { RouterProvider } from 'react-router-dom'
import { App as AntApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClientProvider } from '@tanstack/react-query'

import { queryClient } from './queryClient'
import { router } from './router'
import { proxySentinelTheme } from './theme'

export function App() {
  return (
    <ConfigProvider
      locale={zhCN}
      theme={proxySentinelTheme}
    >
      <QueryClientProvider client={queryClient}>
        <AntApp>
          <RouterProvider router={router} />
        </AntApp>
      </QueryClientProvider>
    </ConfigProvider>
  )
}
