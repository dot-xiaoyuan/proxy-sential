import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { ApiError } from '../shared/api/client'
import { DiscoverySupplementaryPanels } from './DiscoverySupplementaryPanels'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../shared/api/client')>()
  return { ...actual, request }
})
vi.mock('../shared/api/queries', () => ({
  useSession: () => ({
    data: {
      user: { id: 'admin', name: '管理员' },
      role: 'admin',
      site_profile: 'passive_assets',
      permissions: ['identity:read', 'dpi:read'],
    },
  }),
}))

afterEach(() => request.mockReset())

it('renders terminal inventory and network activity asynchronously and isolates 504 timeouts', async () => {
  let trafficAttempts = 0
  request.mockImplementation(async (path: string) => {
    if (path.startsWith('/device-inventory/metadata')) {
      return {
        total: 4763,
        as_of: '2026-11-26T02:00:00Z',
        facets: { brands: ['Apple', 'Huawei', 'unknown'], os_families: ['Android', 'iOS'] },
      }
    }
    if (path.startsWith('/activity/overview')) {
      trafficAttempts++
      if (trafficAttempts === 1) throw new ApiError(504, 'timeout')
      return {
        event_count: 101657102,
        active_ip_count: 82265,
        access_object_count: 119168,
        statistics_as_of: '2026-11-26T02:05:00Z',
        event_type_counts: [
          { value: 'flow', count: 70446107 },
          { value: 'device', count: 8296439 },
        ],
      }
    }
    throw new Error(`unexpected path: ${path}`)
  })

  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <DiscoverySupplementaryPanels window="24h" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  const inventory = await screen.findByRole('region', { name: '终端台账' })
  await waitFor(() => expect(inventory).toHaveTextContent('4,763'))
  expect(inventory).toHaveTextContent('Apple')
  expect(inventory).not.toHaveTextContent('unknown')

  const traffic = await screen.findByRole('region', { name: '网络访问概况' })
  expect(traffic).toHaveTextContent('网络访问统计读取超时，不影响上方资产报表。')
  expect(traffic).not.toHaveTextContent('访问分析')

  fireEvent.click(traffic.querySelector('button')!)
  await waitFor(() => expect(traffic).toHaveTextContent('101,657,102'))
  expect(traffic).toHaveTextContent('设备观测')
  expect(traffic).toHaveTextContent('82,265')
})
