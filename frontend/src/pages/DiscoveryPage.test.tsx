import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DiscoveryPage } from './DiscoveryPage'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/queries', () => ({ useSession: () => ({ data: undefined }) }))
vi.mock('../shared/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../shared/api/client')>()
  return { ...actual, request, api: { ...actual.api, routerObservations: () => Promise.resolve({ items: [], total: 0 }) } }
})

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter><DiscoveryPage /></MemoryRouter></QueryClientProvider>)
}

afterEach(() => { cleanup(); request.mockReset() })

describe('网络设备发现', () => {
  // 空结果历史上被后端序列化为 null，前端直接 .map 会让整页崩到错误边界。
  it('接口 items 为 null 时按空列表渲染且不崩溃', async () => {
    request.mockImplementation((path: string) => {
      if (String(path).startsWith('/discovery/devices')) return Promise.resolve({ items: null, total: 0 })
      return Promise.resolve({ items: [], total: 0 })
    })
    setup()
    fireEvent.click(await screen.findByText('发现记录'))
    await waitFor(() => expect(screen.getAllByText('没有发现记录').length).toBeGreaterThan(0))
  })

  it('接口 items 为正常数组时渲染发现记录', async () => {
    request.mockImplementation((path: string) => {
      if (String(path).startsWith('/discovery/devices')) {
        return Promise.resolve({
          items: [{
            id: 'device-1',
            primary_ip: '198.18.90.8', category: 'printer', capabilities: ['printing'], protocols: ['dns_sd'], confidence: 'strong', last_seen: '2026-10-12T00:00:00Z', current: true,
            observations: [{ id: 'obs-1', ip: '198.18.90.8', mac: '02:00:00:00:90:08', name: 'office-printer.local', origin: 'dns_sd', observed_at: '2026-10-12T00:00:00Z', valid_until: '2026-10-13T00:00:00Z', explanation: '服务能力公告', device_type: 'printer', capabilities: ['printing'] }],
            association: '',
          }],
          total: 1,
        })
      }
      return Promise.resolve({ items: [], total: 0 })
    })
    setup()
    fireEvent.click(await screen.findByText('发现记录'))
    await waitFor(() => expect(screen.getAllByText('198.18.90.8').length).toBeGreaterThan(0))
    expect(screen.getAllByText('打印').length).toBeGreaterThan(0)
  })
})
