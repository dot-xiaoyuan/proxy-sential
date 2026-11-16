import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { DiscoveryCoveragePage } from './DiscoveryCoveragePage'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../shared/api/client')>()
  return { ...actual, request }
})
vi.mock('./CensusPanel', () => ({CensusPanel: () => <section aria-label="镜像可见标识统计"/>}))

afterEach(() => request.mockReset())

it('loads the report as an independent page using the selected window', async () => {
  request.mockResolvedValue({
    as_of:'2026-11-15T11:00:00Z', identity_as_of:'2026-11-15T10:38:00Z', window:'168h',
    subnet24:388, ipv4:2830, ipv6:1848, mac:2972, scoped_mac:5891,
    ip_mac_pairs:5993, identified:328, dumb_terminals:75, identity_total:6304,
  })
  const client = new QueryClient({defaultOptions:{queries:{retry:false}}})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/devices/coverage?window=168h']}><DiscoveryCoveragePage/></MemoryRouter></QueryClientProvider>)
  expect(screen.getByRole('heading', {name:'设备发现覆盖报表'})).toBeVisible()
  await waitFor(() => expect(request).toHaveBeenCalledWith('/discovery/devices/coverage-report?window=168h', expect.anything()))
  await waitFor(() => expect(screen.getByLabelText('设备发现覆盖报表')).toHaveTextContent('2,830'))
  expect(screen.getByLabelText('镜像可见标识统计')).not.toBeVisible()
  screen.getByText('查看原因分析与镜像明细').click()
  expect(screen.getByLabelText('镜像可见标识统计')).toBeVisible()
})
