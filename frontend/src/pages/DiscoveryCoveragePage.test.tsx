import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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
  expect(screen.queryByLabelText('镜像可见标识统计')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('tab',{name:'镜像与配对'}))
  expect(screen.getByText('镜像明细与台账对照')).toBeVisible()
  expect(screen.queryByLabelText('镜像可见标识统计')).not.toBeInTheDocument()
  fireEvent.click(screen.getByText('镜像明细与台账对照'))
  expect(await screen.findByLabelText('镜像可见标识统计')).toBeVisible()
  fireEvent.click(screen.getByRole('tab',{name:'网段与 VLAN'}))
  await waitFor(() => expect(request).toHaveBeenCalledWith('/discovery/devices/metadata?mode=passive&identity_scope=devices&window=168h', expect.anything()))
})

it('shows a metadata error, retries both overview queries and retains the last successful composition', async () => {
  let attempts = 0
  request.mockImplementation(async (path: string) => {
    if (path.includes('/metadata?')) {
      attempts++
      if (attempts !== 2) throw new Error('metadata unavailable')
      return {types:[{device_type:'printer',count:7}]}
    }
    return {as_of:'2026-11-15T11:00:00Z',window:'24h',ipv4:5,ipv6:0}
  })
  const client = new QueryClient({defaultOptions:{queries:{retry:false}}})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/devices/coverage']}><DiscoveryCoveragePage/></MemoryRouter></QueryClientProvider>)

  expect(await screen.findByRole('alert')).toHaveTextContent('类型构成读取失败。可用顶部的刷新按钮重试。')
  expect(screen.queryByText('正在读取类型构成…')).not.toBeInTheDocument()
  expect(screen.getByRole('region',{name:'发现与识别'})).toBeVisible()
  fireEvent.click(screen.getByRole('button',{name:'刷新'}))
  expect(await screen.findByRole('region',{name:'哑终端'})).toHaveTextContent('打印机')
  expect(screen.getByRole('region',{name:'哑终端'})).toHaveTextContent('7')
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()

  fireEvent.click(screen.getByRole('button',{name:'刷新'}))
  expect(await screen.findByRole('alert')).toHaveTextContent('类型构成读取失败。当前显示上次成功读取的数据。')
  expect(screen.getByRole('region',{name:'哑终端'})).toHaveTextContent('7')
  expect(attempts).toBe(3)
  expect(request.mock.calls.filter(([path])=>path.includes('/coverage-report?'))).toHaveLength(3)
})
