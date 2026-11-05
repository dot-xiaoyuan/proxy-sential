import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { PassiveDiscoveryPanel } from './PassiveDiscoveryPanel'

const request = vi.hoisted(() => vi.fn())
vi.mock('../shared/api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../shared/api/client')>()
  return { ...actual, request }
})

const device = {
  id: 'device-1',
  sensor_id: 'sensor-a',
  primary_ip: '192.0.2.10',
  current_addresses: ['192.0.2.10', '192.0.2.11'],
  last_observed_ip: '192.0.2.12',
  last_seen: '2026-11-01T12:00:00Z',
  classification_status: 'candidate',
  current: true,
  observations: [],
  protocols: ['arp'],
  capabilities: [],
}

function mockReads(observedPortResult: unknown = {
  items: {
    'sensor-a|192.0.2.10': [{
      sensor_id: 'sensor-a', src_ip: '192.0.2.10', proto: 'tcp', dst_port: 443,
      connection_outcome: 'syn_ack_observed', last_seen: '2026-11-01T12:00:00Z', evidence_id: 'flow-443',
    }],
  },
}, deviceRow: typeof device & {mac?:string;name?:string;device_type?:string;recognition?:{device_type:string;confidence:number}} = device, coverage = { enabled: true, items: [] as Array<{protocol:string;enabled:boolean;message_source_epoch?:string}> }, includeListTotal = true) {
  request.mockImplementation((path: string) => {
    if (path.startsWith('/discovery/observed-ports?')) {
      return observedPortResult instanceof Error ? Promise.reject(observedPortResult) : Promise.resolve(observedPortResult)
    }
    if (path.startsWith('/discovery/devices?')) return Promise.resolve({ items: [deviceRow], ...(includeListTotal?{total:1}:{}), has_more: false })
    if (path === '/device-inventory/metadata?view=history') return Promise.resolve({total:1458,as_of:'2026-11-05T14:00:00Z'})
    if (path === '/discovery/coverage') return Promise.resolve(coverage)
    if (path === '/discovery/statistics') return Promise.resolve({ items: [], pending_updates: 0 })
    if (path === '/discovery/types') return Promise.resolve({ items: [] })
    if (path.startsWith('/discovery/service-clues?')) return Promise.resolve({ items: {} })
    if (path.startsWith('/discovery/passive-signals?')) return Promise.resolve({ items: [] })
    if (path.startsWith('/discovery/history?')) return Promise.resolve({ items: [], has_more: false, next_cursor: '' })
    return Promise.resolve({ items: [] })
  })
}

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  client.setQueryData(['session'],{user:{id:'admin',name:'管理员'},role:'admin',permissions:['endpoints:write'],csrf_token:'csrf'})
  render(<QueryClientProvider client={client}><MemoryRouter><PassiveDiscoveryPanel view="records" /></MemoryRouter></QueryClientProvider>)
}

function observedCalls() {
  return request.mock.calls.map(([path]) => String(path)).filter(path => path.startsWith('/discovery/observed-ports?'))
}

afterEach(() => { cleanup(); request.mockReset() })

it('shows the independent identity total and recognized type when the discovery cursor page has no total', async () => {
  mockReads({items:{}}, {...device,mac:'02:00:00:20:40:01',recognition:{device_type:'access_point',confidence:0.9}}, undefined, false)
  renderPanel()
  const summary = await screen.findByLabelText('发现设备摘要')
  await waitFor(()=>expect(summary).toHaveTextContent('终端身份总数1458'))
  expect(summary).toHaveTextContent('本页明确类型1')
  expect(await screen.findByText('无线接入点')).toBeVisible()
  expect(screen.queryByText('待分类')).not.toBeInTheDocument()
})

it('renders endpoint types that are outside the IoT type catalogue', async () => {
  mockReads({items:{}}, {...device,device_type:'router'})
  renderPanel()
  expect(await screen.findByText('路由器')).toBeVisible()
  expect(screen.queryByText('待分类')).not.toBeInTheDocument()
})

it('separates mirrored protocols from the DHCP message source', async () => {
  mockReads(undefined, device, { enabled: true, items: [
    { protocol: 'arp', enabled: true },
    { protocol: 'dns_sd', enabled: true },
    { protocol: 'ssdp', enabled: true },
    { protocol: 'lldp', enabled: true },
    { protocol: 'dhcp', enabled: false, message_source_epoch: 'dhcp-message-fresh' },
  ] })
  renderPanel()
  const heading = await screen.findByText('镜像采集协议')
  const summary = heading.closest('.discovery-protocol-summary')
  expect(summary).toHaveTextContent('ARP')
  expect(summary).toHaveTextContent('DNS-SD')
  expect(summary).toHaveTextContent('SSDP')
  expect(summary).toHaveTextContent('LLDP')
  expect(summary).toHaveTextContent('DHCP 逐消息源已登记')
  expect(summary?.querySelectorAll('.ant-tag')).toHaveLength(4)
})

it('registers a MAC discovery as a local fact without treating its observed IP as registered', async () => {
  mockReads({items:{}}, {...device, mac:'02:00:00:20:40:01', name:'镜像名称'})
  renderPanel()
  await screen.findByText('192.0.2.10')
  fireEvent.click(screen.getByRole('button',{name:'查看证据'}))
  fireEvent.click(await screen.findByRole('button',{name:'登记此设备'}))
  expect(screen.getByText(/登记 IP 是资料字段/)).toBeInTheDocument()
  fireEvent.change(screen.getByRole('textbox',{name:'资产编号'}),{target:{value:'204-ASSET-1'}})
  fireEvent.click(screen.getByRole('button',{name:'保存登记'}))
  await waitFor(()=>expect(request.mock.calls.some(([path])=>String(path).includes('/endpoints/mac%3A02%3A00%3A00%3A20%3A40%3A01/registration'))).toBe(true))
  const [,options]=request.mock.calls.find(([path])=>String(path).includes('/endpoints/mac%3A02%3A00%3A00%3A20%3A40%3A01/registration'))!
  const body=JSON.parse(options.body)
  expect(body.registration_details.name).toBe('镜像名称')
  expect(body.registration_details.registered_ip).toBeUndefined()
  expect(body.asset_tag).toBe('204-ASSET-1')
})

it('loads one current IP port clue only when its evidence detail opens', async () => {
  mockReads()
  renderPanel()
  await screen.findByText('192.0.2.10')
  expect(observedCalls()).toHaveLength(0)

  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  await waitFor(() => expect(observedCalls()).toHaveLength(1))
  const targets = new URLSearchParams(observedCalls()[0].split('?')[1]).get('targets')
  expect(targets).toBe('sensor-a|192.0.2.10')
  expect(await screen.findByText('见 TCP SYN-ACK 443')).toBeInTheDocument()
  expect(screen.getByText(/近 2 小时目标端口线索/)).toBeInTheDocument()
})

it('shows a detail error when the selected IP port read fails', async () => {
  mockReads(new Error('read failed'))
  renderPanel()
  await screen.findByText('192.0.2.10')
  expect(screen.queryByText('读取目标端口线索失败')).not.toBeInTheDocument()

  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  expect(await screen.findByText('读取目标端口线索失败')).toBeInTheDocument()
  expect(observedCalls()).toHaveLength(1)
})

it('does not query a historical address when the device has no current address', async () => {
  mockReads({ items: {} }, { ...device, current_addresses: [] })
  renderPanel()
  await screen.findByText('最后观测地址 · 192.0.2.12')
  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  expect(observedCalls()).toHaveLength(0)
  expect(screen.queryByText('正在读取当前 IP 近 2 小时目标端口线索')).not.toBeInTheDocument()
})

it('distinguishes an empty current IP port read from a failed read', async () => {
  mockReads({ items: {} })
  renderPanel()
  await screen.findByText('192.0.2.10')
  fireEvent.click(screen.getByRole('button', { name: '查看证据' }))
  expect(await screen.findByText('当前 IP 近 2 小时的镜像端口聚合中无匹配记录')).toBeInTheDocument()
  expect(screen.queryByText('读取目标端口线索失败')).not.toBeInTheDocument()
})
