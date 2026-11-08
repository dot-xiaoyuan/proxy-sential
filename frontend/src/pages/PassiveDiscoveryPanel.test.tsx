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
    if (path.startsWith('/discovery/devices/metadata?')) return Promise.resolve(path.includes('type=access_point')?{total:1,identified:1,candidate:0,conflict:0,expired:0,types:[{device_type:'access_point',count:1}],as_of:'2026-11-05T14:00:00Z',count_unit:'trusted_discovery_identity'}:{total:84,identified:42,candidate:35,conflict:4,expired:3,types:[{device_type:'router',count:30},{device_type:'access_point',count:12}],as_of:'2026-11-05T14:00:00Z',count_unit:'trusted_discovery_identity'})
    if (path === '/discovery/coverage') return Promise.resolve(coverage)
    if (path === '/discovery/statistics') return Promise.resolve({ items: [], pending_updates: 0 })
    if (path === '/discovery/types') return Promise.resolve({ items: [] })
    if (path.startsWith('/discovery/service-clues?')) return Promise.resolve({ items: {} })
    if (path.startsWith('/discovery/passive-signals?')) return Promise.resolve({ items: [] })
    if (path.startsWith('/discovery/history?')) return Promise.resolve({ items: [], has_more: false, next_cursor: '' })
    return Promise.resolve({ items: [] })
  })
}

function renderPanel(initialEntries = ["/"]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  client.setQueryData(['session'],{user:{id:'admin',name:'管理员'},role:'admin',permissions:['endpoints:write'],csrf_token:'csrf'})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={initialEntries}><PassiveDiscoveryPanel view="records" /></MemoryRouter></QueryClientProvider>)
}

function observedCalls() {
  return request.mock.calls.map(([path]) => String(path)).filter(path => path.startsWith('/discovery/observed-ports?'))
}

afterEach(() => { cleanup(); request.mockReset() })

it('shows the filtered discovery metadata total when the cursor page has no total', async () => {
  mockReads({items:{}}, {...device,mac:'02:00:00:20:40:01',recognition:{device_type:'access_point',confidence:0.9}}, undefined, false)
  renderPanel()
  const summary = await screen.findByLabelText('发现设备摘要')
  await waitFor(()=>expect(screen.getByLabelText('发现设备总览')).toHaveTextContent('发现设备数84'))
  expect(summary).toHaveTextContent('本页明确类型 1')
  expect((await screen.findAllByText('无线接入点'))[0]).toBeVisible()
  expect(screen.queryByText('待分类')).not.toBeInTheDocument()
})

it('shows complete discovery and confirmed type counts using the same metadata scope', async () => {
  mockReads()
  renderPanel()
  const overview=await screen.findByLabelText('发现设备总览')
  await waitFor(()=>expect(overview).toHaveTextContent('已识别具体类型42'))
  expect(overview).toHaveTextContent('发现设备数84')
  expect(overview).toHaveTextContent('具体类型（合计 42）')
  expect(overview).toHaveTextContent('待核实35')
  expect(overview).toHaveTextContent('类型冲突4')
  expect(overview).toHaveTextContent('证据过期3')
  expect(overview).toHaveTextContent('路由器 30')
  expect(overview).toHaveTextContent('无线接入点 12')
})

it('keeps the type overview visible when the statistics request fails', async () => {
  mockReads()
  const normalRead = request.getMockImplementation()!
  request.mockImplementation((path: string) => path.startsWith('/discovery/devices/metadata?')
    ? Promise.reject(new Error('statistics timeout'))
    : normalRead(path))
  renderPanel()
  const overview = screen.getByLabelText('发现设备总览')
  expect(overview).toBeVisible()
  await waitFor(() => expect(overview).toHaveTextContent('统计读取失败'))
  expect(overview).toHaveTextContent('发现设备数')
  expect(overview).toHaveTextContent('已识别具体类型')
})

it('renders endpoint types that are outside the IoT type catalogue', async () => {
  mockReads({items:{}}, {...device,device_type:'router'})
  renderPanel()
  expect(await screen.findByText('路由器')).toBeVisible()
  expect(screen.queryByText('待分类')).not.toBeInTheDocument()
})

it('keeps a computer hostname out of confirmed device type and OS fields', async () => {
  mockReads({items:{}}, {...device,name:'DESKTOP-204',mac:'02:00:00:20:40:01'})
  renderPanel()
  expect(await screen.findByText('电脑名称线索')).toBeVisible()
  expect(screen.queryByText(/办公终端|Windows/)).not.toBeInTheDocument()
  expect(screen.getByLabelText('发现设备摘要')).toHaveTextContent('本页明确类型 0')
  fireEvent.click(screen.getByRole('button',{name:'查看详情'}))
  expect(await screen.findByText(/名称可自行设置，不能据此确认设备类型、操作系统或用途/)).toBeInTheDocument()
  expect(screen.getByText(/仅有地址活动证据/)).toBeInTheDocument()
})

it('does not label a Huawei AP hostname as Android or a mobile device', async () => {
  mockReads({items:{}}, {...device,name:'Huawei-AP',mac:'02:00:00:20:40:01'})
  renderPanel()
  await screen.findByText('Huawei-AP')
  expect(screen.queryByText(/Android|移动终端|移动设备名称线索/)).not.toBeInTheDocument()
})

it('counts recent observations beyond the configured five-minute discovery holdback', async () => {
  mockReads({items:{}}, {...device,last_seen:new Date(Date.now()-7*60_000).toISOString()})
  renderPanel()
  const summary=await screen.findByLabelText('发现设备摘要')
  await waitFor(()=>expect(summary).toHaveTextContent('本页近15分钟观测 1'))
})

it('keeps type filters visible and collection diagnostics behind a disclosure', async () => {
  mockReads();renderPanel()
  expect(screen.getByRole('combobox',{name:'设备类型'})).toBeVisible()
  expect(screen.getByText('采集与识别状态').closest('details')).not.toHaveAttribute('open')
  expect(screen.getByRole('button',{name:'新增登记'})).toBeVisible()
})

it('starts an independent registration without requiring a mirrored device', async()=>{
  mockReads();renderPanel()
  fireEvent.click(screen.getByRole('button',{name:'新增登记'}))
  fireEvent.change(screen.getByRole('textbox',{name:'MAC 地址'}),{target:{value:'00:11:22:33:44:55'}})
  fireEvent.change(screen.getByRole('textbox',{name:'资产编号'}),{target:{value:'ASSET-204'}})
  fireEvent.click(screen.getByRole('button',{name:'保存登记'}))
  await waitFor(()=>expect(request.mock.calls.some(([path])=>String(path).includes('/endpoints/mac%3A00%3A11%3A22%3A33%3A44%3A55/registration'))).toBe(true))
})

it('registers a MAC discovery as a local fact without treating its observed IP as registered', async () => {
  mockReads({items:{}}, {...device, mac:'02:00:00:20:40:01', name:'镜像名称'})
  renderPanel()
  await screen.findAllByText('192.0.2.10')
  fireEvent.click(screen.getByRole('button',{name:'查看详情'}))
  fireEvent.click(await screen.findByRole('button',{name:'登记此设备'}))
  expect(await screen.findByText(/登记 IP 是资料字段/)).toBeInTheDocument()
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
  await screen.findAllByText('192.0.2.10')
  expect(observedCalls()).toHaveLength(0)

  fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
  await waitFor(() => expect(observedCalls()).toHaveLength(1))
  const targets = new URLSearchParams(observedCalls()[0].split('?')[1]).get('targets')
  expect(targets).toBe('sensor-a|192.0.2.10')
  expect(await screen.findByText('见 TCP SYN-ACK 443')).toBeInTheDocument()
  expect(screen.getByText(/近 2 小时目标端口线索/)).toBeInTheDocument()
})

it('shows a detail error when the selected IP port read fails', async () => {
  mockReads(new Error('read failed'))
  renderPanel()
  await screen.findAllByText('192.0.2.10')
  expect(screen.queryByText('读取目标端口线索失败')).not.toBeInTheDocument()

  fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
  expect(await screen.findByText('读取目标端口线索失败')).toBeInTheDocument()
  expect(observedCalls()).toHaveLength(1)
})

it('does not query a historical address when the device has no current address', async () => {
  mockReads({ items: {} }, { ...device, current_addresses: [] })
  renderPanel()
  await screen.findByText('最后地址 192.0.2.12')
  fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
  expect(observedCalls()).toHaveLength(0)
  expect(screen.queryByText('正在读取当前 IP 近 2 小时目标端口线索')).not.toBeInTheDocument()
})

it('distinguishes an empty current IP port read from a failed read', async () => {
  mockReads({ items: {} })
  renderPanel()
  await screen.findAllByText('192.0.2.10')
  fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
  expect(await screen.findByText('当前 IP 近 2 小时的镜像端口聚合中无匹配记录')).toBeInTheDocument()
  expect(screen.queryByText('读取目标端口线索失败')).not.toBeInTheDocument()
})

it('switches shortcut types atomically and clears the dumb capability filter', async()=>{
  mockReads();renderPanel(['/?discovery_capability=dumb'])
  fireEvent.click(screen.getByRole('button',{name:'无线 AP'}))
  await waitFor(()=>{
    const paths=request.mock.calls.map(([p])=>String(p)).filter(p=>p.startsWith('/discovery/devices?'))
    const query=new URLSearchParams(paths.at(-1)!.split('?')[1])
    expect(query.get('type')).toBe('access_point')
    expect(query.has('capability')).toBe(false)
  })
})

it('does not count expired or conflicting recognition as an explicit current type', async()=>{
  mockReads({items:{}},{...device,classification_status:'expired',recognition:{device_type:'access_point',confidence:.95}})
  renderPanel()
  await screen.findAllByText('192.0.2.10')
  expect(screen.getByLabelText('发现设备摘要')).toHaveTextContent('本页明确类型 0')
})

it('preserves owner account and identity merge relations when editing the registration ledger',async()=>{
  mockReads()
  const read=request.getMockImplementation()!
  const row={endpoint_id:'mac:00:11:22:33:44:55',primary_mac:'00:11:22:33:44:55',registration_status:'registered',owner_account:'asset-owner',owner_name:'',owner_department:'实验室',asset_tag:'',ownership_class:'school_asset',registration_note:'核验记录',registration_details:{name:'实验室打印机',device_type:'printer',registered_ip:'192.0.2.20'},merge_status:'merged',merged_into_endpoint_id:'mac:00:11:22:33:44:66',split_from_endpoint_id:'',registration_updated_at:'2026-11-05T12:00:00Z'}
  request.mockImplementation((path:string,options?:unknown)=>path.startsWith('/endpoints/registrations/metadata')?Promise.resolve({total:1}):path.startsWith('/endpoints/registrations?')?Promise.resolve({items:[row],has_more:false}):read(path,options))
  renderPanel(['/?discovery_view=registrations'])
  fireEvent.click(await screen.findByRole('button',{name:'编辑登记'}))
  expect(screen.getByRole('textbox',{name:'责任人账号'})).toHaveValue('asset-owner')
  fireEvent.change(screen.getByRole('textbox',{name:'部门'}),{target:{value:'信息中心'}})
  fireEvent.click(screen.getByRole('button',{name:'保存登记'}))
  await waitFor(()=>{
    const call=request.mock.calls.find(([path,options])=>String(path).includes('/registration')&&(options as {method?:string})?.method==='POST')
    expect(call).toBeDefined()
    const payload=JSON.parse((call![1] as {body:string}).body)
    expect(payload).toMatchObject({owner_account:'asset-owner',owner_department:'信息中心',merge_status:'merged',merged_into_endpoint_id:row.merged_into_endpoint_id,registration_details:row.registration_details})
  })
})

it('removes previous rows when a filter changes after one discovery key was split into evidence groups',async()=>{
  const errorLog=vi.spyOn(console,'error').mockImplementation(()=>{})
  mockReads()
  const read=request.getMockImplementation()!
  const splitRows=['one','two','three'].map((name,index)=>({...device,id:'shared-discovery-key',name:`打印机 ${name}`,device_type:'printer',mac:'00:11:22:33:44:55',observations:[{id:`evidence-${index}`,origin:'dns_sd',observed_at:device.last_seen}]}))
  request.mockImplementation((path:string,options?:unknown)=>path.startsWith('/discovery/devices?')?Promise.resolve({items:path.includes('type=access_point')?[{...device,id:'ap-key',name:'筛选后的 AP',device_type:'access_point',observations:[{id:'ap-evidence',origin:'arp',observed_at:device.last_seen}]}]:splitRows,has_more:false}):read(path,options))
  renderPanel()
  await screen.findByRole('button',{name:'打印机 three'})
  fireEvent.click(screen.getByRole('button',{name:'无线 AP'}))
  await screen.findByRole('button',{name:'筛选后的 AP'})
  expect(screen.queryByRole('button',{name:'打印机 one'})).not.toBeInTheDocument()
  expect(screen.queryByRole('button',{name:'打印机 two'})).not.toBeInTheDocument()
  expect(screen.queryByRole('button',{name:'打印机 three'})).not.toBeInTheDocument()
  const duplicateKeys=errorLog.mock.calls.filter(args=>args.map(String).join(' ').includes('same key'))
  errorLog.mockRestore()
  expect(duplicateKeys).toEqual([])
})

it('keeps the loaded list and offers retry when filtered statistics fail',async()=>{
  mockReads()
  const read=request.getMockImplementation()!
  request.mockImplementation((path:string,options?:unknown)=>path.startsWith('/discovery/devices/metadata?')?Promise.reject(new Error('统计暂时不可用')):read(path,options))
  renderPanel()
  await screen.findAllByText('192.0.2.10')
  expect(await screen.findByText('读取发现数量失败')).toBeVisible()
  expect(screen.getByRole('button',{name:'重试统计'})).toBeVisible()
  expect(screen.queryByText('终端身份总数')).not.toBeInTheDocument()
})
