import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
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
}, deviceRow: typeof device & {hardware_type?:string;hardware_type_status?:string;hardware_model?:string;hardware_model_status?:string;type_evidence_at?:string;type_rule_version?:string;activity_status?:string;type_sources?:Array<{source:string;rule_id:string;rule_version:string;evidence_id:string;observed_at:string}>;mac?:string;name?:string;device_type?:string;last_product_type?:string;last_product_at?:string;endpoint_id?:string;review_reason?:string;review_observed_at?:string;recognition?:{device_type?:string;confidence?:number;os_family?:string;os_family_confidence?:number;rule_version?:string;source?:string;evidence?:string[];brand?:string;model?:string;brand_inference_status?:string;brand_inference_brand?:string;brand_inference_confidence?:number}} = device, coverage = { enabled: true, items: [] as Array<{protocol:string;enabled:boolean;message_source_epoch?:string}> }, includeListTotal = true) {
  request.mockImplementation((path: string) => {
    if (path.startsWith('/discovery/observed-ports?')) {
      return observedPortResult instanceof Error ? Promise.reject(observedPortResult) : Promise.resolve(observedPortResult)
    }
    if (path.startsWith('/discovery/devices?')) return Promise.resolve({ items: [deviceRow], ...(includeListTotal?{total:1}:{}), has_more: false, freshness: { status: 'ready', lag_seconds: 125, result_version: 1 } })
    if (path.startsWith('/discovery/devices/metadata?')) return Promise.resolve(path.includes('type=access_point')?{total:1,identified:1,candidate:0,conflict:0,expired:0,types:[{device_type:'access_point',count:1}],as_of:'2026-11-05T14:00:00Z',count_unit:'trusted_discovery_identity'}:{total:84,identified:42,candidate:35,conflict:4,expired:3,types:[{device_type:'router',count:30},{device_type:'access_point',count:12}],as_of:'2026-11-05T14:00:00Z',count_unit:'trusted_discovery_identity'})
    if (path.startsWith('/discovery/trends')) return Promise.resolve({ days: [{ date: '2026-11-06', new: 2, typed: 1 }, { date: '2026-11-07', new: 4, typed: 3 }], top_types: [{ device_type: 'mobile', count: 3 }, { device_type: 'camera', count: 1 }], as_of: '2026-11-07T00:00:00Z', window_days: 7 })
    if (path === '/discovery/types') return Promise.resolve({ version: 'test', items: [{ id: 'printer', label: '打印机', category: 'printer' }, { id: 'camera', label: '摄像头', category: 'camera' }] })
    if (path === '/device-recognition/summary') return Promise.resolve({ total_endpoints: 121, coverage: { device_type: { known: 15, rate: 15 / 121 }, brand: { known: 1, rate: 1 / 121 }, model: { known: 1, rate: 1 / 121 }, os_family: { known: 15, rate: 15 / 121 } }, mac_attribution_rate: 0.5, event_attribution_rate: 0, top_brands: [{ brand: '华为', count: 3 }], top_type_brands: [{ device_type: 'camera', brand: 'Hikvision', count: 2 }], untyped_reasons: [{ reason: 'Apple 系统线索', count: 2 }], top_models: [{ model: 'LaserJet Pro MFP', brand: 'HP', count: 1 }], top_os: [{ os: 'Apple OS', count: 2 }, { os: 'Windows', count: 1 }] })
    if (path.startsWith('/device-inventory/')) return Promise.resolve({ profile: { recognition: { source_matches: [{ source_id: 'satori', rule_id: 'fixture-dhcp-options', version: 'fixture', name: 'Hikvision DHCP options', strength: 'self_report', fields: ['dhcp_options'], observed: { dhcp_options: '53,61,12,81' } }] } } })
    if (path === '/discovery/coverage') return Promise.resolve(coverage)
    if (path === '/discovery/statistics') return Promise.resolve({ items: [], pending_updates: 0 })
    if (path.startsWith('/discovery/census/summary?')) return Promise.resolve({ metric_version:'passive-census/v1',scope:{sensor_id:'sensor-a'},window:'24h0m0s',status:'initializing',failed_batches:0,observed_ips:0,observed_ipv4:0,observed_ipv6:0,observed_macs:0,random_macs:0,incomplete_scope:0,active_bindings:0,identified_terminals:0,terminal_candidates:0,terminal_conflicts:0,terminal_expired:0,manually_verified:0,types:[] })
    if (path.startsWith('/discovery/census/identifiers?')) return Promise.resolve({items:[],next_cursor:'',has_more:false})
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

it('uses the same review reason for the list and count', async () => {
  mockReads({items:{}}, {...device,classification_status:'conflict',review_reason:'conflict',review_observed_at:'2026-11-10T08:00:00Z'})
  renderPanel(['/?discovery_review_reason=conflict'])
  await waitFor(() => {
    for (const endpoint of ['/discovery/devices?', '/discovery/devices/metadata?']) {
      expect(request.mock.calls.some(([path]) => String(path).startsWith(endpoint) && String(path).includes('review_reason=conflict'))).toBe(true)
    }
  })
  expect(await screen.findByText(/类型证据冲突 ·/)).toBeInTheDocument()
})

it('shows the filtered discovery metadata total when the cursor page has no total', async () => {
  mockReads({items:{}}, {...device,classification_status:'identified',device_type:'access_point',mac:'02:00:00:20:40:01',recognition:{device_type:'access_point',confidence:0.9}}, undefined, false)
  renderPanel()
  const summary = await screen.findByLabelText('发现设备摘要')
  const overview = await screen.findByLabelText('发现设备总览')
  await waitFor(()=>expect(overview).toHaveTextContent('共 84 个设备'))
  expect(summary).toHaveTextContent('本页明确类型 1')
  expect((await screen.findAllByText('无线接入点'))[0]).toBeVisible()
  expect(screen.queryByText('待分类')).not.toBeInTheDocument()
})

it('shows a loading status while the first page loads and a search status as soon as a term is typed', async () => {
  mockReads()
  let resolveDevices: (value: unknown) => void = () => {}
  const normalRead = request.getMockImplementation()!
  request.mockImplementation((path: string) => path.startsWith('/discovery/devices?')
    ? new Promise(resolve => { resolveDevices = resolve })
    : normalRead(path))
  renderPanel()
  expect(await screen.findByRole('status')).toHaveTextContent('正在加载')
  resolveDevices({ items: [device], has_more: false })
  await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())

  fireEvent.change(screen.getByLabelText('搜索 IP、MAC、名称或型号'), { target: { value: 'router' } })
  expect(screen.getByRole('status')).toHaveTextContent('正在搜索')
})

it('shows complete discovery and confirmed type counts using the same metadata scope', async () => {
  mockReads()
  renderPanel()
  const overview=await screen.findByLabelText('发现设备总览')
  await waitFor(()=>expect(overview).toHaveTextContent('已识别类型 42'))
  expect(overview).toHaveTextContent('共 84 个设备')
  expect(overview).toHaveTextContent('已识别类型（合计 42）')
  expect(overview).toHaveTextContent('待核实 35')
  expect(overview).toHaveTextContent('类型冲突 4')
  expect(overview).toHaveTextContent('证据过期 3')
  expect(overview).toHaveTextContent('数据延迟 2 分钟')
  expect(overview).toHaveTextContent('路由器 30')
  expect(overview).toHaveTextContent('无线接入点 12')
  const routerTypeButton = screen.getAllByRole('button').find(button => button.textContent === '路由器 30')
  expect(routerTypeButton).toBeTruthy()
  fireEvent.click(routerTypeButton!)
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).includes('type=router') && String(path).includes('state=identified'))).toBe(true))
})

it('keeps the type overview visible when the statistics request fails', async () => {
  mockReads()
  const normalRead = request.getMockImplementation()!
  request.mockImplementation((path: string) => path.startsWith('/discovery/devices/metadata?')
    ? Promise.reject(new Error('statistics timeout'))
    : normalRead(path))
  renderPanel()
  const overview = await screen.findByLabelText('发现设备总览')
  await waitFor(() => expect(overview).toHaveTextContent('统计读取失败'))
  expect(overview).toHaveTextContent('共 ')
  expect(overview).toHaveTextContent('已识别类型')
})

it('keeps the last successful list and offers a retry when refresh fails', async () => {
  mockReads()
  const normalRead = request.getMockImplementation()!
  let listReads = 0
  request.mockImplementation((path: string) => path.startsWith('/discovery/devices?') && ++listReads > 1
    ? Promise.reject(new Error('读取发现结果失败'))
    : normalRead(path))
  renderPanel()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('button',{name:'刷新数据'}))
  await waitFor(() => expect(screen.getByText('读取发现设备失败')).toBeInTheDocument())
  expect(screen.getByText(/当前展示上次成功读取的结果/)).toBeInTheDocument()
  expect(screen.getByRole('button',{name:'重试列表'})).toBeInTheDocument()
  expect(screen.getByRole('table')).toBeInTheDocument()
})

it('renders endpoint types that are outside the IoT type catalogue', async () => {
  mockReads({items:{}}, {...device,device_type:'router'})
  renderPanel()
  await waitFor(()=>expect(screen.getByRole('table')).toHaveTextContent('路由器 · 类型线索'))
  expect(screen.queryByText('待分类')).not.toBeInTheDocument()
})

it('keeps an expired product self-report visible without counting it as an effective type', async () => {
  mockReads({items:{}}, {...device, device_type:'camera', last_product_type:'printer', last_product_at:'2026-11-01T09:00:00Z'})
  renderPanel()
  const table = await screen.findByRole('table')
  await waitFor(()=>expect(table).toHaveTextContent('打印机 · 历史型号自报'))
  expect(table).not.toHaveTextContent('摄像头 · 类型线索')
  expect(screen.getByLabelText('发现设备摘要')).toHaveTextContent('本页明确类型 0')
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

it('shows a hostname-only network role as a clue and does not show a weak OS conclusion', async () => {
  mockReads({items:{}}, {...device, mac:'18:f2:2c:1b:ad:8c', endpoint_id:'mac:18:f2:2c:1b:ad:8c', recognition:{
    device_type:'router', confidence:.65, os_family:'', os_family_confidence:0,
    rule_version:'offline-test',
    evidence:['IEEE OUI: TP-LINK','设备规则: TP-Link 路由器型号','主机名线索: 网络设备类型缺少独立协议确认，按类型线索展示'],
  }})
  renderPanel()
  fireEvent.click(await screen.findByRole('button',{name:'查看详情'}))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('路由器 · 类型线索（65%）')).toBeInTheDocument()
  expect(within(dialog).getByText('类型置信度')).toBeInTheDocument()
  expect(within(dialog).queryByText('识别操作系统')).not.toBeInTheDocument()
  expect(within(dialog).queryByText('系统置信度')).not.toBeInTheDocument()
})

it('shows OS confidence separately from type confidence', async () => {
  mockReads({items:{}}, {...device, mac:'02:00:00:20:40:01', endpoint_id:'mac:02:00:00:20:40:01', recognition:{
    device_type:'desktop', confidence:.9, os_family:'Windows', os_family_confidence:.51,
    rule_version:'offline-test',
    evidence:['Fingerbank DHCP: Windows OS'],
  }})
  renderPanel()
  fireEvent.click(await screen.findByRole('button',{name:'查看详情'}))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('Windows · 系统线索（51%）')).toBeInTheDocument()
  expect(within(dialog).getByText('类型置信度')).toBeInTheDocument()
  expect(within(dialog).getByText('系统置信度')).toBeInTheDocument()
  expect(within(dialog).getByText('51%')).toBeInTheDocument()
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
}, 15000) // 两次完整列表重渲染，满载并跑时超过默认 5 秒

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

it('shows identification quality when the status section opens', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByText('采集与识别状态'))
  await waitFor(() => expect(screen.getByText('类型覆盖')).toBeInTheDocument())
  expect(screen.getAllByText('12%')).toHaveLength(2)
  expect(screen.getByText('50%')).toBeInTheDocument()
  expect(screen.getAllByText('15/121')).toHaveLength(2)
  expect(screen.getByText('厂商 Top')).toBeInTheDocument()
  expect(screen.getByText('华为 3')).toBeInTheDocument()
  expect(screen.getByText('类型厂商')).toBeInTheDocument()
  expect(screen.getByText('摄像头 · Hikvision 2')).toBeInTheDocument()
  expect(screen.getByText('型号 Top')).toBeInTheDocument()
  expect(screen.getByText('HP · LaserJet Pro MFP 1')).toBeInTheDocument()
  expect(screen.getByText('系统 Top')).toBeInTheDocument()
  expect(screen.getByText('Apple OS 2')).toBeInTheDocument()
  expect(screen.getByText('未识别原因')).toBeInTheDocument()
  expect(screen.getByText('Apple 系统线索 2')).toBeInTheDocument()
  expect(screen.getByText('全局识别画像 · 不随列表筛选变化')).toBeInTheDocument()
  expect(await screen.findByText('近 7 天新增')).toBeInTheDocument()
  expect(screen.getByText('6 台 · 今天 4')).toBeInTheDocument()
  expect(screen.getByText('新增类型')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '手机 3' })).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '华为 3' }))
  await waitFor(() => expect(request.mock.calls.some(([path]) => decodeURIComponent(String(path)).includes('search=华为'))).toBe(true))
  fireEvent.click(screen.getByRole('button', { name: '摄像头 · Hikvision 2' }))
  await waitFor(() => expect(request.mock.calls.some(([path]) => decodeURIComponent(String(path)).includes('type=camera') && decodeURIComponent(String(path)).includes('search=Hikvision'))).toBe(true))
  fireEvent.click(screen.getByRole('button', { name: 'Apple OS 2' }))
  await waitFor(() => expect(request.mock.calls.some(([path]) => new URL(String(path), 'http://x').searchParams.get('os') === 'Apple OS')).toBe(true))
})


it('filters the list from the triage counts', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /待核实/ }))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).startsWith('/discovery/devices?') && String(path).includes('state=candidate'))).toBe(true))
})

it('filters VoIP phones from the quick types', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: 'VoIP 话机' }))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).startsWith('/discovery/devices?') && String(path).includes('type=voip_phone'))).toBe(true))
})


it('exports the filtered discovery rows as CSV', async () => {
  mockReads()
  const oldFetch=globalThis.fetch
  globalThis.fetch=vi.fn().mockResolvedValue(new Response([
    JSON.stringify({record:'manifest',total:1,snapshot_at:'2026-11-11T03:00:00Z'}),
    JSON.stringify({record:'item',item:device}),
    JSON.stringify({record:'end',count:1,complete:true}),
  ].join('\n')+'\n'))
  const blobs: Blob[] = []
  const create = URL.createObjectURL
  const revoke = URL.revokeObjectURL
  URL.createObjectURL = (blob: Blob | MediaSource) => { blobs.push(blob as Blob); return "blob:test" }
  URL.revokeObjectURL = () => {}
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {})
  try {
    renderPanel()
    fireEvent.click(screen.getByRole("button", { name: '导出全部筛选结果' }))
    await waitFor(() => expect(blobs.length).toBe(1))
    const csv = await blobs[0].text()
    expect(csv).toContain("标识,名称,MAC")
    expect(csv).toContain("device-1")
    expect(csv).toContain("192.0.2.10")
  } finally {
    click.mockRestore()
    URL.createObjectURL = create
    URL.revokeObjectURL = revoke
    globalThis.fetch=oldFetch
  }
})


it('shows fingerprint matches for linked discovery devices', async () => {
  mockReads(undefined, { ...device, endpoint_id: 'mac:00:11:22:33:44:55' })
  renderPanel()
  fireEvent.click(await screen.findByRole('button', { name: '192.0.2.10' }))
  await waitFor(() => expect(screen.getByText('指纹库命中（端点识别）')).toBeInTheDocument())
  expect(screen.getByText('Hikvision DHCP options')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '查看终端画像' })).toBeInTheDocument()
})


it('filters randomized MAC devices from the advanced filters', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /更多筛选/ }))
  fireEvent.click(screen.getByRole('checkbox', { name: '随机 MAC' }))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).startsWith('/discovery/devices?') && String(path).includes('random_mac=true'))).toBe(true))
})


it('filters by device category from advanced filters', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /更多筛选/ }))
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '设备分类' }))
  fireEvent.click(screen.getByText('网络设备'))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).startsWith('/discovery/devices?') && String(path).includes('category=network'))).toBe(true))
})


it('shows detail navigation across the current page', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(await screen.findByRole('button', { name: '192.0.2.10' }))
  await waitFor(() => expect(screen.getByText('1 / 1')).toBeInTheDocument())
  expect(screen.getByRole('button', { name: '上一台' })).toBeDisabled()
  expect(screen.getByRole('button', { name: '下一台' })).toBeDisabled()
})


it('saves and applies discovery views', async () => {
  localStorage.clear()
  mockReads()
  renderPanel(['/devices?tab=discovery&discovery_type=printer'])
  fireEvent.click(await screen.findByRole('button', { name: /更多筛选/ }))
  fireEvent.click(screen.getByRole('button', { name: '保存视图' }))
  fireEvent.change(screen.getByRole('textbox', { name: '视图名称' }), { target: { value: '打印机视图' } })
  fireEvent.click(screen.getByRole('button', { name: '保 存' }))
  await waitFor(() => expect(localStorage.getItem('proxy-sentinel.discovery.views.v1')).toContain('打印机视图'))
  expect(localStorage.getItem('proxy-sentinel.discovery.views.v1')).toContain('discovery_type=printer')
  fireEvent.click(screen.getByRole('button', { name: '清除筛选' }))
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '保存的视图' }))
  fireEvent.click(screen.getByText('打印机视图'))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).includes('type=printer'))).toBe(true))
  expect(screen.getByRole('button', { name: '删除视图' })).toBeInTheDocument()
})


it('filters by operating system from advanced filters', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /更多筛选/ }))
  fireEvent.change(screen.getByRole('textbox', { name: '操作系统' }), { target: { value: 'Apple OS' } })
  await waitFor(() => expect(request.mock.calls.some(([path]) => new URL(String(path), 'http://x').searchParams.get('os') === 'Apple OS')).toBe(true))
})


it('exports the identification quality report', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByText('采集与识别状态'))
  await screen.findByText('类型覆盖')
  const blobs: Blob[] = []
  const create = URL.createObjectURL
  const revoke = URL.revokeObjectURL
  URL.createObjectURL = (blob: Blob | MediaSource) => { blobs.push(blob as Blob); return "blob:test" }
  URL.revokeObjectURL = () => {}
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {})
  try {
    fireEvent.click(screen.getByRole('button', { name: '导出质量报告' }))
    await waitFor(() => expect(blobs.length).toBe(1))
    const csv = await blobs[0].text()
    expect(csv).toContain('识别质量报告')
    expect(csv).toContain('类型覆盖')
  } finally {
    click.mockRestore()
    URL.createObjectURL = create
    URL.revokeObjectURL = revoke
  }
})


it('switches the trend window to 30 days', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByText('采集与识别状态'))
  await screen.findByText('近 7 天新增')
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '趋势范围' }))
  fireEvent.click(screen.getByText('近 30 天'))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).startsWith('/discovery/trends?days=30'))).toBe(true))
  expect(await screen.findByText(/近 30 天新增/)).toBeInTheDocument()
})


it('toggles automatic refresh and remembers it', async () => {
  localStorage.clear()
  mockReads()
  renderPanel()
  const toggle = await screen.findByRole('switch', { name: '自动刷新' })
  expect(toggle.getAttribute('aria-checked')).toBe('false')
  fireEvent.click(toggle)
  await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('true'))
  expect(localStorage.getItem('proxy-sentinel.discovery.auto-refresh')).toBe('true')
})


it('filters the last 15 minutes from the window select', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /更多筛选/ }))
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '最近观测范围' }))
  fireEvent.click(screen.getByText('近 15 分钟'))
  await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).startsWith('/discovery/devices?') && String(path).includes('window=15m'))).toBe(true))
})


it('debounces the operating system input', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /更多筛选/ }))
  const input = screen.getByRole('textbox', { name: '操作系统' })
  fireEvent.change(input, { target: { value: 'A' } })
  fireEvent.change(input, { target: { value: 'Ap' } })
  fireEvent.change(input, { target: { value: 'Apple OS' } })
  await waitFor(() => expect(request.mock.calls.some(([path]) => new URL(String(path), 'http://x').searchParams.get('os') === 'Apple OS')).toBe(true))
  const listOsValues = request.mock.calls.filter(([path]) => String(path).startsWith('/discovery/devices?')).map(([path]) => new URL(String(path), 'http://x').searchParams.get('os')).filter(Boolean)
  expect(listOsValues).toEqual(['Apple OS'])
})


it('filters multiple device types', async () => {
  mockReads()
  renderPanel()
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '设备类型' }))
  await waitFor(() => expect(document.querySelectorAll('.ant-select-item-option').length).toBeGreaterThan(0))
  const typeOptions = Array.from(document.querySelectorAll<HTMLElement>('.ant-select-item-option'))
  fireEvent.click(typeOptions.find(option => option.textContent === '打印机')!)
  await waitFor(() => expect(Array.from(document.querySelectorAll<HTMLElement>('.ant-select-item-option')).some(option => option.textContent === '摄像头')).toBe(true))
  const nextTypeOptions = Array.from(document.querySelectorAll<HTMLElement>('.ant-select-item-option'))
  fireEvent.click(nextTypeOptions.find(option => option.textContent === '摄像头')!)
  await waitFor(() => expect(request.mock.calls.some(([path]) => new URL(String(path), 'http://x').searchParams.get('type') === 'printer,camera')).toBe(true))
})


it('filters multiple VLANs from one input', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /更多筛选/ }))
  fireEvent.change(screen.getByRole('textbox', { name: 'VLAN' }), { target: { value: '32,33' } })
  await waitFor(() => expect(request.mock.calls.some(([path]) => new URL(String(path), 'http://x').searchParams.get('vlan') === '32,33')).toBe(true))
})


it('filters to current evidence without expired', async () => {
  mockReads()
  renderPanel()
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '证据状态' }))
  fireEvent.click(screen.getByText('当前有效（不含过期）'))
  await waitFor(() => expect(request.mock.calls.some(([path]) => new URL(String(path), 'http://x').searchParams.get('state') === 'identified,candidate,conflict')).toBe(true))
})


it('filters multiple protocols', async () => {
  mockReads()
  renderPanel()
  fireEvent.click(screen.getByRole('button', { name: /更多筛选/ }))
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '发现协议' }))
  await waitFor(() => expect(document.querySelectorAll('.ant-select-item-option').length).toBeGreaterThan(0))
  const protocolOptions = Array.from(document.querySelectorAll<HTMLElement>('.ant-select-item-option'))
  fireEvent.click(protocolOptions.find(option => option.textContent === 'DHCP')!)
  await waitFor(() => expect(Array.from(document.querySelectorAll<HTMLElement>('.ant-select-item-option')).some(option => option.textContent === 'DNS-SD')).toBe(true))
  const nextProtocolOptions = Array.from(document.querySelectorAll<HTMLElement>('.ant-select-item-option'))
  fireEvent.click(nextProtocolOptions.find(option => option.textContent === 'DNS-SD')!)
  await waitFor(() => expect(request.mock.calls.some(([path]) => new URL(String(path), 'http://x').searchParams.get('protocol') === 'dhcp,dns_sd')).toBe(true))
})


it('manages saved discovery views', async () => {
  localStorage.clear()
  mockReads()
  renderPanel()
  fireEvent.click(await screen.findByRole('button', { name: /更多筛选/ }))
  const saveView = async (name: string) => {
    fireEvent.click(screen.getByRole('button', { name: '保存视图' }))
    fireEvent.change(screen.getByRole('textbox', { name: '视图名称' }), { target: { value: name } })
    fireEvent.click(screen.getByRole('button', { name: '保 存' }))
    await waitFor(() => expect(localStorage.getItem('proxy-sentinel.discovery.views.v1')).toContain(name))
  }
  await saveView('视图A')
  await saveView('视图B')
  fireEvent.click(screen.getByRole('button', { name: '管理' }))
  await screen.findByText('管理视图')
  const rowA = screen.getByText('视图A').closest('.discovery-view-manage-row')
  expect(rowA).toBeTruthy()
  fireEvent.click(within(rowA as HTMLElement).getByRole('button', { name: '删除' }))
  await waitFor(() => expect(localStorage.getItem('proxy-sentinel.discovery.views.v1')).not.toContain('视图A'))
  expect(localStorage.getItem('proxy-sentinel.discovery.views.v1')).toContain('视图B')
})



it('retains a known hardware type when service observations expire and shows its dated source', async () => {
  mockReads({items:{}}, {...device,classification_status:'expired',device_type:'camera',hardware_type:'printer',hardware_type_status:'identified',hardware_model:'Canon MF260 Series',type_evidence_at:'2026-11-09T08:00:00Z',type_rule_version:'hardware-v8',activity_status:'stale',type_sources:[{source:'dns_sd',rule_id:'canon-mf260',rule_version:'hardware-v8',evidence_id:'model-event-1',observed_at:'2026-11-09T08:00:00Z'}]})
  renderPanel()
  expect((await screen.findAllByText('打印机'))[0]).toBeVisible()
  expect(await screen.findByLabelText('发现设备摘要')).toHaveTextContent('本页明确类型 1')
  expect(await screen.findByText('最近活动线索已过期')).toBeVisible()
  fireEvent.click(screen.getByRole('button',{name:'查看详情'}))
  const dialog=await screen.findByRole('dialog')
  expect(within(dialog).getByText('类型依据时间')).toBeInTheDocument()
  expect(within(dialog).getByText('model-event-1')).toBeInTheDocument()
  expect(within(dialog).getByText('Canon MF260 Series')).toBeInTheDocument()
})

it('does not revive a revoked scoped hardware type through a legacy endpoint summary', async () => {
  mockReads({items:{}}, {...device,hardware_type_status:'revoked',activity_status:'active',recognition:{device_type:'camera',confidence:0.99}})
  renderPanel()
  expect(await screen.findByLabelText('发现设备摘要')).toHaveTextContent('本页明确类型 0')
  expect(await screen.findByText('硬件结论已撤销')).toBeVisible()
  expect(screen.queryByText('摄像头')).not.toBeInTheDocument()
})


it('shows hardware projection failure instead of inventing zero backlog', async () => {
  mockReads()
  const normalRead=request.getMockImplementation()!
  request.mockImplementation(async(path:string)=>{
    const result=await normalRead(path)
    return path.startsWith('/discovery/devices?')?{...result,hardware_freshness:{status:'failed',error:'规则包版本尚未就绪'}}:result
  })
  renderPanel()
  expect(await screen.findByText('硬件分类处理异常：规则包版本尚未就绪')).toBeVisible()
  expect(screen.getByLabelText('硬件分类处理进度')).not.toHaveTextContent('待处理 0')
})

it('shows ingestion, discovery and archive watermarks for batch discovery', async () => {
  mockReads()
  const normalRead=request.getMockImplementation()!
  request.mockImplementation(async(path:string)=>{
    const result=await normalRead(path)
    return path.startsWith('/discovery/devices?')?{...result,freshness:{
      status:'delayed',source:'passive-discovery-batch-v3',lag_seconds:1800,
      ingested_at:'2026-11-13T08:00:00Z',processed_at:'2026-11-13T07:30:00Z',
      archive_verified_at:'2026-11-13T07:00:00Z',pending_batches:3,archive_pending_batches:2,
      oldest_pending_at:'2026-11-13T07:25:00Z',archive_oldest_pending_at:'2026-11-13T06:50:00Z',
    }}:result
  })
  renderPanel()
  const progress=await screen.findByLabelText('存储处理进度')
  expect(progress).toHaveTextContent('采集入库')
  expect(progress).toHaveTextContent('设备发现')
  expect(progress).toHaveTextContent('待发现批次 3')
  expect(progress).toHaveTextContent('证据归档')
  expect(progress).toHaveTextContent('待归档批次 2')
  expect(await screen.findByText('设备数据更新延迟')).toBeInTheDocument()
})
