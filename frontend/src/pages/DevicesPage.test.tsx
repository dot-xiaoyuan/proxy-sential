import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { DevicesPage } from './DevicesPage'

vi.mock('../widgets/IpTrafficObservations', () => ({ IpTrafficObservations: ({ip}:{ip:string}) => <output data-testid="ip-observations">{ip}</output> }))

const fixture = vi.hoisted(()=>({total:88 as number|undefined,items:[] as unknown[]|null,eventsRead:true,metadataError:false,readState:undefined as {complete:boolean;updating:boolean;as_of:string;available?:boolean}|undefined,refresh:vi.fn(),metadataRefresh:vi.fn(),organization:vi.fn(()=>({data:undefined})),diagnosticsData:undefined as unknown,diagnostics:vi.fn((_enabled?:boolean)=>({data:undefined as unknown}))}))
vi.mock('../shared/api/queries', () => ({
  useOrganization: fixture.organization,
  useSession: () => ({data:{user:{id:'admin'},permissions:fixture.eventsRead?['identity:read','events:read']:['identity:read']}}),
  useDeviceRecognitionSummary: (enabled?:boolean)=>{fixture.diagnostics(enabled);return {data:fixture.diagnosticsData}},
  useDevices: () => ({ data: { items: fixture.items, read_model_state:fixture.readState, page: {next_cursor:'20'}, facets: { brands: [], os_families: [] } },dataUpdatedAt:Date.now(), isFetching: false,isPlaceholderData:false,refresh:fixture.refresh }),
  useDeviceInventoryMetadata:()=>({data:fixture.total===undefined?undefined:{total:fixture.total,facets:{brands:[],os_families:[]}},isError:fixture.metadataError,refresh:fixture.metadataRefresh}),
}))
afterEach(()=>{cleanup();fixture.total=88;fixture.items=[];fixture.eventsRead=true;fixture.metadataError=false;fixture.readState=undefined;fixture.diagnosticsData=undefined;localStorage.clear();vi.clearAllMocks()})
function Location() { return <output data-testid="location">{useLocation().search}</output> }
function setup(url = '/devices') { render(<MemoryRouter initialEntries={[url]}><DevicesPage /><Location /></MemoryRouter>) }
async function settle() { await act(async () => { await new Promise(resolve => setTimeout(resolve, 450)) }) }

describe('终端列表分页与搜索', () => {
  it('精确 IP 没有终端结果时在列表内展示有界流量观测', () => {
    fixture.total=0
    setup('/devices?tab=terminal&view=recent&window=24h&q=10.157.2.191')
    expect(screen.getByTestId('ip-observations')).toHaveTextContent('10.157.2.191')
    expect(screen.queryByRole('link', {name:'查看该 IP 的流量观察'})).not.toBeInTheDocument()
  })
  it('没有事件读取权限时不加载流量观测', () => {
    fixture.total=0;fixture.eventsRead=false
    setup('/devices?tab=terminal&view=recent&window=24h&q=10.157.2.191')
    expect(screen.queryByTestId('ip-observations')).not.toBeInTheDocument()
    expect(screen.getByText('当前身份与地址索引中没有该 IP 的关联记录。')).toBeInTheDocument()
  })
  it('翻页后保持第二页，继续翻页不会触发搜索重置', async () => {
    setup()
    fireEvent.click(screen.getByTitle('2'))
    await settle()
    expect(screen.getByTestId('location')).toHaveTextContent('page=2')
    fireEvent.click(screen.getByTitle('3'))
    await settle()
    expect(screen.getByTestId('location')).toHaveTextContent('page=3')
  })
  it('保留 URL 页码，仅搜索内容变化时重置第一页', async () => {
    setup('/devices?page=2&limit=50')
    await settle()
    expect(screen.getByTestId('location')).toHaveTextContent('page=2&limit=50')
    fireEvent.change(screen.getByPlaceholderText('搜索终端名称、MAC、IP 或账号'), { target: { value: 'Dell' } })
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('page=1&limit=50'))
    fireEvent.click(screen.getByTitle('2'))
    await settle()
    expect(screen.getByTestId('location')).toHaveTextContent('page=2&limit=50')
  })
})

it('falls back to the last available page after the result count shrinks', async()=>{
 fixture.total=21
 setup('/devices?page=5&limit=20&view=recent&window=24h')
 await waitFor(()=>expect(screen.getByTestId('location')).toHaveTextContent('page=2'))
 expect(screen.getByTestId('location')).toHaveTextContent('view=recent')
})
it('restores search and scope from the URL', async()=>{
 setup('/devices?view=history&q=office&page=1&limit=20')
 expect(screen.getByPlaceholderText('搜索终端名称、MAC、IP 或账号')).toHaveValue('office')
 expect(screen.queryByText('10 分钟')).not.toBeInTheDocument()
 await settle()
 expect(screen.getByTestId('location')).toHaveTextContent('q=office')
})
it('treats a legacy null items response as an empty list',()=>{
 fixture.items=null
 setup('/devices?view=recent&window=24h')
 expect(screen.getAllByText('没有匹配的终端').length).toBeGreaterThan(0)
})
it('keeps IPv4 as the only primary address and places names and MACs in fixed fields',()=>{
 fixture.items=[
  {endpoint_id:'named',current_ip:'192.0.2.10',primary_mac:'00:11:22:33:44:10',device_name:{value:'DESKTOP-01',source:'dhcp',confidence:1}},
  {endpoint_id:'mac-only',primary_mac:'00:11:22:33:44:11'},
  {endpoint_id:'ipv6-only',current_ip:'2001:db8::12',primary_mac:'00:11:22:33:44:12'},
 ]
 const {container}=render(<MemoryRouter initialEntries={['/devices?view=recent&window=24h']}><DevicesPage /></MemoryRouter>)
 const rows=[...container.querySelectorAll('.ant-table-tbody tr.ant-table-row')]
 expect(rows).toHaveLength(3)
 expect(rows[0]).toHaveTextContent('192.0.2.10')
 expect(rows[0]).toHaveTextContent('DESKTOP-01')
 expect(rows[0]).toHaveTextContent('00:11:22:33:44:10')
 expect(rows[1]).not.toHaveTextContent('192.0.2.')
 expect(rows[1]).toHaveTextContent('00:11:22:33:44:11')
 expect(rows[2]).not.toHaveTextContent('192.0.2.')
 expect(rows[2]).toHaveTextContent('00:11:22:33:44:12')
 expect(rows[2]).toHaveTextContent('2001:db8::12')
})
it('restores exact account search and waits for explicit submit',async()=>{
 setup('/devices?view=recent&window=24h&search_type=account&q=Student-A&page=2')
 const input=screen.getByPlaceholderText('输入完整账号（最新观测关联）')
 expect(input).toHaveValue('Student-A')
 fireEvent.change(input,{target:{value:'Student-B'}});await settle()
 expect(screen.getByTestId('location')).toHaveTextContent('q=Student-A')
 fireEvent.keyDown(input,{key:'Enter',code:'Enter',charCode:13});fireEvent.keyUp(input,{key:'Enter',code:'Enter',charCode:13})
 await waitFor(()=>expect(screen.getByTestId('location')).toHaveTextContent('q=Student-B'))
 expect(screen.getByTestId('location')).toHaveTextContent('search_type=account')
 expect(screen.getByTestId('location')).toHaveTextContent('page=1')
})

it('shows the list before statistics without displaying a zero count',()=>{
 fixture.total=undefined
 fixture.items=[{endpoint_id:'test',current_ip:'192.0.2.1',primary_mac:'00:11:22:33:44:55',current_account:'student-1',current_access_id:'Campus-AP-1'}]
 setup('/devices?view=recent&window=24h')
 expect(screen.getAllByRole('link',{name:'192.0.2.1'}).length).toBeGreaterThan(0)
 expect(screen.getByRole('button',{name:'下一页'})).toBeEnabled()
 expect(screen.queryByText('0 个终端身份')).not.toBeInTheDocument()
 expect(screen.getAllByText('student-1').length).toBeGreaterThan(0)
 expect(fixture.organization).not.toHaveBeenCalled()
})
it('keeps the list when metadata fails and retries only statistics',()=>{
 fixture.total=undefined;fixture.metadataError=true
 setup('/devices?view=recent&window=24h')
 expect(screen.getAllByText('没有匹配的终端').length).toBeGreaterThan(0)
 fireEvent.click(screen.getByRole('button',{name:'重试统计'}))
 expect(fixture.metadataRefresh).toHaveBeenCalledOnce()
 expect(fixture.refresh).not.toHaveBeenCalled()
})
it('mounts campus filters only when expanded and enables diagnostics separately',async()=>{
 setup('/devices?view=recent&window=24h')
 expect(fixture.organization).not.toHaveBeenCalled()
 fireEvent.click(screen.getByRole('button',{name:/更多筛选/}))
 await waitFor(()=>expect(fixture.organization).toHaveBeenCalled())
 expect(fixture.diagnostics).toHaveBeenLastCalledWith(false)
 const diagnostics=document.querySelector('.device-diagnostics') as HTMLDetailsElement
 diagnostics.open=true;fireEvent(diagnostics,new Event('toggle'))
 await waitFor(()=>expect(fixture.diagnostics).toHaveBeenLastCalledWith(true))
})
function openDiagnostics(){const diagnostics=document.querySelector('.device-diagnostics') as HTMLDetailsElement;diagnostics.open=true;fireEvent(diagnostics,new Event('toggle'))}
it('reports link-layer attribution and per-source visibility',async()=>{
 fixture.diagnosticsData={total_endpoints:36,coverage:{},event_count:100,mac_attributed_event_count:6,mac_attribution_rate:.06,event_attribution_rate:0,observability:[{source_event_type:'conn',event_count:60,mac_attributed_count:0},{source_event_type:'ssdp',event_count:40,mac_attributed_count:40}]}
 setup('/devices?view=recent&window=24h')
 openDiagnostics()
 await waitFor(()=>expect(document.querySelector('.device-attribution-summary')).toBeTruthy())
 expect(screen.getByText(/6 \/ 100 事件带 MAC/)).toBeInTheDocument()
 const rows=document.querySelectorAll('.device-observability-list > li')
 expect(rows).toHaveLength(2)
 expect(rows[0]).toHaveTextContent('conn')
 expect(rows[1]).toHaveTextContent('ssdp')
 expect(screen.queryByText('镜像事件尚未带链路层地址')).not.toBeInTheDocument()
})
it('warns when no mirrored event carries a link-layer address',async()=>{
 fixture.diagnosticsData={total_endpoints:1,coverage:{},event_count:100,mac_attributed_event_count:0,mac_attribution_rate:0,event_attribution_rate:0,observability:[{source_event_type:'conn',event_count:100,mac_attributed_count:0}]}
 setup('/devices?view=recent&window=24h')
 openDiagnostics()
 await waitFor(()=>expect(screen.getByText('镜像事件尚未带链路层地址')).toBeInTheDocument())
})

it('distinguishes available summaries from incomplete historical associations',()=>{
 fixture.readState={available:true,complete:false,updating:true,as_of:'2026-10-13T12:00:00Z'}
 fixture.items=[{endpoint_id:'summary-only',current_ip:'192.0.2.19'}]
 setup('/devices')
 expect(screen.getByText('历史关联正在回填')).toBeInTheDocument()
 expect(screen.getByText(/历史检索和关联统计尚不完整/)).toBeInTheDocument()
 expect(screen.getAllByRole('link',{name:'192.0.2.19'}).length).toBeGreaterThan(0)
})
