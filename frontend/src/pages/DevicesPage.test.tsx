import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactElement } from 'react'
import { request } from '../shared/api/client'
import { act, cleanup, fireEvent, render as baseRender, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { DevicesPage } from './DevicesPage'

vi.mock('../shared/api/client', async original => ({...await original<typeof import('../shared/api/client')>(),request:vi.fn(async (path:string)=>{const q=new URL(path,'http://localhost').searchParams;return {page:Number(q.get('page')),limit:Number(q.get('limit')),cursor:`page-${q.get('page')}`}})}))
function render(ui:ReactElement){return baseRender(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}>{ui}</QueryClientProvider>)}

vi.mock('../widgets/IpTrafficObservations', () => ({ IpTrafficObservations: ({ip}:{ip:string}) => <output data-testid="ip-observations">{ip}</output> }))

vi.stubGlobal('localStorage',{getItem:vi.fn(()=>null),setItem:vi.fn(),removeItem:vi.fn(),clear:vi.fn()})
const fixture = vi.hoisted(()=>({total:88 as number|undefined,items:[] as unknown[]|null,nextCursor:'20' as string|null,eventsRead:true,metadataError:false,readState:undefined as {complete:boolean;updating:boolean;as_of:string;available?:boolean}|undefined,refresh:vi.fn(),metadataRefresh:vi.fn(),organization:vi.fn(()=>({data:undefined})),diagnosticsData:undefined as unknown,diagnostics:vi.fn((_enabled?:boolean)=>({data:undefined as unknown}))}))
vi.mock('../shared/api/queries', () => ({
  useOrganization: fixture.organization,
  useSession: () => ({data:{user:{id:'admin'},permissions:fixture.eventsRead?['identity:read','events:read']:['identity:read']}}),
  useDeviceRecognitionSummary: (enabled?:boolean)=>{fixture.diagnostics(enabled);return {data:fixture.diagnosticsData}},
  useDevices: () => ({ data: { items: fixture.items, read_model_state:fixture.readState, page: {next_cursor:fixture.nextCursor}, facets: { brands: [], os_families: [] } },dataUpdatedAt:Date.now(), isFetching: false,isPlaceholderData:false,refresh:fixture.refresh }),
  useDeviceInventoryMetadata:()=>({data:fixture.total===undefined?undefined:{total:fixture.total,facets:{brands:[],os_families:[]}},isError:fixture.metadataError,refresh:fixture.metadataRefresh}),
}))
afterEach(()=>{cleanup();fixture.total=88;fixture.items=[];fixture.nextCursor='20';fixture.eventsRead=true;fixture.metadataError=false;fixture.readState=undefined;fixture.diagnosticsData=undefined;window.localStorage.clear();vi.clearAllMocks()})
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
    fireEvent.click(screen.getByTitle('Next Page'))
    await settle()
    expect(screen.getByTestId('location')).toHaveTextContent('page=2')
    fireEvent.click(screen.getByTitle('Next Page'))
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
    fireEvent.click(screen.getByTitle('Next Page'))
    await settle()
    expect(screen.getByTestId('location')).toHaveTextContent('page=2&limit=50')
  })
})

it('keeps the requested page when positioning fails even if the independent count shrinks', async()=>{
 fixture.total=21
 vi.mocked(request).mockRejectedValueOnce(new Error('目标页超出当前结果范围'))
 setup('/devices?page=5&limit=20&view=recent&window=24h')
 await screen.findByText('页码定位失败')
 expect(screen.getByTestId('location')).toHaveTextContent('page=5')
 expect(vi.mocked(request).mock.calls.every(([path])=>!String(path).includes('page=1'))).toBe(true)
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
it('leads the identity column with IPv4 and keeps IPv6 in the address column',()=>{
 fixture.items=[
  {endpoint_id:'named',current_ip:'192.0.2.10',primary_mac:'00:11:22:33:44:10',device_name:{value:'DESKTOP-01',source:'dhcp',confidence:1}},
  {endpoint_id:'mac-only',primary_mac:'00:11:22:33:44:11'},
  {endpoint_id:'ipv6-only',current_ip:'2001:db8::12',primary_mac:'00:11:22:33:44:12'},
  {endpoint_id:'dual',current_ip:'2001:db8::99',current_ipv4:'192.0.2.99',current_ipv6:'2001:db8::99',primary_mac:'00:11:22:33:44:13',device_name:{value:'DUAL-01',source:'dhcp',confidence:1}},
 ]
 const {container}=render(<MemoryRouter initialEntries={['/devices?view=recent&window=24h']}><DevicesPage /></MemoryRouter>)
 const rows=[...container.querySelectorAll('.ant-table-tbody tr.ant-table-row')]
 expect(rows).toHaveLength(4)
 expect(rows[0].querySelector('td[data-label="IPv4 / 终端"]')).toHaveTextContent('192.0.2.10')
 expect(rows[0].querySelector('td[data-label="IPv4 / 终端"]')).toHaveTextContent('DESKTOP-01')
 expect(rows[0].querySelector('td[data-label="IPv4 / 终端"]')).toHaveTextContent('00:11:22:33:44:10')
 expect(rows[1]).not.toHaveTextContent('192.0.2.')
 expect(rows[1].querySelector('td[data-label="IPv4 / 终端"]')).toHaveTextContent('00:11:22:33:44:11')
 expect(rows[1].querySelector('td[data-label="IPv4 / 终端"] .terminal-inventory-primary')).toBeNull()
 expect(rows[2].querySelector('td[data-label="IPv4 / 终端"]')).toHaveTextContent('00:11:22:33:44:12')
 expect(rows[2].querySelector('td[data-label="IPv6 / 接入"]')).toHaveTextContent('2001:db8::12')
 expect(rows[3].querySelector('td[data-label="IPv4 / 终端"]')).toHaveTextContent('192.0.2.99')
 expect(rows[3].querySelector('td[data-label="IPv4 / 终端"]')).toHaveTextContent('DUAL-01')
 expect(rows[3].querySelector('td[data-label="IPv6 / 接入"]')).toHaveTextContent('2001:db8::99')
})

it('retains independent identity counts and access conflicts with the unified visual layout',()=>{
 fixture.total=123
 fixture.items=[{endpoint_id:'printer',primary_mac:'00:11:22:33:44:10',current_ip:'192.0.2.10',device_type:'printer',device_type_confidence:.95,brand:'HP',brand_confidence:.95,os_family:'Linux',os_family_confidence:.95,current_account:'user-a',owner_name:'图书馆',current_access_id:'slot=1;subslot=0;port=8;vlanid=204',current_access_conflict:true,ip_match:{ip:'192.0.2.9',matched_at:'2026-11-05T12:00:00Z',source:'ip_observation',is_recent_ip:false}}]
 setup('/devices?view=history&search_type=ip&q=192.0.2.9')
 expect(screen.getByText('123 个终端身份')).toBeVisible()
 expect(screen.getByRole('img',{name:'打印机'})).toBeVisible()
 expect(screen.getByText('Linux')).toBeVisible()
 expect(screen.getByText('user-a')).toBeVisible()
 expect(screen.getByText('端口 1/0/8 · VLAN 204')).toBeVisible()
 expect(screen.getByText('接入位置冲突')).toBeVisible()
 expect(screen.getByText('历史 IP 命中')).toBeVisible()
 const detail=screen.getByRole('link',{name:'查看详情'})
 expect(decodeURIComponent(detail.getAttribute('href')!)).toContain('return_to=/devices?view=history&search_type=ip&q=192.0.2.9')
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
 expect(document.querySelector('.ant-pagination-next')).toHaveClass('ant-pagination-disabled')
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
it('uses numeric page positioning even when the prior response has no next cursor',async()=>{
 fixture.total=123;fixture.nextCursor=null
 fixture.items=[{endpoint_id:'only-page',current_ip:'192.0.2.10'}]
 setup('/devices?view=recent&window=24h')
 expect(screen.getByText('123 个终端身份')).toBeVisible()
 expect(screen.getByTitle('6')).toBeVisible()
 fireEvent.click(screen.getByTitle('6'))
 await waitFor(()=>expect(vi.mocked(request).mock.calls.some(([path])=>String(path).includes('page=6'))).toBe(true))
 expect(screen.getByTestId('location')).toHaveTextContent('page=6')
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
