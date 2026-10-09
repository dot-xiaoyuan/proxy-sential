import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { DevicesPage } from './DevicesPage'

const fixture = vi.hoisted(()=>({total:88 as number|undefined,items:[] as unknown[]|null,metadataError:false,refresh:vi.fn(),metadataRefresh:vi.fn(),organization:vi.fn(()=>({data:undefined})),diagnostics:vi.fn(()=>({data:undefined}))}))
vi.mock('../shared/api/queries', () => ({
  useOrganization: fixture.organization,
  useDeviceRecognitionSummary: fixture.diagnostics,
  useDevices: () => ({ data: { items: fixture.items, page: {next_cursor:'20'}, facets: { brands: [], os_families: [] } },dataUpdatedAt:Date.now(), isFetching: false,isPlaceholderData:false,refresh:fixture.refresh }),
  useDeviceInventoryMetadata:()=>({data:fixture.total===undefined?undefined:{total:fixture.total,facets:{brands:[],os_families:[]}},isError:fixture.metadataError,refresh:fixture.metadataRefresh}),
}))
afterEach(()=>{cleanup();fixture.total=88;fixture.items=[];fixture.metadataError=false;localStorage.clear();vi.clearAllMocks()})
function Location() { return <output data-testid="location">{useLocation().search}</output> }
function setup(url = '/devices') { render(<MemoryRouter initialEntries={[url]}><DevicesPage /><Location /></MemoryRouter>) }
async function settle() { await act(async () => { await new Promise(resolve => setTimeout(resolve, 450)) }) }

describe('终端列表分页与搜索', () => {
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
    fireEvent.change(screen.getByPlaceholderText('搜索设备名称、MAC、IP 或账号'), { target: { value: 'Dell' } })
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
 expect(screen.getByPlaceholderText('搜索设备名称、MAC、IP 或账号')).toHaveValue('office')
 expect(screen.queryByText('10 分钟')).not.toBeInTheDocument()
 await settle()
 expect(screen.getByTestId('location')).toHaveTextContent('q=office')
})
it('treats a legacy null items response as an empty list',()=>{
 fixture.items=null
 setup('/devices?view=recent&window=24h')
 expect(screen.getAllByText('没有匹配的终端').length).toBeGreaterThan(0)
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
it('manual refresh refreshes current list and statistics without changing the page',()=>{
 setup('/devices?view=history&page=2')
 fireEvent.click(screen.getByRole('button',{name:/刷新数据/}))
 expect(fixture.refresh).toHaveBeenCalledOnce()
 expect(fixture.metadataRefresh).toHaveBeenCalledOnce()
 expect(screen.getByTestId('location')).toHaveTextContent('page=2')
})
it('mounts campus filters only when expanded and enables diagnostics separately',async()=>{
 setup('/devices?view=recent&window=24h')
 expect(fixture.organization).not.toHaveBeenCalled()
 const filters=document.querySelector('.device-filter-disclosure') as HTMLDetailsElement
 filters.open=true;fireEvent(filters,new Event('toggle'))
 await waitFor(()=>expect(fixture.organization).toHaveBeenCalled())
 expect(fixture.diagnostics).toHaveBeenLastCalledWith(false)
 const diagnostics=document.querySelector('.device-diagnostics') as HTMLDetailsElement
 diagnostics.open=true;fireEvent(diagnostics,new Event('toggle'))
 await waitFor(()=>expect(fixture.diagnostics).toHaveBeenLastCalledWith(true))
})
