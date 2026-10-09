import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { DevicesPage } from './DevicesPage'

const fixture = vi.hoisted(()=>({total:88,items:[] as unknown[]|null}))
vi.mock('../shared/api/queries', () => ({
  useOrganization: () => ({ data: undefined }),
  useDeviceRecognitionSummary: () => ({ data: undefined }),
  useDevices: () => ({ data: { items: fixture.items, page: { total: fixture.total }, facets: { brands: [], os_families: [] } }, isFetching: false, refetch: vi.fn() }),
}))
afterEach(()=>{cleanup();fixture.total=88;fixture.items=[]})
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
