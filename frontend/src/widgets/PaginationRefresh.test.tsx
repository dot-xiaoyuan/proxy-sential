import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { EndpointTracePanel } from '../entities/device/EndpointTracePanel'
import { StreamRiskCurrentPanel } from './StreamRiskCurrentPanel'
const mock=vi.hoisted(()=>({at:'2026-11-06T01:00:00Z',observations:vi.fn(),risk:vi.fn(),request:vi.fn()}))
vi.mock('../shared/api/client',()=>({api:{endpointObservations:mock.observations,streamRiskCurrent:mock.risk},request:mock.request,ApiError:class extends Error {status=500}}))
let client:QueryClient
beforeEach(()=>{
 client=new QueryClient({defaultOptions:{queries:{retry:false}}});mock.at='2026-11-06T01:00:00Z';vi.clearAllMocks()
 mock.request.mockImplementation(async(path:string)=>{const q=new URL(path,'http://localhost').searchParams;return path.includes('/position')?{page:Number(q.get('page')),limit:Number(q.get('limit')),cursor:'page-position',as_of:mock.at}:{total:61,as_of:mock.at}})
 mock.observations.mockResolvedValue({items:[],state:{complete:true,updating:false,as_of:mock.at}})
 mock.risk.mockResolvedValue({items:[],accepted_after:'2026-11-06T00:00:00Z',next_cursor:''})
})
afterEach(()=>{cleanup();client.clear()})
function setup(ui:React.ReactNode){render(<QueryClientProvider client={client}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>)}
it('溯源刷新重新取得快照并回到首屏，不用旧as_of继续读取',async()=>{
 setup(<EndpointTracePanel endpointId="mac:test"/>)
 await waitFor(()=>expect(mock.observations).toHaveBeenCalled())
 expect(mock.observations.mock.lastCall?.[1].as_of).toBe('2026-11-06T01:00:00Z')
 fireEvent.click(screen.getByTitle('3'))
 await waitFor(()=>expect(mock.observations.mock.lastCall?.[1].cursor).toBe('page-position'))
 mock.at='2026-11-06T02:00:00Z'
 const before=mock.observations.mock.calls.length
 await waitFor(()=>expect(screen.getByRole('button',{name:/刷新明细/})).not.toHaveClass('ant-btn-loading'))
 fireEvent.click(screen.getByRole('button',{name:/刷新明细/}))
 await waitFor(()=>expect(mock.observations.mock.lastCall?.[1].as_of).toBe(mock.at))
 expect(mock.observations.mock.calls.slice(before).every(([,q])=>q.as_of===mock.at&&!q.cursor)).toBe(true)
 await waitFor(()=>expect(screen.getByTitle('1')).toHaveClass('ant-pagination-item-active'))
})
it('风险列表不再独立轮询，显式刷新同时更新统计并归首页',async()=>{
 setup(<StreamRiskCurrentPanel/>)
 await screen.findByText('共 61 条')
 await waitFor(()=>expect(mock.risk).toHaveBeenCalledTimes(1))
 await act(async()=>{await new Promise(resolve=>setTimeout(resolve,3100))})
 expect(mock.risk).toHaveBeenCalledTimes(1)
 fireEvent.click(screen.getByTitle('3'))
 await waitFor(()=>expect(mock.risk.mock.lastCall?.[0].cursor).toBe('page-position'))
 const before=mock.risk.mock.calls.length
 mock.at='2026-11-06T02:00:00Z'
 fireEvent.click(screen.getByRole('button',{name:'刷新结果'}))
 await waitFor(()=>expect(mock.risk.mock.calls.length).toBeGreaterThan(before))
 expect(mock.risk.mock.lastCall?.[0].cursor).toBeUndefined()
 await waitFor(()=>expect(screen.getByTitle('1')).toHaveClass('ant-pagination-item-active'))
 expect(screen.getByText(/统计时间/)).toBeVisible()
 expect(mock.request.mock.calls.filter(([path])=>String(path).includes('/metadata'))).toHaveLength(2)
})
