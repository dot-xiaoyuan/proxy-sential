import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { CensusPanel } from './CensusPanel'

const request=vi.hoisted(()=>vi.fn())
vi.mock('../shared/api/client',async original=>({...await original<typeof import('../shared/api/client')>(),request}))

it('shows scoped counts and sends the same window to summary and drill-down',async()=>{
  request.mockImplementation((path:string)=>path.includes('/summary?')?Promise.resolve({metric_version:'passive-census/v1',scope:{sensor_id:'sensor-204'},window:'24h0m0s',status:'ready',as_of:'2026-11-10T09:00:00Z',available_from:'2026-11-09T09:00:00Z',failed_batches:0,last_batch_rows:100,last_batch_ms:9,observed_ips:12,observed_ipv4:10,observed_ipv6:2,observed_macs:8,random_macs:1,incomplete_scope:0,active_bindings:5,identified_terminals:3,terminal_candidates:1,terminal_conflicts:0,terminal_expired:0,manually_verified:0,types:[{device_type:'printer',identified:3,candidate:1,conflict:0,expired:0}]}):Promise.resolve({items:[],has_more:false,next_cursor:''}))
  const client=new QueryClient({defaultOptions:{queries:{retry:false}}})
  render(<QueryClientProvider client={client}><CensusPanel/></QueryClientProvider>)
  expect((await screen.findByText('12')).closest('button')).toHaveTextContent('IP')
  fireEvent.click(screen.getByText('8').closest('button')!)
  await waitFor(()=>expect(request.mock.calls.some(([path])=>String(path).includes('/identifiers?')&&String(path).includes('kind=mac'))).toBe(true))
  fireEvent.click(screen.getByText('3').closest('button')!)
  await waitFor(()=>expect(request.mock.calls.some(([path])=>String(path).includes('kind=terminal&limit=100&terminal_status=identified'))).toBe(true))
  fireEvent.change(screen.getByLabelText('镜像统计VLAN'),{target:{value:'20'}})
  await waitFor(()=>expect(request.mock.calls.some(([path])=>String(path).includes('/summary?')&&String(path).includes('vlan=20'))).toBe(true))
})
