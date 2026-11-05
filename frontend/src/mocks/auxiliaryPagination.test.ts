import { afterAll, beforeAll, expect, it } from 'vitest'
import { setupServer } from 'msw/node'
import { auxiliaryPaginationHandlers } from './auxiliaryPagination'
import { inventoryTraceHandlers } from './inventoryTrace'
import { ipTrafficObservationHandlers } from './ipTrafficObservations'
import { macOSDevice } from './deviceRecognition'

const server=setupServer(...auxiliaryPaginationHandlers,...inventoryTraceHandlers,...ipTrafficObservationHandlers)
const base=new URL('/api/v1',window.location.href).href
const get=(path:string)=>fetch(`${base}${path}`)
beforeAll(()=>server.listen({onUnhandledRequest:'error'}))
afterAll(()=>server.close())

it('jumps directly to filtered relay pages and rejects pages past the end',async()=>{
  const first=await(await get('/ai-relay/usages?domain=yunwu.ai&limit=10')).json()
  expect(first.page.total).toBe(23)
  const position=await(await get('/ai-relay/usages/position?domain=yunwu.ai&limit=10&page=3')).json()
  const last=await(await get(`/ai-relay/usages?domain=yunwu.ai&limit=10&cursor=${position.cursor}`)).json()
  expect(last.items).toHaveLength(3)
  expect(last.items.every((item:{domains:string[]})=>item.domains.includes('api.yunwu.ai'))).toBe(true)
  expect((await get('/ai-relay/usages/position?domain=yunwu.ai&limit=10&page=4')).status).toBe(400)
})

it('keeps stream and risk counts aligned with the actual cursor list',async()=>{
  const stream='/events/stream-index',query='scope_id=scope-a&from=2026-11-06T00:00:00Z&to=2026-11-06T00:10:00Z'
  expect((await(await get(`${stream}/metadata?${query}`)).json()).total).toBe(1)
  expect((await get(`${stream}/position?${query}&page=2&limit=1`)).status).toBe(400)
  const risks=await(await get('/risks/stream-current')).json()
  expect(risks.next_cursor).toBeUndefined()
  const level=risks.items[0].level
  expect((await(await get(`/risks/stream-current/metadata?level=${level}`)).json()).total).toBe(risks.items.length)
})

it('uses a fixed trace snapshot and the same source filter for count and page lookup',async()=>{
  const path=`/endpoints/${encodeURIComponent(macOSDevice.endpoint_id!)}/observations`
  const query='kind=ip&as_of=2026-11-06T00:00:00Z&source=mock'
  const metadata=await(await get(`${path}/metadata?${query}`)).json()
  const first=await(await get(`${path}?${query}&limit=20`)).json()
  expect(metadata.total).toBe(45)
  expect(first.items).toHaveLength(20)
  const position=await(await get(`${path}/position?${query}&page=3&limit=20`)).json()
  expect(position.as_of).toBe('2026-11-06T00:00:00Z')
  expect((await(await get(`${path}?${query}&limit=20&cursor=${position.cursor}`)).json()).items).toHaveLength(5)
  expect((await(await get(`${path}/metadata?kind=ip&source=other`)).json()).total).toBe(0)
})

it('keeps IP observation count and protocol paging aligned',async()=>{
  const path='/ips/192.0.2.1/traffic-observations',query='from=2026-11-06T00:00:00Z&to=2026-11-06T00:10:00Z'
  expect((await(await get(`${path}/metadata?${query}`)).json()).total).toBe(2)
  const position=await(await get(`${path}/position?${query}&limit=1&page=2`)).json()
  const second=await(await get(`${path}?${query}&limit=1&cursor=${position.cursor}`)).json()
  expect(second.events).toHaveLength(1)
  expect(second.events[0].protocol).toBe('ttl')
  expect((await(await get(`${path}/metadata?${query}&protocol=ttl`)).json()).total).toBe(1)
  expect((await get(`${path}/position?${query}&protocol=ttl&limit=1&page=2`)).status).toBe(400)
})
