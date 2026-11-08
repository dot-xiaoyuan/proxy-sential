import { afterAll, beforeAll, expect, it } from 'vitest'
import { setupServer } from 'msw/node'
import { discoveryHandlers } from './discovery'

const server = setupServer(...discoveryHandlers)
const base = new URL('/api/v1/discovery/devices', window.location.href).href
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())

it('keeps independent discovery metadata aligned with type, search and capability filters', async () => {
  for (const [query, expected] of [['', 6], ['&type=router', 1], ['&search=Huawei', 1], ['&type=access_point&category=printer', 1], ['&capability=dumb', 3], ['&type=router&search=摄像机', 0]] as const) {
    const suffix = `?mode=passive&limit=1${query}`
    const page = await (await fetch(`${base}${suffix}`)).json()
    const metadata = await (await fetch(`${base}/metadata${suffix}`)).json()
    expect(metadata.total).toBe(expected)
    expect(metadata.count_unit).toBe('trusted_discovery_identity')
    expect(page.total).toBe(metadata.total)
    expect(page.items).toHaveLength(Math.min(1, expected))
  }
})

it('returns a complete router sample and pages without changing the independent count', async () => {
  const routers = await (await fetch(`${base}?mode=passive&type=router`)).json()
  expect(routers.items[0]).toMatchObject({ device_type: 'router', manufacturer: 'Huawei', classification_status: 'identified', current: true, current_addresses: ['192.0.2.41'], capabilities: ['routing'] })
  const first = await (await fetch(`${base}?mode=passive&limit=2`)).json()
  const second = await (await fetch(`${base}?mode=passive&limit=2&cursor=${first.next_cursor}`)).json()
  expect(first.has_more).toBe(true)
  expect(new Set([...first.items, ...second.items].map((row: { id: string }) => row.id)).size).toBe(4)
  expect((await (await fetch(`${base}/metadata?mode=passive&cursor=${first.next_cursor}`)).json()).total).toBe(6)
})

it('locates an unvisited discovery page and rejects a page past the exact last boundary', async () => {
  const position = await (await fetch(`${base}/position?mode=passive&page=3&limit=2`)).json()
  const located = await (await fetch(`${base}?mode=passive&limit=2&cursor=${position.cursor}`)).json()
  expect(position).toMatchObject({page:3,limit:2})
  expect(located.items.map((row:{id:string})=>row.id)).toEqual(['fixture-camera','fixture-router'])
  expect((await fetch(`${base}/position?mode=passive&page=4&limit=2`)).status).toBe(400)
  expect((await fetch(`${base}/position?mode=passive&type=router&page=2&limit=1`)).status).toBe(400)
})
