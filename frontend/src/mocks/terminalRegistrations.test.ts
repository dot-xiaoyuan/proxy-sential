import { afterAll, beforeAll, beforeEach, expect, it } from 'vitest'
import { setupServer } from 'msw/node'
import { createTerminalRegistrationHandlers } from './terminalRegistrations'
import type { components } from '../shared/api/generated'

type Page = components['schemas']['EndpointRegistrationPage']
const server = setupServer()
const base = new URL('/api/v1', window.location.href).href
const get = (path: string) => fetch(`${base}${path}`)

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
beforeEach(() => server.resetHandlers(...createTerminalRegistrationHandlers()))
afterAll(() => server.close())

it('filters the ledger and independent count by the same search, type, state and ownership', async () => {
  const query = '?search=教学楼&type=access_point&status=registered&ownership_class=infrastructure'
  const page = await (await get(`/endpoints/registrations${query}`)).json() as Page
  const metadata = await (await get(`/endpoints/registrations/metadata${query}`)).json()
  expect(page.items).toHaveLength(1)
  expect(page.items[0].registration_details.name).toBe('教学楼二层无线 AP')
  expect(metadata.total).toBe(1)
  expect(page).not.toHaveProperty('total')
  const noMatch = await (await get('/endpoints/registrations?type=camera&status=registered')).json() as Page
  expect(noMatch.items).toEqual([])
  const exactMAC = await (await get('/endpoints/registrations?mac=02:20:40:00:00:03&limit=2')).json() as Page
  expect(exactMAC.items).toHaveLength(1)
  expect(exactMAC.items[0].registration_details.device_type).toBe('camera')
})

it('pages by a query-bound opaque cursor without duplicates and keeps metadata independent of the cursor', async () => {
  let cursor = ''
  const ids: string[] = []
  let firstCursor = ''
  do {
    const page = await (await get(`/endpoints/registrations?limit=1&cursor=${encodeURIComponent(cursor)}`)).json() as Page
    expect(page.items).toHaveLength(1)
    ids.push(page.items[0].endpoint_id)
    cursor = page.next_cursor
    firstCursor ||= cursor
    expect(page.has_more).toBe(Boolean(cursor))
  } while (cursor)
  expect(new Set(ids).size).toBe(3)
  const changedScope = await get(`/endpoints/registrations?status=registered&cursor=${encodeURIComponent(firstCursor)}`)
  expect(changedScope.status).toBe(400)
  const metadata = await (await get(`/endpoints/registrations/metadata?cursor=${encodeURIComponent(firstCursor)}`)).json()
  expect(metadata.total).toBe(3)
})

it('creates and edits an independent device without inventing a passive observation or duplicating it', async () => {
  const id = 'mac:02:20:40:00:00:04'
  const path = `/endpoints/${encodeURIComponent(id)}/registration`
  const create = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    registration_status: 'registered', merge_status: 'active', owner_account: 'demo-owner', ownership_class: 'school_asset',
    registration_details: { name: '新增演示打印机', device_type: 'printer', registered_ip: '192.0.2.40' },
  }) })
  expect(create.status).toBe(200)
  const saved = await create.json()
  expect(saved.last_seen).toBe('')
  expect(saved.attributes.manual_registration.registered_ip).toBe('192.0.2.40')
  const update = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    registration_status: 'retired', merge_status: 'active', ownership_class: 'school_asset', owner_account: 'demo-owner',
    registration_details: { name: '退役演示打印机', device_type: 'printer' },
  }) })
  expect(update.status).toBe(200)
  const page = await (await get('/endpoints/registrations?search=02:20:40:00:00:04&status=retired')).json() as Page
  expect(page.items).toHaveLength(1)
  expect(page.items[0].registration_details.name).toBe('退役演示打印机')
  expect(page.items[0].owner_account).toBe('demo-owner')
  expect(page.items[0].last_seen).toBe('')
  const metadata = await (await get('/endpoints/registrations/metadata')).json()
  expect(metadata.total).toBe(4)
})

it('rejects malformed paging and incomplete registered records rather than showing a false success', async () => {
  expect((await get('/endpoints/registrations?limit=0')).status).toBe(400)
  expect((await get('/endpoints/registrations?cursor=broken')).status).toBe(400)
  const response = await fetch(`${base}/endpoints/mac%3A02%3A20%3A40%3A00%3A00%3A04/registration`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ registration_status: 'registered', merge_status: 'active' }),
  })
  expect(response.status).toBe(400)
  expect((await response.json()).code).toBe('bad_endpoint_registration_request')
})
