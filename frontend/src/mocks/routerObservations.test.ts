import { afterAll, beforeAll, expect, it } from 'vitest'
import { setupServer } from 'msw/node'
import { routerObservationHandlers, routerObservations } from './routerObservations'

const server = setupServer(...routerObservationHandlers)
const base = new URL('/api/v1/router-observations', window.location.href).href
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())

it('uses an opaque seek cursor and explicitly ends the final page', async () => {
  const first = await (await fetch(`${base}?role=router&limit=1`)).json()
  expect(first.items.map((item: { assessment_id: string }) => item.assessment_id)).toEqual([
    'router-huawei-ar-001',
  ])
  expect(first.page).toMatchObject({ limit: 1, total: 0, has_more: true })
  expect(first.page.next_cursor).toMatch(/^router-seek:/)
  const second = await (
    await fetch(`${base}?role=router&limit=50&cursor=${encodeURIComponent(first.page.next_cursor)}`)
  ).json()
  expect(second.items.map((item: { assessment_id: string }) => item.assessment_id)).toEqual([
    'router-h3c-msr-002',
  ])
  expect(second.page).toMatchObject({ limit: 50, total: 0, has_more: false, next_cursor: null })
  expect(
    (await fetch(`${base}?role=ap&cursor=${encodeURIComponent(first.page.next_cursor)}`)).status,
  ).toBe(400)
  expect((await fetch(`${base}?role=router&cursor=1`)).status).toBe(400)
})

it('keeps the default router filter when no role or authentication filter is selected', async () => {
  const page = await (await fetch(base)).json()
  const clearedAuth = await (await fetch(`${base}?has_auth_binding=false`)).json()
  expect(page.items.map((item: { assessment_id: string }) => item.assessment_id)).toEqual([
    'router-huawei-ar-001',
    'router-h3c-msr-002',
  ])
  expect(clearedAuth.items.map((item: { assessment_id: string }) => item.assessment_id)).toEqual(
    page.items.map((item: { assessment_id: string }) => item.assessment_id),
  )
})

it('keeps the strongest assessment for one physical MAC across pages', async () => {
  routerObservations.push({
    ...routerObservations[0],
    assessment_id: 'router-duplicate-likely',
    status: 'likely',
    confidence: 99,
  })
  try {
    const first = await (await fetch(`${base}?role=router&limit=1`)).json()
    const second = await (
      await fetch(
        `${base}?role=router&limit=1&cursor=${encodeURIComponent(first.page.next_cursor)}`,
      )
    ).json()
    expect(first.items.map((item: { assessment_id: string }) => item.assessment_id)).toEqual([
      'router-huawei-ar-001',
    ])
    expect(second.items.map((item: { assessment_id: string }) => item.assessment_id)).toEqual([
      'router-h3c-msr-002',
    ])
    expect(second.page.has_more).toBe(false)
  } finally {
    routerObservations.pop()
  }
})
