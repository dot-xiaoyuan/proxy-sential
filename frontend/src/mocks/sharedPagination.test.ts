import { expect, it } from 'vitest'
import { sharedPaginationMock } from './sharedPagination'

it('keeps metadata, target-page boundaries and page rows consistent', async () => {
  const rows = [{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }]
  const snapshot = '2026-11-06T00:00:00Z'
  const base = `http://localhost/shared-access/reviews?snapshot=${snapshot}`
  expect(await sharedPaginationMock(new URL(base.replace('reviews?', 'reviews/metadata?')), rows).json()).toMatchObject({ total: 4, snapshot })
  const position = await sharedPaginationMock(new URL(base.replace('reviews?', 'reviews/position?') + '&page=2&limit=2'), rows).json() as { cursor: string }
  expect(await sharedPaginationMock(new URL(base + '&limit=2&cursor=' + encodeURIComponent(position.cursor)), rows).json()).toMatchObject({ items: [{ id: 'c' }, { id: 'd' }], next_cursor: '', snapshot })
  expect(sharedPaginationMock(new URL(base.replace('reviews?', 'reviews/position?') + '&page=3&limit=2'), rows).status).toBe(400)
})

it('keeps an empty first page available and rejects invalid or over-limit requests', async () => {
  expect(await sharedPaginationMock(new URL('http://localhost/reviews/position'), []).json()).toMatchObject({ page: 1, limit: 20, cursor: '' })
  expect(sharedPaginationMock(new URL('http://localhost/reviews/position?page=2'), []).status).toBe(400)
  expect(sharedPaginationMock(new URL('http://localhost/reviews/position?limit=101'), [], 100).status).toBe(400)
  expect(sharedPaginationMock(new URL('http://localhost/reviews/metadata?snapshot=invalid'), []).status).toBe(400)
})
