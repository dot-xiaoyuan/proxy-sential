import { HttpResponse } from 'msw'

/** A compact mock index. Metadata and positioning use exactly the list fixture. */
export function sharedPaginationMock<T>(url: URL, items: T[], maxLimit = 200, extra: Record<string, unknown> = {}) {
  const snapshot = url.searchParams.get('snapshot') || new Date().toISOString()
  const page = Number(url.searchParams.get('page') || 1)
  const limit = Number(url.searchParams.get('limit') || 20)
  if (!Number.isFinite(Date.parse(snapshot)) || !Number.isSafeInteger(page) || page < 1 || page > 1e9 || !Number.isSafeInteger(limit) || limit < 1 || limit > maxLimit) return HttpResponse.json({ message: '分页参数无效' }, { status: 400 })
  if (url.pathname.endsWith('/metadata')) return HttpResponse.json({ total: items.length, as_of: snapshot, snapshot })
  const cursorFor = (offset: number) => offset ? `mock-shared:${offset}` : ''
  if (url.pathname.endsWith('/position')) {
    const offset = (page - 1) * limit
    if (page > 1 && offset >= items.length) return HttpResponse.json({ message: '目标页不存在，请刷新' }, { status: 400 })
    return HttpResponse.json({ page, limit, cursor: cursorFor(offset), as_of: snapshot, snapshot })
  }
  const cursor = url.searchParams.get('cursor') || ''
  if (cursor && !/^mock-shared:\d+$/.test(cursor)) return HttpResponse.json({ message: '分页游标无效' }, { status: 400 })
  const offset = cursor ? Number(cursor.split(':')[1]) : 0
  return HttpResponse.json({ ...extra, items: items.slice(offset, offset + limit), next_cursor: offset + limit < items.length ? cursorFor(offset + limit) : '', snapshot })
}
