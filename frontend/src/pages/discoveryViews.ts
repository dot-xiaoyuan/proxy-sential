export type DiscoveryView = { id: string; name: string; params: string }

export const discoveryViewsStorageKey = 'proxy-sentinel.discovery.views.v1'
const maxDiscoveryViews = 10

function validView(value: unknown): value is DiscoveryView {
  if (!value || typeof value !== 'object') return false
  const view = value as Record<string, unknown>
  return typeof view.id === 'string' && typeof view.name === 'string' && typeof view.params === 'string'
}

export function loadDiscoveryViews(storage: Pick<Storage, 'getItem'>): DiscoveryView[] {
  try {
    const raw = storage.getItem(discoveryViewsStorageKey)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter(validView) : []
  } catch {
    return []
  }
}

export function saveDiscoveryView(storage: Pick<Storage, 'getItem' | 'setItem'>, name: string, params: string): DiscoveryView[] {
  const trimmed = name.trim()
  const views = loadDiscoveryViews(storage)
  if (!trimmed) return views
  const view = { id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`, name: trimmed, params }
  const next = [view, ...views.filter(item => item.name !== trimmed)].slice(0, maxDiscoveryViews)
  try {
    storage.setItem(discoveryViewsStorageKey, JSON.stringify(next))
  } catch {
    return views
  }
  return next
}

export function removeDiscoveryView(storage: Pick<Storage, 'getItem' | 'setItem'>, id: string): DiscoveryView[] {
  const next = loadDiscoveryViews(storage).filter(item => item.id !== id)
  storage.setItem(discoveryViewsStorageKey, JSON.stringify(next))
  return next
}
