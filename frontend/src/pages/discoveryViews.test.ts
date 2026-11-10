import { expect, it } from 'vitest'
import { discoveryViewsStorageKey, loadDiscoveryViews, removeDiscoveryView, saveDiscoveryView } from './discoveryViews'

function fakeStorage() {
  const values = new Map<string, string>()
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value) },
  }
}

it('saves, replaces, and removes discovery views', () => {
  const storage = fakeStorage()
  expect(loadDiscoveryViews(storage)).toEqual([])
  const first = saveDiscoveryView(storage, '  网络设备  ', 'discovery_type=access_point')
  expect(first).toHaveLength(1)
  expect(first[0].name).toBe('网络设备')
  const second = saveDiscoveryView(storage, '网络设备', 'discovery_category=network')
  expect(second).toHaveLength(1)
  expect(second[0].params).toBe('discovery_category=network')
  const third = saveDiscoveryView(storage, '打印机', 'discovery_type=printer')
  expect(third).toHaveLength(2)
  expect(removeDiscoveryView(storage, third[0].id)).toHaveLength(1)
  expect(JSON.parse(storage.getItem(discoveryViewsStorageKey) ?? '[]')).toHaveLength(1)
})

it('ignores malformed storage and empty names', () => {
  const storage = fakeStorage()
  storage.setItem(discoveryViewsStorageKey, 'not-json')
  expect(loadDiscoveryViews(storage)).toEqual([])
  expect(saveDiscoveryView(storage, '   ', 'x=1')).toEqual([])
})
