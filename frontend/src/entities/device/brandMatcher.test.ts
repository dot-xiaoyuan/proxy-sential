import { describe, expect, it } from 'vitest'
import { resolveDeviceBrand } from './brandMatcher'
import { brandIconPaths } from './brandIcons'

describe('brand presentation does not introduce recognition claims', () => {
  it('keeps independent brands distinct and handles aliases', () => {
    for (const [brand, key] of [['Honor', 'honor'], ['荣耀', 'honor'], ['Huawei', 'huawei'], ['OPPO', 'oppo'], ['vivo', 'vivo'], ['realme', 'realme'], ['Redmi', 'xiaomi'], ['TP-Link', 'tplink'], ['HP Inc.', 'hp']]) {
      expect(resolveDeviceBrand({ brand }).key).toBe(key)
      expect(brandIconPaths[key].length).toBeGreaterThan(0)
    }
  })
  it('does not infer a hardware brand from an OS or endpoint text', () => {
    expect(resolveDeviceBrand({ vendor: 'Dell Inc.' }).key).toBe('unknown')
    expect(resolveDeviceBrand({ vendor: 'Apple, Inc.' }).key).toBe('unknown')
    expect(resolveDeviceBrand({ brand: 'Dell', summary: 'Windows' }).key).toBe('dell')
    expect(resolveDeviceBrand({ summary: 'Windows iOS', endpoint_id: 'apple-laptop', model: 'MacBook' }).key).toBe('unknown')
    expect(resolveDeviceBrand({ brand: 'Unlisted manufacturer' }).name).toBe('Unlisted manufacturer')
  })
})
