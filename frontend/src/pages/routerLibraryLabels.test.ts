import { describe, expect, it } from 'vitest'
import { routerLibraryLabels } from './routerLabels'

describe('router library labels', () => {
  it('names every open-source library as a secondary "命中" label', () => {
    for (const [id, label] of Object.entries(routerLibraryLabels)) {
      expect(label, id).toMatch(/命中$/)
      expect(label, id).not.toMatch(/未识别|未获取|未关联|未观测/)
    }
  })

  it('covers the libraries the router pipeline can emit', () => {
    expect(Object.keys(routerLibraryLabels)).toEqual(expect.arrayContaining(['recog', 'satori', 'whatweb', 'librenms', 'openwrt']))
  })
})
