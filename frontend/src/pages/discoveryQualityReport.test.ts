import { expect, it } from 'vitest'
import { qualityReportCSV } from './discoveryQualityReport'

it('exports the quality report with coverage, tops, and trend', () => {
  const csv = qualityReportCSV({
    total_endpoints: 10,
    coverage: { device_type: { known: 4, rate: 0.4 }, brand: { known: 1, rate: 0.1 }, model: { known: 1, rate: 0.1 }, os_family: { known: 5, rate: 0.5 } },
    mac_attribution_rate: 0.5,
    event_attribution_rate: 0,
    top_brands: [{ brand: 'Huawei', count: 3 }],
    top_type_brands: [{ device_type: 'camera', brand: 'Hikvision', count: 2 }],
    top_models: [{ model: 'LaserJet Pro MFP', brand: 'HP', count: 1 }],
    top_os: [{ os: 'Apple OS', count: 2 }],
    untyped_reasons: [{ reason: 'Apple 系统线索', count: 2 }],
  } as never, { days: [{ date: '2026-11-10', new: 2, typed: 1 }], top_types: [{ device_type: 'camera', count: 1 }], window_days: 7 } as never, { camera: '摄像机' })
  expect(csv).toContain('识别质量报告')
  expect(csv).toContain('全局识别画像，不随列表筛选变化')
  expect(csv).toContain('类型覆盖,4,10,40%')
  expect(csv).toContain('摄像机 · Hikvision,2')
  expect(csv).toContain('HP · LaserJet Pro MFP,1')
  expect(csv).toContain('Apple OS,2')
  expect(csv).toContain('2026-11-10,2,1')
  expect(csv).toContain('新增类型,数量')
  expect(csv).toContain('摄像机,1')
  expect(csv).toContain('趋势范围,近 7 天')
})
