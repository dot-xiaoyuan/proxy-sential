import { describe, expect, it } from 'vitest'
import { formatDeviceName } from './sharedDeviceProfileFormat'

describe('formatDeviceName', () => {
  it('does not repeat a brand already included in the model', () => {
    expect(formatDeviceName('Huawei', 'Huawei AP-AP4050DE')).toBe('Huawei AP-AP4050DE')
    expect(formatDeviceName('Huawei', 'HUAWEI AirEngine5762')).toBe('HUAWEI AirEngine5762')
  })

  it('keeps a distinct brand and model combination', () => {
    expect(formatDeviceName('H3C', 'MSR860')).toBe('H3C MSR860')
  })

  it('uses the available identity value as fallback', () => {
    expect(formatDeviceName('', '', '192.0.2.22')).toBe('192.0.2.22')
  })
})
