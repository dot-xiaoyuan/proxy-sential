import { expect, it } from 'vitest'
import { isRandomizedMAC } from './mac'

it('detects locally administered MAC addresses', () => {
  expect(isRandomizedMAC('46:ea:12:8a:cd:07')).toBe(true)
  expect(isRandomizedMAC('02:20:40:00:00:03')).toBe(true)
  expect(isRandomizedMAC('aa:bb:cc:dd:ee:ff')).toBe(true)
  expect(isRandomizedMAC('00:11:22:33:44:55')).toBe(false)
  expect(isRandomizedMAC('f4:74:88:c7:ee:60')).toBe(false)
  expect(isRandomizedMAC('')).toBe(false)
  expect(isRandomizedMAC(undefined)).toBe(false)
})
