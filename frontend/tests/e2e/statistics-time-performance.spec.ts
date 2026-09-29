import { expect, test } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

for (const route of ['/', '/activity']) {
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    test(`statistics source time ${route} ${viewport.width}x${viewport.height}`, async ({ page }) => {
      await page.setViewportSize(viewport)
      await page.goto(route)
      await expect(page.locator('.statistics-time')).toContainText('数据统计于：')
      await page.waitForTimeout(700)
      const probe = await page.evaluate(() => {
        const label = document.querySelector('.statistics-time')!
        const stamp = label.querySelector('time')!
        const style = getComputedStyle(label)
        return {
          documentWidth: document.documentElement.scrollWidth,
          label: { width: label.clientWidth, scrollWidth: label.scrollWidth, fontSize: style.fontSize, color: style.color, flexWrap: style.flexWrap },
          stamp: { dateTime: stamp.dateTime, whiteSpace: getComputedStyle(stamp).whiteSpace, flexShrink: getComputedStyle(stamp).flexShrink },
          buttons: [...document.querySelectorAll('.ant-btn')].map(el => ({ whiteSpace: getComputedStyle(el).whiteSpace, flexShrink: getComputedStyle(el).flexShrink })),
        }
      })
      expect(probe.documentWidth).toBeLessThanOrEqual(viewport.width + 2)
      expect(probe.label.scrollWidth).toBeLessThanOrEqual(probe.label.width + 2)
      expect(probe.label.flexWrap).toBe('wrap')
      expect(probe.label.fontSize).toBe('12px')
      expect(probe.label.color).toBe('rgb(100, 116, 139)')
      expect(probe.stamp.whiteSpace).toBe('nowrap')
      expect(probe.stamp.flexShrink).toBe('0')
      expect(Number.isNaN(Date.parse(probe.stamp.dateTime))).toBe(false)
      for (const button of probe.buttons) {
        expect(button.whiteSpace).toBe('nowrap')
        expect(button.flexShrink).toBe('0')
      }
      const directory = path.resolve('../artifacts/api-performance-fix-20260917/ui')
      fs.mkdirSync(directory, { recursive: true })
      const name = `statistics-${route === '/' ? 'overview' : 'activity'}-${viewport.width}x${viewport.height}`
      fs.writeFileSync(path.join(directory, `${name}-probe.json`), JSON.stringify(probe, null, 2))
      await page.screenshot({ path: path.join(directory, `${name}.png`) })
      const fullDirectory = path.resolve('../artifacts/api-performance-fix-20260918/ui')
      fs.mkdirSync(fullDirectory, { recursive: true })
      await page.screenshot({ path: path.join(fullDirectory, `${name}-full.png`), fullPage: true })
      if (await page.locator('.distribution-echart').count()) {
        await page.locator('.distribution-echart').first().screenshot({ path: path.join(fullDirectory, `${name}-chart.png`) })
      }
    })
  }
}
