import { expect, test } from '@playwright/test'

const viewports = [
  { width: 390, height: 844 },
  { width: 1280, height: 800 },
  { width: 1440, height: 900 },
]

test.describe('运营工作台布局与运行负载', () => {
  for (const viewport of viewports) {
    test(`${viewport.width}x${viewport.height} 保持紧凑且无横向溢出`, async ({
      page,
    }, testInfo) => {
      await page.setViewportSize(viewport)
      await page.goto('/overview')

      await expect(page.getByRole('heading', { name: '运营工作台', level: 1 })).toBeVisible()
      await expect(page.getByText('观察期 · 仅记录未执行')).toBeVisible()
      await expect(page.getByRole('heading', { name: '服务器资源' })).toBeVisible()
      await expect(page.getByRole('heading', { name: '服务运行态' })).toBeVisible()
      await expect(page.getByRole('heading', { name: '核心组件健康' })).toBeVisible()

      const audit = await page.evaluate(() => {
        const selectors = [
          '.page',
          '.overview-runtime-grid',
          '.overview-focus-grid',
          '.overview-detail-grid',
          '.overview-panel',
        ]
        const internalOverflows: string[] = []
        selectors.forEach((selector) => {
          document.querySelectorAll(selector).forEach((element, index) => {
            const style = window.getComputedStyle(element)
            const scrollable = ['auto', 'scroll'].includes(style.overflowX)
            if (!scrollable && element.scrollWidth > element.clientWidth + 2) {
              internalOverflows.push(
                `${selector}[${index}] ${element.scrollWidth}>${element.clientWidth}`,
              )
            }
          })
        })
        return {
          documentOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
          internalOverflows,
          runtimeColumns: window
            .getComputedStyle(document.querySelector('.overview-runtime-grid')!)
            .gridTemplateColumns.split(' ').length,
        }
      })

      expect(audit.documentOverflow).toBe(false)
      expect(audit.internalOverflows).toEqual([])
      expect(audit.runtimeColumns).toBe(viewport.width <= 560 ? 1 : 3)

      await page.screenshot({
        path: testInfo.outputPath(`overview-${viewport.width}x${viewport.height}.png`),
        fullPage: true,
      })
    })
  }
})
