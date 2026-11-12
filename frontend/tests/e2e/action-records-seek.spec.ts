import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) {
  test(`record tabs use cursor pages at ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    const errors: string[] = []
    const listRequests: string[] = []
    page.on('console', entry => { if (entry.type() === 'error') errors.push(entry.text()) })
    page.on('pageerror', error => errors.push(error.message))
    page.on('requestfailed', request => errors.push(`${request.url()}: ${request.failure()?.errorText}`))
    page.on('request', request => {
      if (/\/api\/v1\/(actions|behavior-reports\/outbox)\?/.test(request.url())) listRequests.push(request.url())
    })
    await page.goto('/actions?tab=actions')
    await expect(page.getByRole('heading', { name: '处置动作记录' })).toBeVisible()
    await expect(page.getByText('第 1 页')).toBeVisible()
    const dir = path.resolve('test-results/action-records-seek')
    await mkdir(dir, { recursive: true })
    const audit = async (tab: string) => {
      const probe = await page.evaluate(() => ({
        overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 2,
        compressed: [...document.querySelectorAll('.action-records-page .ant-btn,.action-records-page .ant-tag')].filter(element => {
          const style = getComputedStyle(element)
          return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
        }).map(element => element.textContent),
      }))
      expect(probe.overflow).toBe(false)
      expect(probe.compressed).toEqual([])
      await writeFile(path.join(dir, `dom-${tab}-${width}.json`), JSON.stringify(probe, null, 2))
      await page.screenshot({ path: path.join(dir, `${tab}-${width}.png`), fullPage: true, animations: 'disabled' })
    }
    await audit('actions')
    await page.getByRole('tab', { name: '上报记录' }).click()
    await expect(page.getByRole('heading', { name: '上报记录' })).toBeVisible()
    await expect(page.getByText('第 1 页')).toBeVisible()
    expect(listRequests.some(value => value.includes('/actions?') && value.includes('seek=1'))).toBe(true)
    expect(listRequests.some(value => value.includes('/behavior-reports/outbox?') && value.includes('seek=1'))).toBe(true)
    await audit('reports')
    expect(errors).toEqual([])
  })
}
