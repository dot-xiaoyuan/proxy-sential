import { expect, test } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) {
  test(`historical shared correction stays readable at ${width}`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', item => { if (item.type() === 'error') errors.push(item.text()) })
    page.on('pageerror', error => errors.push(error.message))
    page.on('requestfailed', request => errors.push(`${request.url()}: ${request.failure()?.errorText}`))
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize({ width, height })
    await page.addInitScript(() => {
      const original = window.fetch
      window.fetch = async (...args) => {
        const response = await original(...args)
        const url = args[0] instanceof Request ? args[0].url : String(args[0])
        if (!/\/api\/v1\/(actions|policy-decisions)\?/.test(url) || !response.ok) return response
        const body = await response.clone().json() as { items?: Record<string, unknown>[] }
        if (!body.items?.length) return response
        body.items[0] = {
          ...body.items[0],
          evidence_review_status: 'insufficient_evidence',
          evidence_review_reason: 'strong_anchor_missing',
        }
        return new Response(JSON.stringify(body), { status: response.status, headers: { 'Content-Type': 'application/json' } })
      }
    })
    const dir = path.resolve('test-results/shared-correction-layout')
    await mkdir(dir, { recursive: true })
    const audit = async (tab: string) => {
      const probe = await page.evaluate(() => {
        const root = document.querySelector('.action-records-page')!
        const selected = root.querySelector('.ant-tabs-tab-active .ant-tabs-tab-btn')!
        const selectedBackground = getComputedStyle(selected.parentElement!).backgroundColor
        const color = (value: string) => (value.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(v => {
          const unit = v / 255
          return unit <= 0.04045 ? unit / 12.92 : ((unit + 0.055) / 1.055) ** 2.4
        })
        const luminance = (value: string) => {
          const [red, green, blue] = color(value)
          return .2126 * red + .7152 * green + .0722 * blue
        }
        const foreground = luminance(getComputedStyle(selected).color)
        const background = luminance(selectedBackground === 'rgba(0, 0, 0, 0)' ? 'rgb(248, 250, 252)' : selectedBackground)
        return {
          documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
          tableOverflow: [...root.querySelectorAll('.compact-list-table')].some(item => item.scrollWidth > item.clientWidth + 2),
          rowDisplay: getComputedStyle(root.querySelector('.ant-table-row')!).display,
          compressedControls: [...root.querySelectorAll('.ant-btn,.ant-tag')].filter(item => {
            const style = getComputedStyle(item)
            return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
          }).map(item => item.textContent),
          selectedContrast: (Math.max(foreground, background) + .05) / (Math.min(foreground, background) + .05),
        }
      })
      expect(probe.documentOverflow).toBe(false)
      expect(probe.tableOverflow).toBe(false)
      expect(probe.compressedControls).toEqual([])
      expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
      if (width === 390) expect(probe.rowDisplay).toBe('block')
      await writeFile(path.join(dir, `${tab}-${width}.json`), JSON.stringify(probe, null, 2))
      await page.screenshot({ path: path.join(dir, `${tab}-${width}.png`), fullPage: true, animations: 'disabled' })
    }
    await page.goto('/actions?tab=actions')
    await expect(page.getByText('旧规则证据不足')).toBeVisible()
    await audit('actions')
    await page.getByRole('tab', { name: '策略执行' }).click()
    await expect(page.getByText('旧规则记录：共享证据不足')).toBeVisible()
    await expect(page.getByText('已确认共享')).toHaveCount(0)
    await audit('decisions')
    expect(errors).toEqual([])
  })
}
