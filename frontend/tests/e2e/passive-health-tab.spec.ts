import { expect, test } from '@playwright/test'

const viewports = [
  { name: '390', width: 390, height: 844 },
  { name: '1280', width: 1280, height: 800 },
  { name: '1440', width: 1440, height: 900 },
]

for (const vp of viewports) {
  test(`passive health tab layout and zero errors at ${vp.name}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text())
    })
    page.on('response', (res) => {
      if (res.status() >= 400 && !res.url().includes('/auth/')) {
        errors.push(`${res.status()} ${res.url()}`)
      }
    })

    await page.setViewportSize({ width: vp.width, height: vp.height })
    await page.goto('/ingest?diagnostic_tab=health', { waitUntil: 'networkidle' })

    const panel = page.getByLabel('系统健康与容量看板')
    await expect(panel).toBeVisible()
    await expect(panel.getByText('数据盘使用率')).toBeVisible()
    await expect(panel.getByText('proxy-sentinel-zeek-log-prune.timer')).toBeVisible()
    await expect(panel.getByText('capwap')).toBeVisible()

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow).toBeLessThanOrEqual(2)
    expect(errors).toEqual([])
  })
}
