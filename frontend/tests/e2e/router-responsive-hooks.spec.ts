import { expect, test } from '@playwright/test'

test('路由器列表跨断点缩放时保持渲染且不报 Hook 错误', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/devices?tab=network')
  await expect(page.locator('.router-observations-panel')).toBeVisible()
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await expect(page.locator('.router-observations-panel')).toBeVisible()
    await expect(page.locator('.router-observations-panel .ant-table-row').first()).toBeVisible()
    await page.screenshot({ path: `/tmp/proxy-sentinel-router-responsive-${viewport.width}.png` })
  }
  expect(errors).toEqual([])
})
