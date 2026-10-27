import { expect, test } from '@playwright/test'

test('recognition diagnostics remain readable at required viewports', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('response', response => {
    if (response.status() >= 400 && response.url().includes('/api/')) errors.push(`${response.status()} ${response.url()}`)
  })
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await page.goto('/devices/mac%3A00%3A1b%3A21%3A00%3A00%3A41?tab=recognition')
    await expect(page.getByText('可用信号事件')).toBeVisible()
    await expect(page.getByText('dhcp-demo-41', { exact: false })).toBeVisible()
    const probe = await page.evaluate(() => ({
      documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
      longFieldOverflow: [...document.querySelectorAll('.fingerprint-ident')].some(node => node.scrollWidth > node.clientWidth + 2),
      compressedButtons: [...document.querySelectorAll('.ant-btn')].some(node => getComputedStyle(node).whiteSpace !== 'nowrap'),
    }))
    expect(probe).toEqual({ documentOverflow: false, longFieldOverflow: false, compressedButtons: false })
    await page.screenshot({ path: testInfo.outputPath(`recognition-${viewport.width}x${viewport.height}.png`), fullPage: true })
  }
  expect(errors).toEqual([])
})
