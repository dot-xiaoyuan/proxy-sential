import { expect, test } from '@playwright/test'

test('SADP discovery presentation remains readable at three viewports', async ({ page }) => {
  const consoleErrors: string[] = []
  const networkErrors: string[] = []
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()) })
  page.on('response', response => { if (response.status() >= 400) networkErrors.push(`${response.status()} ${response.url()}`) })
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await page.goto('/discovery', { waitUntil: 'domcontentloaded' })
    await expect(page.getByRole('heading', { name: '发现设备', level: 1 })).toBeVisible()
    await expect(page.locator('.passive-ledger-table')).toBeVisible()
    await page.screenshot({ path: `test-results/discovery-sadp-${viewport.width}x${viewport.height}.png`, fullPage: true })
    const probe = await page.evaluate(() => {
      const table = document.querySelector('.passive-ledger-table') as HTMLElement
      const buttons = [...document.querySelectorAll('.passive-ledger-table .ant-btn')]
      return {
        pageOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        tableOverflow: table.scrollWidth > table.clientWidth + 2,
        compressedButtons: buttons.filter(button => getComputedStyle(button).whiteSpace !== 'nowrap').length,
        tableDisplay: getComputedStyle(table).display,
      }
    })
    expect(probe.pageOverflow).toBe(false)
    expect(probe.tableOverflow).toBe(false)
    expect(probe.compressedButtons).toBe(0)
  }
  expect(consoleErrors).toEqual([])
  expect(networkErrors).toEqual([])
})
