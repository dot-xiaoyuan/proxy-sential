import { expect, test } from '@playwright/test'

test('historical DHCP clues remain visibly historical across ledger layouts', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('response', response => {
    if (response.status() >= 400 && new URL(response.url()).pathname.startsWith('/discovery/')) {
      errors.push(`${response.status()} ${response.url()}`)
    }
  })
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=discovery')
    const row = page.locator('.passive-ledger-table').getByRole('row').filter({ hasText: '00:11:22:33:44:77' })
    await expect(row.getByText('Windows · 历史线索')).toBeVisible()
    const layout = await page.evaluate(() => {
      const table = document.querySelector('.passive-ledger-table')
      const row = [...document.querySelectorAll('.passive-ledger-table .ant-table-row')].find(item => item.textContent?.includes('00:11:22:33:44:77'))
      const label = row?.querySelector('[title*="历史 DHCP REQUEST"]')
      return {
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        rowDisplay: row ? getComputedStyle(row).display : '',
        labelClipped: label ? label.scrollWidth > label.clientWidth + 2 : true,
        compressedActions: [...document.querySelectorAll('.passive-discovery-panel .ant-btn')]
          .some(button => getComputedStyle(button).whiteSpace !== 'nowrap'),
      }
    })
    expect(layout.overflow).toBe(false)
    expect(layout.labelClipped).toBe(false)
    expect(layout.compressedActions).toBe(false)
    if (viewport.width < 560) expect(layout.rowDisplay).not.toBe('table-row')
    await row.scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`historical-dhcp-${viewport.width}.png`), fullPage: true })
    await row.getByRole('button', { name: '查看证据' }).click()
    await expect(page.getByText('历史 REQUEST 线索；同源当前租约仍有效，需结合观测时间核对')).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`historical-dhcp-detail-${viewport.width}.png`), fullPage: true })
  }
  expect(errors).toEqual([])
})
