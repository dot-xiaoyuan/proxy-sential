import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`brand inference evidence and design audit ${viewport.width}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('response', response => { if (response.status() >= 500) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.goto('/devices?view=history')
    await expect(page.locator('.device-inventory-surface .ant-table')).toBeVisible()
    await expect(page.locator('.device-inventory-surface tr').filter({ hasText: '198.18.90.8' })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`devices-${viewport.width}.png`), fullPage: false })
    if (viewport.width < 560) {
      await expect(page.locator('.device-inventory-surface .ant-table')).toBeVisible()
    }
    await page.goto('/devices/mac%3A02%3A00%3A00%3A00%3A90%3A08')
    await page.getByRole('tab', { name: '终端识别', exact: true }).click()
    await expect(page.getByRole('heading', { name: '推测品牌与依据' })).toBeVisible()
    await expect(page.locator('.brand-inference-details')).toContainText('最近证据')
    await expect(page.locator('.brand-inference-details').getByText('albert.apple.com', { exact: true }).first()).toBeVisible()
    await expect(page.locator('.brand-inference-details').getByText('推测 Apple', { exact: true })).toBeVisible()
    await page.locator('.brand-evidence-list > li').first().scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`evidence-${viewport.width}.png`), fullPage: false })
    const probe = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth + 2,
      controls: Array.from(document.querySelectorAll('.ant-btn, .ant-tag')).filter(el => el.getClientRects().length).map(el => {
        const style = getComputedStyle(el); return { whiteSpace: style.whiteSpace, shrink: style.flexShrink }
      }),
      card: { radius: getComputedStyle(document.querySelector('.brand-evidence-list > li')!).borderRadius, padding: getComputedStyle(document.querySelector('.brand-evidence-list > li')!).padding, border: getComputedStyle(document.querySelector('.brand-evidence-list > li')!).borderColor },
      titleSize: getComputedStyle(document.querySelector('.brand-inference-details h4')!).fontSize,
    }))
    expect(probe.overflow).toBe(false)
    expect(probe.card.radius).toBe('8px')
    expect(probe.card.padding).toBe(viewport.width < 560 ? '14px' : '20px')
    expect(probe.card.border).toBe('rgb(226, 232, 240)')
    for (const control of probe.controls) { expect(control.whiteSpace).toBe('nowrap'); expect(control.shrink).toBe('0') }
    expect(parseFloat(probe.titleSize)).toBeGreaterThan(14)
    await testInfo.attach('dom-style-probe', { body: JSON.stringify(probe, null, 2), contentType: 'application/json' })
    await page.goto('/settings/rules')
    await page.getByRole('tab', { name: '设备特征库', exact: true }).click()
    await expect(page.getByText('域名来源明细', { exact: true })).toHaveCount(1)
    await page.screenshot({ path: testInfo.outputPath(`rules-${viewport.width}.png`), fullPage: false })
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2)).toBe(true)
    expect(errors).toEqual([])
  })
}
