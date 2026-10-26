import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`IP menu entry and lookup at ${viewport.width}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.url().includes('/api/v1/') && response.status() >= 400) errors.push(`${response.status()} ${new URL(response.url()).pathname}`) })
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=ip')
    await expect(page.getByRole('heading', { name: '按 IP 查看流量观测' })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`ip-observation-empty-${viewport.width}.png`) })
    await page.getByRole('textbox', { name: 'IP 地址' }).fill('10.157.2.191')
    await page.getByRole('button', { name: '查询 IP' }).click()
    const panel = page.getByLabel('IP 流量观察', { exact: true })
    await expect(panel.getByText('本页 2 条观测摘要')).toBeVisible()
    await panel.getByRole('button', { name: '查看观测内容' }).first().click()
    await expect(panel.getByText('api.example.com', { exact: true })).toBeVisible()
    const probe = await page.evaluate(() => {
      const lookup = document.querySelector('.ip-observation-lookup')!
      const input = lookup.querySelector('.ip-observation-lookup-form .ant-input')!
      const button = lookup.querySelector('.ip-observation-lookup-form button')!
      const panel = document.querySelector('.ip-traffic-observations')!
      const card = panel.querySelector('.ip-traffic-card')!
      return {
        viewport: [innerWidth, innerHeight], documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        lookupOverflow: lookup.scrollWidth > lookup.clientWidth + 2, panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        cardOverflow: card.scrollWidth > card.clientWidth + 2, inputWidth: Math.round(input.getBoundingClientRect().width),
        buttonWhiteSpace: getComputedStyle(button).whiteSpace, buttonFlexShrink: getComputedStyle(button).flexShrink,
        padding: getComputedStyle(card).paddingLeft, border: getComputedStyle(card).borderTopColor,
      }
    })
    expect(probe.documentOverflow).toBe(false); expect(probe.lookupOverflow).toBe(false)
    expect(probe.panelOverflow).toBe(false); expect(probe.cardOverflow).toBe(false)
    expect(probe.inputWidth).toBeGreaterThan(200)
    expect(probe.buttonWhiteSpace).toBe('nowrap'); expect(probe.buttonFlexShrink).toBe('0')
    expect(probe.padding).toBe(viewport.width === 390 ? '14px' : '20px')
    expect(probe.border).toBe('rgb(226, 232, 240)')
    await writeFile(testInfo.outputPath('dom-style-probe.json'), JSON.stringify(probe, null, 2))
    await page.locator('.ip-observation-lookup-header').scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`ip-observation-entry-${viewport.width}.png`) })
    await panel.locator('.ip-traffic-detail').scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`ip-observation-detail-${viewport.width}.png`) })
    expect(errors).toEqual([])
  })
}
