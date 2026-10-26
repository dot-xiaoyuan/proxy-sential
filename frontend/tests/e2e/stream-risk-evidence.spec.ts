import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`current stream risk evidence stays readable at ${viewport.width}x${viewport.height}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.url().includes('/risks/stream-') && response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.goto('/cases')
    await page.locator('summary').filter({ hasText: '新流风险结果' }).click()
    const evidenceButton = page.getByRole('button', { name: '查看证据 1' })
    await expect(evidenceButton).toBeVisible()
    await evidenceButton.click()
    await expect(page.locator('.stream-risk-evidence-json')).toContainText('evidence-ua-59')
    const probe = await page.evaluate(() => {
      const button = document.querySelector('.stream-risk-card-evidence .ant-btn')!
      const style = getComputedStyle(button)
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        buttonWhiteSpace: style.whiteSpace,
        buttonFlexShrink: style.flexShrink,
        cardOverflow: [...document.querySelectorAll('.stream-risk-card')].some(card => card.scrollWidth > card.clientWidth + 2),
        evidenceOverflow: document.querySelector('.stream-risk-evidence-json')!.scrollWidth > document.querySelector('.stream-risk-evidence-json')!.clientWidth + 2,
      }
    })
    expect(probe).toEqual({ documentOverflow: false, buttonWhiteSpace: 'nowrap', buttonFlexShrink: '0', cardOverflow: false, evidenceOverflow: false })
    expect(errors).toEqual([])
    await page.screenshot({ path: testInfo.outputPath(`stream-risk-evidence-${viewport.width}.png`), fullPage: true })
  })
}
