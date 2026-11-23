import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`shows the scoped SNI brand clue with its source evidence at ${viewport.width}px`, async ({ page }, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=discovery&discovery_search=192.0.2.31')
    await page.getByRole('button', { name: '查看详情' }).filter({ visible: true }).first().click()
    const dialog = page.getByRole('dialog')
    const behavior = dialog.getByRole('region', { name: '被动流量行为线索' })
    await expect(behavior.getByText('品牌线索 · Hikvision（SNI）')).toBeVisible()
    await behavior.getByText('查看行为证据（3）').click()
    await expect(behavior.getByText('dev.hik-connect.com', { exact: true }).first()).toBeVisible()
    await expect(behavior.getByText(/fixture-tls-evidence-0/)).toBeVisible()
    const layout = await behavior.evaluate(section => ({
      pageOverflow: document.documentElement.scrollWidth > innerWidth + 2,
      evidenceOverflow: [section, ...section.querySelectorAll('article, article span, summary')].some(element =>
        element.scrollWidth > element.clientWidth + 2 && getComputedStyle(element).display !== 'inline'),
      clipped: section.getBoundingClientRect().right > innerWidth + 2,
      controls: [...section.closest('[role=dialog]')!.querySelectorAll('button')].filter(element => element.getClientRects().length && element.textContent?.trim()).every(element => {
        const style = getComputedStyle(element)
        return style.whiteSpace === 'nowrap' && style.flexShrink === '0'
      }),
    }))
    expect(layout).toEqual({ pageOverflow: false, evidenceOverflow: false, clipped: false, controls: true })
    await behavior.screenshot({ path: info.outputPath(`discovery-sni-brand-${viewport.width}.png`), animations: 'disabled' })
    expect(errors).toEqual([])
  })
}
