import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`IP traffic observations remain readable at ${viewport.width}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.url().includes('/api/v1/') && response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.goto('/ips/10.255.0.59?tab=devices')
    const panel = page.getByLabel('IP 流量观察', { exact: true })
    await expect(panel.getByText('本页 2 条观测摘要')).toBeVisible()
    await panel.getByRole('button', { name: '查看观测内容' }).first().click()
    await expect(panel.getByText('api.example.com', { exact: true })).toBeVisible()
    const probe = await panel.evaluate(element => {
      const button = element.querySelector('button')!
      const card = element.querySelector('.ip-traffic-card')!
      const selectedTab = document.querySelector('[role=tab][aria-selected=true]')!
      const luminance = (color: string) => {
        const values = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(n => n / 255).map(n => n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4)
        return values[0] * .2126 + values[1] * .7152 + values[2] * .0722
      }
      let background = selectedTab as Element | null
      while (background && ['rgba(0, 0, 0, 0)', 'transparent'].includes(getComputedStyle(background).backgroundColor)) background = background.parentElement
      const fg = luminance(getComputedStyle(selectedTab).color), bg = luminance(background ? getComputedStyle(background).backgroundColor : 'rgb(255,255,255)')
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: element.scrollWidth > element.clientWidth + 2,
        cardOverflow: [...element.querySelectorAll('.ip-traffic-card')].some(node => node.scrollWidth > node.clientWidth + 2),
        buttonWhiteSpace: getComputedStyle(button).whiteSpace, buttonFlexShrink: getComputedStyle(button).flexShrink,
        padding: getComputedStyle(card).paddingLeft, border: getComputedStyle(card).borderTopColor,
        longValueWrap: getComputedStyle(element.querySelector('.ip-traffic-values li')!).overflowWrap,
        titleFont: getComputedStyle(element.querySelector('h4')!).fontSize,
        selectedTabColor: getComputedStyle(selectedTab).color, selectedTabBackground: getComputedStyle(selectedTab).backgroundColor,
        selectedTabContrast: (Math.max(fg, bg) + .05) / (Math.min(fg, bg) + .05),
      }
    })
    expect(probe.documentOverflow).toBe(false); expect(probe.panelOverflow).toBe(false); expect(probe.cardOverflow).toBe(false)
    expect(probe.buttonWhiteSpace).toBe('nowrap'); expect(probe.buttonFlexShrink).toBe('0')
    expect(probe.padding).toBe(viewport.width === 390 ? '14px' : '20px')
    expect(probe.border).toBe('rgb(226, 232, 240)'); expect(probe.longValueWrap).toBe('anywhere')
    expect(probe.selectedTabContrast).toBeGreaterThanOrEqual(4.5)
    await testInfo.attach('dom-style-probe', { body: JSON.stringify(probe, null, 2), contentType: 'application/json' })
    await writeFile(testInfo.outputPath('dom-style-probe.json'), JSON.stringify(probe, null, 2))
    await panel.evaluate(element => element.scrollIntoView({ block: 'start' }))
    await page.screenshot({ path: testInfo.outputPath(`ip-traffic-top-${viewport.width}.png`) })
    await panel.locator('.ip-traffic-raw').scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`ip-traffic-detail-${viewport.width}.png`) })
    await panel.getByRole('button', { name: '查看观测内容' }).last().click()
    await expect(panel.getByText('链路邻居归属尚未核实，TTL 仅作为路径观测。')).toBeVisible()
    expect(errors).toEqual([])
  })
}
