import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

const viewports = [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]

for (const viewport of viewports) {
  test(`link-layer attribution diagnostics ${viewport.width}x${viewport.height}`, async ({ page }, info) => {
    await page.setViewportSize(viewport)
    await page.goto('/devices?view=history')
    await page.getByText('识别质量与接入诊断', { exact: true }).click()
    await expect(page.locator('.recognition-coverage-strip')).toBeVisible()
    await expect(page.locator('.device-attribution-summary')).toContainText('链路层归属')
    await expect(page.locator('.device-attribution-summary')).toContainText('285518 / 3795418 事件带 MAC')
    const rows = page.getByRole('list', { name: '按来源可见性' }).locator('> li')
    await expect(rows).toHaveCount(9)
    await expect(rows.filter({ hasText: 'ieee1905_topology' })).toContainText('12006 带 MAC')
    await expect(rows.filter({ hasText: 'mdns' })).toContainText('0 带 MAC')
    await expect(rows.filter({ hasText: 'ssdp' })).toContainText('268744 带 MAC')

    const probe = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > window.innerWidth + 2,
      attribution: [...document.querySelectorAll('.device-attribution-summary > *')].map(node => getComputedStyle(node).whiteSpace),
      sources: [...document.querySelectorAll('.device-observability-source')].map(node => getComputedStyle(node).overflowWrap),
      numbers: [...document.querySelectorAll('.device-observability-list > li > .ant-typography')]
        .filter(node => !node.classList.contains('device-observability-source'))
        .map(node => getComputedStyle(node).whiteSpace),
      controls: [...document.querySelectorAll('.device-diagnostics .ant-btn,.device-diagnostics .ant-tag')]
        .map(node => ({ wrap: getComputedStyle(node).whiteSpace, shrink: getComputedStyle(node).flexShrink })),
      radius: getComputedStyle(document.querySelector('.device-observability-list > li')!).borderRadius,
    }))
    expect(probe.overflow).toBe(false)
    expect(probe.attribution.every(value => value === 'nowrap')).toBe(true)
    expect(probe.sources.every(value => value === 'anywhere')).toBe(true)
    expect(probe.numbers.length).toBeGreaterThan(0)
    expect(probe.numbers.every(value => value === 'nowrap')).toBe(true)
    expect(probe.controls.every(control => control.wrap === 'nowrap' && control.shrink === '0')).toBe(true)
    expect(probe.radius).toBe('8px')
    await writeFile(info.outputPath('dom.json'), JSON.stringify(probe, null, 2))
    await page.locator('.device-diagnostics').scrollIntoViewIfNeeded()
    await page.locator('.recognition-summary-surface').screenshot({ path: info.outputPath('diagnostics-panel.png') })
    await page.screenshot({ path: info.outputPath('diagnostics.png') })
  })
}
