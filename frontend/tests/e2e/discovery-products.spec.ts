import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

test('IP product evidence stays separate from physical confirmation at three viewports', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
  await page.goto('/discovery')
  await expect(page.locator('.passive-ledger-table')).toBeVisible()
  await page.evaluate(async () => { const path = '/src/mocks/hardwareReplay.ts'; const fixture = await import(path); fixture.installHardwareReplay() })
  await page.getByRole('button', { name: '刷新数据' }).click()
  await expect(page.getByLabel('发现设备总览')).toContainText('已确认硬件类型（合计 2）')
  await page.getByRole('button', { name: '统计与类型线索' }).click()
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await page.getByLabel('IP 产品类型线索').scrollIntoViewIfNeeded()
    await expect(page.getByLabel('IP 产品类型线索')).toContainText('不计入确认硬件')
    await page.screenshot({path:`test-results/product-counts-${viewport.width}.png`,animations:'disabled'})
    const row = page.locator('.passive-ledger-table').getByRole('row').filter({hasText:'192.0.2.40'}).getByRole('button', { name: '地址线索', exact: true })
    await row.scrollIntoViewIfNeeded()
    await expect(row).toBeInViewport()
    await page.screenshot({ path: `test-results/product-list-${viewport.width}.png`, animations: 'disabled' })
    await row.click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.getByLabel('IP 产品证据')).toContainText('S2910-24GT4SFP-UP-H')
    await expect(dialog.getByLabel('IP 产品证据')).toContainText('VLAN 4005')
    await expect(dialog.getByLabel('IP 产品证据')).toContainText('snmp-product-evidence')
    const typeSummary = dialog.getByRole('region', {name:'设备类型'})
    await expect(typeSummary.getByText('IP 自报产品 · 交换机')).toBeVisible()
    await expect(typeSummary.getByText(/仍需核实它对应的设备身份/)).toBeVisible()
    await page.screenshot({ path: `test-results/product-detail-${viewport.width}.png`, animations: 'disabled' })
    await dialog.getByLabel('IP 产品证据').locator('article').last().scrollIntoViewIfNeeded()
    await page.screenshot({ path: `test-results/product-sources-${viewport.width}.png`, animations: 'disabled' })
    const probe = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth + 2,
      typeFiltersWrap: [...document.querySelectorAll('.discovery-overview-types')].every(element => getComputedStyle(element).flexWrap === 'wrap'),
      productOverflow: [...document.querySelectorAll('.discovery-product-clues article')].some(element => element.scrollWidth > element.clientWidth + 2),
      badButtons: [...document.querySelectorAll('.ant-btn')].filter(button => { const style = getComputedStyle(button); return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0' }).length,
    }))
    await writeFile(`test-results/product-${viewport.width}.dom.json`, JSON.stringify(probe, null, 2))
    expect(probe).toEqual({ overflow: false, typeFiltersWrap: true, productOverflow: false, badButtons: 0 })
    await dialog.getByRole('button', { name: 'Close', exact: true }).click()
  }
  expect(errors).toEqual([])
})
