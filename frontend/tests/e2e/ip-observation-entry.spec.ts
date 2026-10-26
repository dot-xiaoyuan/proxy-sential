import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`终端列表到详情的 IP 观测路径 ${viewport.width}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.url().includes('/api/v1/') && response.status() >= 400) errors.push(`${response.status()} ${new URL(response.url()).pathname}`) })
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=terminal&view=recent&window=24h&q=10.157.2.191')
    await expect(page.getByText('当前检索条件下没有终端身份结果')).toBeVisible()
    await expect(page.getByRole('link', { name: 'IP 流量观察' })).toHaveCount(0)
    const listPanel = page.getByLabel('IP 流量观察', { exact: true })
    await expect(listPanel.getByText('本页 2 条观测摘要')).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`terminal-ip-search-${viewport.width}.png`) })
    await listPanel.getByRole('button', { name: '查看观测内容' }).first().click()
    await expect(listPanel.getByText('api.miwifi.com', { exact: true })).toBeVisible()
    await expect(listPanel.getByText(/MiWiFi 服务访问/)).toBeVisible()
    await listPanel.getByRole('link', { name: '查看该 MAC 的终端详情' }).click()
    await expect(page.getByRole('heading', { name: '按 IP 核查流量观测' })).toBeVisible()
    await expect(page.getByText(/身份摘要中没有该 IP 的地址关联/)).toBeVisible()
    const detailPanel = page.getByLabel('IP 流量观察', { exact: true })
    await expect(detailPanel.getByText('本页 2 条观测摘要')).toBeVisible()
    const probe = await page.evaluate(() => {
      const lookup = document.querySelector('.endpoint-traffic-lookup')!
      const input = lookup.querySelector('.endpoint-traffic-lookup-form .ant-input')!
      const button = lookup.querySelector('.endpoint-traffic-lookup-form button')!
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
    await page.locator('.endpoint-traffic-lookup').scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`terminal-traffic-lookup-${viewport.width}.png`) })
    await detailPanel.getByRole('button', { name: '查看观测内容' }).first().click()
    await expect(detailPanel.getByText('api.miwifi.com', { exact: true })).toBeVisible()
    await detailPanel.locator('.ip-traffic-detail').scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`terminal-traffic-detail-${viewport.width}.png`) })
    expect(errors).toEqual([])
  })
}
