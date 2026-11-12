import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`event cursor and explicit count layout ${viewport.width}`, async ({ page }, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      ;(window as Window & { eventCountCalls?: number }).eventCountCalls = 0
      window.fetch = async (input, init) => {
        const raw = typeof input === 'string' ? input : input instanceof Request ? input.url : input.href
        const url = new URL(raw, location.origin)
        if (url.pathname.endsWith('/events/count')) {
          const browserWindow = window as Window & { eventCountCalls?: number }
          browserWindow.eventCountCalls = (browserWindow.eventCountCalls ?? 0) + 1
          return new Response(JSON.stringify({ total: 21, queried_at: new Date().toISOString() }), { headers: { 'Content-Type': 'application/json' } })
        }
        if (!url.pathname.endsWith('/events')) return original(input, init)
        const cursor = url.searchParams.get('cursor')
        const offset = cursor === 'event:20' ? 20 : 0
        const items = Array.from({ length: 21 }, (_, index) => ({
          event_id: `cursor-event-${String(index + 1).padStart(3, '0')}`,
          source: 'suricata', type: 'dns', timestamp: new Date(Date.now() - index * 1000).toISOString(),
          observer: { sensor_id: 'mock-sensor' }, subject: { ip: '192.0.2.18' },
          flow: { src_ip: '192.0.2.18', dst_ip: '198.51.100.3', dst_port: 53, proto: 'udp' },
          payload: { query: `school-${index}.example.test` }, confidence: 1,
        }))
        const limit = Number(url.searchParams.get('limit') ?? 20)
        const events = items.slice(offset, offset + limit)
        const next = offset + events.length < items.length ? `event:${offset + events.length}` : null
        return new Response(JSON.stringify({ events, page: { limit, next_cursor: next, has_more: next !== null } }), { headers: { 'Content-Type': 'application/json' } })
      }
    })

    await page.goto('/events')
    await expect(page.getByText('第 1 页 · 本页 20 条')).toBeVisible()
    expect(await page.evaluate(() => (window as Window & { eventCountCalls?: number }).eventCountCalls)).toBe(0)
    await expect(page.getByRole('button', { name: '下一页' })).toBeEnabled()
    await page.getByRole('button', { name: '下一页' }).click()
    await expect(page.getByText('第 2 页 · 本页 1 条')).toBeVisible()
    await expect(page.getByRole('button', { name: '下一页' })).toBeDisabled()
    await page.getByRole('button', { name: '上一页' }).click()
    await expect(page.getByText('第 1 页 · 本页 20 条')).toBeVisible()
    await page.getByRole('button', { name: '统计总数' }).click()
    await expect(page.getByText('共 21 条')).toBeVisible()
    expect(await page.evaluate(() => (window as Window & { eventCountCalls?: number }).eventCountCalls)).toBe(1)

    const probe = await page.evaluate(() => {
      const panel = document.querySelector('.list-surface')!
      const controls = [...panel.querySelectorAll('.ant-btn,.ant-tag')].filter(element => element.getBoundingClientRect().width > 0)
      const selected = document.querySelector('.ant-menu-item-selected,.ant-tabs-tab-active')
      const luminance = (color: string) => {
        const values = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
        return values[0] * 0.2126 + values[1] * 0.7152 + values[2] * 0.0722
      }
      const fg = selected ? luminance(getComputedStyle(selected).color) : 0
      const bg = selected ? luminance(getComputedStyle(selected).backgroundColor) : 0
      return {
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        controls: controls.filter(element => getComputedStyle(element).whiteSpace !== 'nowrap' || getComputedStyle(element).flexShrink !== '0').map(element => element.textContent),
        rowDisplay: getComputedStyle(panel.querySelector('tr[data-row-key]')!).display,
        selectedContrast: selected ? (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05) : null,
      }
    })
    await writeFile(info.outputPath('event-cursor-dom.json'), JSON.stringify({ viewport, probe, errors }, null, 2))
    await page.screenshot({ path: info.outputPath('event-cursor.png'), fullPage: true, animations: 'disabled' })
    expect(probe.overflow).toBe(false)
    expect(probe.panelOverflow).toBe(false)
    expect(probe.controls).toEqual([])
    if (probe.selectedContrast !== null) expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
    if (viewport.width < 560) expect(probe.rowDisplay).not.toBe('table-row')
    expect(errors).toEqual([])

    await page.goto('/ingest')
    await page.getByRole('tab', { name: '最近事件' }).click()
    await expect(page.getByText('第 1 页 · 本页 20 条')).toBeVisible()
    expect(await page.evaluate(() => (window as Window & { eventCountCalls?: number }).eventCountCalls)).toBe(0)
    const ingestProbe = await page.evaluate(() => {
      const panel = [...document.querySelectorAll('.ingest-table-container')].find(element => element.textContent?.includes('最近事件'))!
      const controls = [...panel.querySelectorAll('.ant-btn,.ant-tag')].filter(element => element.getBoundingClientRect().width > 0)
      const selected = document.querySelector('.ant-tabs-tab-active')!
      const luminance = (color: string) => {
        const values = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
        return values[0] * 0.2126 + values[1] * 0.7152 + values[2] * 0.0722
      }
      const fg = luminance(getComputedStyle(selected).color)
      const bgStyle = getComputedStyle(selected).backgroundColor
      const bg = luminance(bgStyle === 'rgba(0, 0, 0, 0)' ? 'rgb(255, 255, 255)' : bgStyle)
      return {
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        panelOverflow: panel.scrollWidth > panel.clientWidth + 2,
        controls: controls.filter(element => getComputedStyle(element).whiteSpace !== 'nowrap' || getComputedStyle(element).flexShrink !== '0').map(element => element.textContent),
        rowDisplay: getComputedStyle(panel.querySelector('tr[data-row-key]')!).display,
        selectedContrast: (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05),
      }
    })
    await writeFile(info.outputPath('ingest-event-cursor-dom.json'), JSON.stringify({ viewport, probe: ingestProbe, errors }, null, 2))
    await page.screenshot({ path: info.outputPath('ingest-event-cursor.png'), fullPage: true, animations: 'disabled' })
    expect(ingestProbe.overflow).toBe(false)
    expect(ingestProbe.panelOverflow).toBe(false)
    expect(ingestProbe.controls).toEqual([])
    expect(ingestProbe.selectedContrast).toBeGreaterThanOrEqual(4.5)
    if (viewport.width < 560) expect(ingestProbe.rowDisplay).not.toBe('table-row')
  })
}
