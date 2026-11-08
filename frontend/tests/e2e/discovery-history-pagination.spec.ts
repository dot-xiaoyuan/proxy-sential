import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`discovery history numeric pages and hostname explanation ${viewport.width}`, async ({ page }, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      const calls: string[] = []
      Object.assign(window, { historyPaginationCalls: calls })
      window.fetch = async (input, init) => {
        const raw = typeof input === 'string' ? input : input instanceof Request ? input.url : input.href
        const url = new URL(raw, location.origin)
        const path = url.pathname
        if (!path.includes('/discovery/devices') && !path.includes('/discovery/history')) return original(input, init)
        const stamp = '2026-11-06T00:00:00Z'
        let response: object
        if (path.includes('/discovery/history')) {
          calls.push(path + url.search)
          const limit = Number(url.searchParams.get('limit') || 20)
          const number = Number(url.searchParams.get('page') || 1)
          const offset = Number((url.searchParams.get('cursor') || '0').replace('history-boundary-', ''))
          if (path.endsWith('/metadata')) response = { total: 41, as_of: stamp, snapshot: stamp }
          else if (path.endsWith('/position')) response = { page: number, limit, cursor: `history-boundary-${(number - 1) * limit}`, as_of: stamp, snapshot: stamp }
          else response = { items: Array.from({ length: Math.max(0, Math.min(limit, 41 - offset)) }, (_, index) => ({ id: `history-${offset + index + 1}`, observed_at: stamp, evidence: { origin: 'dhcp', explanation: `历史地址记录${offset + index + 1}` } })), has_more: offset + limit < 41, next_cursor: `history-boundary-${offset + limit}`, snapshot: stamp }
        } else if (path.endsWith('/metadata')) response = { total: 1, as_of: stamp, count_unit: 'trusted_discovery_identity' }
        else response = { items: [{ id: 'hostname-device-204', mac: '02:20:40:00:00:01', name: 'DESKTOP-204', classification_status: 'candidate', device_type: '', category: 'identity_only', protocols: ['dhcp', 'arp'], capabilities: [], current: true, current_addresses: ['192.0.2.204'], observations: [], first_seen: stamp, last_seen: stamp }], limit: 20, has_more: false, next_cursor: '' }
        return new Response(JSON.stringify(response), { headers: { 'Content-Type': 'application/json' } })
      }
    })
    await page.goto('/devices?tab=discovery')
    await page.getByRole('button', { name: 'DESKTOP-204', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: '设备详情' })
    await expect(dialog).toBeVisible()
    await expect(dialog).toHaveCSS('opacity', '1')
    await expect(dialog.getByText('分类状态说明', { exact: true })).toBeVisible()
    await expect(dialog.getByText(/已发现设备，现有分类证据不足以确定设备类型/)).toBeVisible()
    await expect(dialog.getByText(/名称可自行设置，不能据此确认设备类型、操作系统或用途/)).toBeVisible()
    await page.screenshot({ path: info.outputPath('hostname-explanation.png'), animations: 'disabled' })
    const pagination = dialog.locator('.app-server-pagination')
    await expect(pagination.getByText('共 41 条', { exact: true })).toBeVisible()
    const before = await page.evaluate(() => (window as unknown as { historyPaginationCalls: string[] }).historyPaginationCalls.length)
    await pagination.getByTitle('3', { exact: true }).click()
    await expect(dialog.getByText('历史地址记录41', { exact: true })).toBeVisible()
    const calls = (await page.evaluate(() => (window as unknown as { historyPaginationCalls: string[] }).historyPaginationCalls)).slice(before)
    expect(calls.filter(url => url.includes('/position'))).toHaveLength(1)
    expect(calls.filter(url => /\/history\?/.test(url))).toHaveLength(1)
    expect(calls.every(url => new URL(url, 'http://localhost').searchParams.get('snapshot') === '2026-11-06T00:00:00Z')).toBe(true)
    expect(calls.every(url => new URL(url, 'http://localhost').searchParams.get('device_id') === 'hostname-device-204')).toBe(true)
    const probe = await dialog.evaluate(element => ({ overflow: document.documentElement.scrollWidth > innerWidth + 2, modalOverflow: element.scrollWidth > element.clientWidth + 2, paginationOverflow: [...element.querySelectorAll('.app-server-pagination')].some(node => node.scrollWidth > node.clientWidth + 2), totalStyles: [...element.querySelectorAll('.ant-pagination-total-text')].map(node=>({whiteSpace:getComputedStyle(node).whiteSpace,shrink:getComputedStyle(node).flexShrink})), compressed: [...element.querySelectorAll('.ant-btn')].filter(node => getComputedStyle(node).whiteSpace !== 'nowrap' || getComputedStyle(node).flexShrink !== '0').map(node => node.textContent) }))
    expect(probe.overflow).toBe(false)
    expect(probe.modalOverflow).toBe(false)
    expect(probe.paginationOverflow).toBe(false)
    expect(probe.totalStyles.every(style=>style.whiteSpace==='nowrap'&&style.shrink==='0')).toBe(true)
    expect(probe.compressed).toEqual([])
    await page.screenshot({ path: info.outputPath('history-page-three.png'), animations: 'disabled' })
    await pagination.screenshot({ path: info.outputPath('history-pagination.png'), animations: 'disabled' })
    await pagination.locator('.ant-select').click()
    await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({ hasText: /^50/ }).click()
    await expect(dialog.getByText('历史地址记录1', { exact: true })).toBeVisible()
    await expect(pagination.locator('.ant-pagination-item-1')).toHaveClass(/ant-pagination-item-active/)
    await expect(pagination.locator('.ant-pagination-item-2')).toHaveCount(0)
    await writeFile(info.outputPath('history-dom.json'), JSON.stringify({ viewport, probe, calls, errors }, null, 2))
    expect(errors).toEqual([])
  })
}
