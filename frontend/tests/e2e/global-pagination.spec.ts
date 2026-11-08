import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`blacklist and cursor lists share real numeric pagination ${viewport.width}`, async ({ page }, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      const calls: string[] = []
      Object.assign(window, { paginationCalls: calls })
      window.fetch = async (input, init) => {
        const raw = typeof input === 'string' ? input : input instanceof Request ? input.url : input.href
        const url = new URL(raw, location.origin)
        const path = url.pathname
        if (!path.endsWith('/blacklist') && !path.includes('/discovery/devices')) return original(input, init)
        calls.push(url.pathname + url.search)
        const as_of = '2026-11-06T00:00:00Z'
        const limit = Number(url.searchParams.get('limit') || 20)
        const number = Number(url.searchParams.get('page') || 1)
        const offset = Number((url.searchParams.get('cursor') || '0').replace('boundary-', ''))
        let response: object
        if (path.endsWith('/metadata')) response = { total: 61, as_of, count_unit: 'trusted_discovery_identity' }
        else if (path.endsWith('/position')) response = { page: number, limit, cursor: `boundary-${(number - 1) * limit}`, as_of }
        else {
          const items = Array.from({ length: Math.max(0, Math.min(limit, 61 - offset)) }, (_, index) => {
            const id = offset + index + 1
            return path.endsWith('/blacklist') ? { entry_id: `entry-${id}`, type: 'account', value: `pagination-user-${id}`, enabled: true, valid_from: as_of, revision: 1, reason: '分页回放样本' } : { id: `router-${id}`, name: `分页设备${id}`, mac: `02:20:40:00:00:${id.toString(16).padStart(2, '0')}`, device_type: 'router', classification_status: 'identified', current: true, category: 'network', protocols: ['lldp'], capabilities: ['routing'], current_addresses: [`192.0.2.${id}`], observations: [], last_seen: as_of, first_seen: as_of }
          })
          response = path.endsWith('/blacklist') ? { items, page: { total: 61, limit, next_cursor: offset + limit < 61 ? String(offset + limit) : '' }, checked_at: as_of } : { items, limit, has_more: offset + limit < 61, next_cursor: offset + limit < 61 ? `boundary-${offset + limit}` : '', as_of }
        }
        return new Response(JSON.stringify(response), { headers: { 'Content-Type': 'application/json' } })
      }
    })
    const probes: object[] = []
    for (const [label, path, last] of [['blacklist', '/policies/blacklist', 'pagination-user-61'], ['routers', '/devices?tab=network&routers_view=router', '分页设备61']]) {
      await page.goto(path)
      const pagination = page.locator('.app-server-pagination').first()
      await expect(pagination.getByText('共 61 条', { exact: true })).toBeVisible()
      await expect(pagination.locator('.ant-pagination-item-4')).toBeVisible()
      await expect(pagination.locator('.ant-pagination-options-quick-jumper input')).toBeVisible()
      const beforeJump=await page.evaluate(() => (window as unknown as { paginationCalls: string[] }).paginationCalls.length)
      await pagination.locator('.ant-pagination-options-quick-jumper input').fill('4')
      await pagination.locator('.ant-pagination-options-quick-jumper input').press('Enter')
      await expect(page.getByText(last, { exact: true })).toBeVisible()
      await expect(pagination.locator('.ant-pagination-item-4')).toHaveClass(/ant-pagination-item-active/)
      if (label === 'routers') {
        const requests = (await page.evaluate(() => (window as unknown as { paginationCalls: string[] }).paginationCalls)).slice(beforeJump)
        expect(requests.filter(url => url.includes('/position'))).toHaveLength(1)
        expect(requests.find(url => url.includes('/position'))).toContain('page=4')
        const listReads = requests.filter(url => /\/discovery\/devices\?/.test(url))
        expect(listReads).toHaveLength(1)
        expect(listReads[0]).toContain('cursor=boundary-60')
      }
      await pagination.scrollIntoViewIfNeeded()
      const probe = await pagination.evaluate(element => {
        const selected = element.querySelector('.ant-pagination-item-active a')!
        const color = getComputedStyle(selected).color
        const channels = (color.match(/[\d.]+/g) || []).slice(0, 3).map(Number).map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4)
        const luminance = channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722
        return { className: element.className, tag: element.tagName, overflow: document.documentElement.scrollWidth > innerWidth + 2, barOverflow: element.scrollWidth > element.clientWidth + 2, selectedContrastOnWhite: 1.05 / (luminance + .05), controls: [...element.querySelectorAll('li,input,button')].filter(node => node.getBoundingClientRect().width > 0).map(node => ({ text: node.textContent, width: node.getBoundingClientRect().width, display: getComputedStyle(node).display })) }
      })
      probes.push({ label, viewport, probe })
      expect(probe.tag).toBe('UL')
      expect(probe.className).toContain('ant-pagination')
      expect(probe.overflow).toBe(false)
      expect(probe.barOverflow).toBe(false)
      expect(probe.selectedContrastOnWhite).toBeGreaterThanOrEqual(4.5)
      await page.screenshot({ path: info.outputPath(`${label}-page-four.png`), animations: 'disabled' })
      await pagination.screenshot({ path: info.outputPath(`${label}-pagination.png`), animations: 'disabled' })
      await pagination.locator('.ant-select').click()
      await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({ hasText: /^50/ }).click()
      await expect(pagination.locator('.ant-pagination-item-1')).toHaveClass(/ant-pagination-item-active/)
      await expect(pagination.locator('.ant-select')).toContainText('50')
      await expect(pagination.locator('.ant-pagination-item-2')).toBeVisible()
      await expect(pagination.locator('.ant-pagination-item-3')).toHaveCount(0)
      await pagination.locator('.ant-select').click()
      await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({ hasText: /^20/ }).click()
      await expect(pagination.locator('.ant-pagination-item-1')).toHaveClass(/ant-pagination-item-active/)
      await expect(pagination.locator('.ant-pagination-item-4')).toBeVisible()
    }
    await writeFile(info.outputPath('pagination-dom.json'), JSON.stringify({ probes, errors }, null, 2))
    expect(errors).toEqual([])
  })
}
