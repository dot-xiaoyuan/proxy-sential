import { expect, test } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) {
  test(`audit records use bounded cursor pages at ${width}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', item => { if (item.type() === 'error') errors.push(item.text()) })
    page.on('requestfailed', request => errors.push(`${request.url()}: ${request.failure()?.errorText}`))
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.setViewportSize({ width, height })
    await page.addInitScript(() => {
      const original = window.fetch
      const auditWindow = window as typeof window & { __auditRequests: string[] }
      auditWindow.__auditRequests = []
      window.fetch = async (...args) => {
        const address = args[0] instanceof Request ? args[0].url : String(args[0])
        if (!address.includes('/api/v1/audit-logs?')) return original(...args)
        auditWindow.__auditRequests.push(address)
        const url = new URL(address, window.location.origin)
        const next = url.searchParams.get('cursor') === 'next-audit'
        return new Response(JSON.stringify({
          logs: [{ audit_id: next ? 'audit-second' : 'audit-first', actor: 'system', action: 'identity.snapshot.commit', target: next ? 'target-second' : 'target-first', outcome: 'recorded', created_at: '2026-11-12T03:00:00Z' }],
          next_cursor: next ? '' : 'next-audit', has_more: !next,
        }), { headers: { 'Content-Type': 'application/json' } })
      }
    })
    await page.goto('/audit')
    await expect(page.getByText('target-first')).toBeVisible()
    const probe = await page.evaluate(() => {
      const root = document.querySelector('.page')!
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        rowDisplay: getComputedStyle(root.querySelector('.ant-table-row')!).display,
        compressedControls: [...root.querySelectorAll('.ant-btn,.ant-tag')].filter(item => {
          const style = getComputedStyle(item)
          return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
        }).map(item => item.textContent),
      }
    })
    expect(probe.documentOverflow).toBe(false)
    expect(probe.compressedControls).toEqual([])
    if (width === 390) expect(probe.rowDisplay).toBe('block')
    const dir = path.resolve('test-results/audit-seek-layout')
    await mkdir(dir, { recursive: true })
    await writeFile(path.join(dir, `dom-${width}.json`), JSON.stringify(probe, null, 2))
    await page.screenshot({ path: path.join(dir, `audit-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByRole('button', { name: '下一页' }).click()
    await expect(page.getByText('target-second')).toBeVisible()
    const requests = await page.evaluate(() => (window as typeof window & { __auditRequests: string[] }).__auditRequests)
    expect(requests.every(address => address.includes('seek=1'))).toBe(true)
    expect(requests.some(address => address.includes('cursor=next-audit'))).toBe(true)
    expect(errors).toEqual([])
  })
}
