import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width, height] of [[390, 844], [1280, 800], [1440, 900]]) {
  test(`shared observations cursor and layout ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.addInitScript(() => {
      const originalFetch = window.fetch
      const requestedCursors: string[] = []
      ;(window as typeof window & { __testCursors?: string[] }).__testCursors = requestedCursors
      window.fetch = async (...args) => {
        const url = String(args[0])
        if (!url.includes('/shared-access/observations?')) return originalFetch(...args)
        const cursor = new URL(url, location.origin).searchParams.get('cursor') ?? ''
        requestedCursors.push(cursor)
      const item = {
        observation_id: cursor ? 'second' : 'first',
        sensor_id: 'sensor-test', campus_id: 'campus-test', access_domain: 'mirror',
        ip: cursor ? '192.0.2.2' : '192.0.2.1', status: 'candidate', confidence: 80,
        signal_groups: ['ieee1905_association'], reasons: [], conflicts: [], coverage_state: 'verified',
        rule_version: 'shared-behavior/v13', current: true, strong_anchor: 'ieee1905_association',
        device_lower_bound: 2, first_seen: '2026-11-12T03:50:00Z', last_seen: '2026-11-12T04:00:00Z',
        window_start: '2026-11-12T03:50:00Z', window_end: '2026-11-12T04:00:00Z',
        expires_at: '2026-12-12T04:00:00Z', router: {}, score_components: [],
        feature_samples: {}, event_ids: [], known_device_count: 0, known_devices: [],
      }
        return new Response(JSON.stringify({ items: [item], page: { limit: 20, has_more: !cursor, next_cursor: cursor ? null : 'cursor-2' } }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
    })
    await page.goto('/shared-access?tab=associations')
    await expect(page.getByText('192.0.2.1')).toBeVisible()
    await expect(page.getByText('本页 1 条', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: '下一页' }).click()
    await expect(page.getByText('192.0.2.2')).toBeVisible()
    expect(await page.evaluate(() => (window as typeof window & { __testCursors?: string[] }).__testCursors)).toContain('cursor-2')
    const probe = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth + 2,
      controls: [...document.querySelectorAll('.ant-btn,.ant-tag')].filter(element => {
        const style = getComputedStyle(element)
        return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
      }).map(element => element.textContent),
    }))
    expect(probe.overflow).toBe(false)
    expect(probe.controls).toEqual([])
    expect(errors).toEqual([])
    const dir = path.resolve('test-results/shared-observations')
    await mkdir(dir, { recursive: true })
    await writeFile(path.join(dir, `dom-${width}.json`), JSON.stringify(probe, null, 2))
    await page.screenshot({ path: path.join(dir, `page-${width}.png`), fullPage: true, animations: 'disabled' })
  })
}
