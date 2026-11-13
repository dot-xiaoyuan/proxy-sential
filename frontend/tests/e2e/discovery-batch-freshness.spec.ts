import { expect, test } from '@playwright/test'

test('batch discovery watermarks fit three viewports', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
  await page.addInitScript(() => {
    const originalFetch = window.fetch.bind(window)
    window.fetch = async (input, init) => {
      const response = await originalFetch(input, init)
      const url = new URL(typeof input === 'string' ? input : input instanceof Request ? input.url : String(input), location.origin)
      if (url.pathname !== '/api/v1/discovery/devices' || !response.ok) return response
      const body = await response.clone().json()
      body.freshness = {
        status: 'delayed', source: 'passive-discovery-batch-v3', lag_seconds: 1800,
        ingested_at: '2026-11-13T08:00:00Z', processed_at: '2026-11-13T07:30:00Z',
        archive_verified_at: '2026-11-13T07:00:00Z', archive_oldest_pending_at: '2026-11-13T06:50:00Z',
        oldest_pending_at: '2026-11-13T07:25:00Z', pending_batches: 3, archive_pending_batches: 2,
      }
      return new Response(JSON.stringify(body), { status: response.status, headers: { 'content-type': 'application/json' } })
    }
  })
  await page.goto('/discovery')
  const progress = page.getByLabel('存储处理进度')
  await expect(progress).toContainText('待发现批次 3')
  await expect(progress).toContainText('待归档批次 2')
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport)
    await expect(progress).toBeVisible()
    const probe = await progress.evaluate(element => ({
      documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
      progressOverflow: element.scrollWidth > element.clientWidth + 2,
      textWrapped: [...element.children].some(child => getComputedStyle(child).overflowWrap === 'anywhere'),
      buttonsCompressed: [...document.querySelectorAll('.ant-btn')].some(button => {
        const style = getComputedStyle(button)
        return style.whiteSpace !== 'nowrap' || style.flexShrink !== '0'
      }),
    }))
    expect(probe).toEqual({ documentOverflow: false, progressOverflow: false, textWrapped: true, buttonsCompressed: false })
    await page.screenshot({ path: `test-results/discovery-batch-freshness-${viewport.width}x${viewport.height}.png`, fullPage: true, animations: 'disabled' })
  }
  expect(errors).toEqual([])
})
