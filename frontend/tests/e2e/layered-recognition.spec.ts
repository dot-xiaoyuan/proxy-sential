import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`layered candidates and dimension references ${viewport.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport)
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      window.fetch = async (input, init) => {
        const url = new URL(typeof input === 'string' ? input : input instanceof Request ? input.url : input.href, location.href)
        const response = await original(input, init)
        if (!url.pathname.startsWith('/api/v1/device-inventory/') && !/^\/api\/v1\/endpoints\/.*\/identity$/.test(url.pathname)) return response
        const data = await response.json()
        const profile = data.profile ?? data
        Object.assign(profile.recognition, {
          brand: 'Huawei', brand_confidence: .95, product_family: 'Mate', product_family_confidence: .95,
          model: 'Mate 60 Pro', model_confidence: .95, device_type: 'phone', device_type_confidence: .95,
          recognition_conflict: true, conflict_dimensions: ['model'],
          product_candidates: [{ family: 'Mate', brand: 'Huawei', model: 'Mate 60 Pro', source: 'model_catalog', confidence: .95 }],
          dimension_evidence: [{ dimension: 'brand', value: 'Huawei', layer: 'model_catalog', field: 'ssdp_model', rule_id: 'ADY-AL00', confidence: .95,
            refs: [{ protocol: 'ssdp', field: 'ssdp_model', event_id: `fresh-event-${'0123456789abcdef'.repeat(6)}` }] }],
        })
        return new Response(JSON.stringify(data), { status: response.status, headers: response.headers })
      }
    })
    await page.goto('/devices/mac%3A02%3A00%3A00%3A00%3A90%3A08?tab=recognition')
    const candidates = page.locator('.recognition-evidence-grid').first()
    const evidence = page.locator('.recognition-evidence-grid').nth(1)
    await expect(candidates).toContainText('Mate · Huawei · Mate 60 Pro')
    await expect(candidates).toContainText('型号精确表')
    await expect(evidence).toContainText('品牌：Huawei')
    await expect(evidence).toContainText('fresh-event-0123456789abcdef')
    await expect(page.getByText('冲突字段', { exact: true })).toBeVisible()
    await evidence.scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`layered-${viewport.width}.png`), fullPage: false })
    const probe = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth + 2,
      surfaces: [...document.querySelectorAll('.endpoint-details-page .surface')].filter(el => el.scrollWidth > el.clientWidth + 2).length,
      identifiers: [...document.querySelectorAll('.recognition-evidence-grid .fingerprint-ident')].map(el => getComputedStyle(el).overflowWrap),
      controls: [...document.querySelectorAll('.ant-btn, .ant-tag')].filter(el => el.getClientRects().length).map(el => ({ whiteSpace: getComputedStyle(el).whiteSpace, shrink: getComputedStyle(el).flexShrink })),
    }))
    expect(probe.overflow).toBe(false)
    expect(probe.surfaces).toBe(0)
    expect(probe.identifiers.every(wrap => wrap === 'anywhere')).toBe(true)
    expect(probe.controls.every(control => control.whiteSpace === 'nowrap' && control.shrink === '0')).toBe(true)
    expect(errors).toEqual([])
    await testInfo.attach('layered-style-probe', { body: JSON.stringify(probe, null, 2), contentType: 'application/json' })
  })
}
