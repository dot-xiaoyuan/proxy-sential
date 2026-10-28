import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`recognition waits for evidence after a compact inventory summary ${viewport.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport)
    const errors: string[] = []
    const cancelledRequests: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    page.on('requestfailed', request => {
      const error = request.failure()?.errorText
      // React StrictMode cancels the first mount's query via its AbortSignal.
      if (error === 'net::ERR_ABORTED') cancelledRequests.push(request.url())
      else errors.push(`${error} ${request.url()}`)
    })
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      const gate = window as typeof window & { releaseRecognition?: () => void }
      const evidenceReady = new Promise<void>(resolve => { gate.releaseRecognition = resolve })
      window.fetch = async (input, init) => {
        const url = new URL(typeof input === 'string' ? input : input instanceof Request ? input.url : input.href, location.href)
        const response = await original(input, init)
        if (url.pathname.startsWith('/api/v1/device-inventory/')) {
          const data = await response.json()
          delete data.profile.brand_inference
          data.profile.recognition.brand_inference = { status: 'insufficient', confidence: 0, candidates: null, as_of: '', explanation: '', rule_version: '', window: '' }
          return new Response(JSON.stringify(data), { status: response.status, headers: response.headers })
        }
        if (url.pathname.endsWith('/identity') && url.pathname.startsWith('/api/v1/endpoints/')) await evidenceReady
        return response
      }
    })
    await page.goto('/devices/mac%3A02%3A00%3A00%3A00%3A90%3A08')
    await page.getByRole('tab', { name: '终端识别', exact: true }).click()
    await expect(page.getByRole('heading', { name: '终端识别', exact: true })).toBeVisible()
    await expect(page.locator('.brand-inference-details')).toHaveCount(0)
    await expect(page.getByText('Unexpected Application Error!')).toHaveCount(0)
    await expect(page.getByText('Invalid Date')).toHaveCount(0)
    await page.screenshot({ path: testInfo.outputPath(`recognition-pending-${viewport.width}.png`), fullPage: true, animations: 'disabled' })
    await page.evaluate(() => (window as typeof window & { releaseRecognition?: () => void }).releaseRecognition?.())
    await expect(page.getByRole('heading', { name: '推测品牌与依据' })).toBeVisible()
    await expect(page.locator('.brand-inference-details').getByText('albert.apple.com', { exact: true }).first()).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`recognition-loaded-${viewport.width}.png`), fullPage: true, animations: 'disabled' })
    await page.locator('.brand-evidence-list > li').first().scrollIntoViewIfNeeded()
    await page.screenshot({ path: testInfo.outputPath(`recognition-evidence-${viewport.width}.png`), fullPage: true, animations: 'disabled' })
    const probe = await page.evaluate(() => {
      const styles = (selector: string) => getComputedStyle(document.querySelector(selector)!)
      const selected = styles('.endpoint-details-page .ant-tabs-tab-active .ant-tabs-tab-btn')
      let backgroundNode: Element | null = document.querySelector('.endpoint-details-page .ant-tabs-tab-active')
      let backgroundColor = 'rgb(255, 255, 255)'
      while (backgroundNode) {
        const color = getComputedStyle(backgroundNode).backgroundColor
        if (color !== 'rgba(0, 0, 0, 0)' && color !== 'transparent') { backgroundColor = color; break }
        backgroundNode = backgroundNode.parentElement
      }
      const luminance = (rgb: string) => {
        const channels = rgb.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(v => {
          const channel = v / 255
          return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4
        })
        return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722
      }
      const levels = [luminance(selected.color), luminance(backgroundColor)].sort((a, b) => a - b)
      return {
        overflow: document.documentElement.scrollWidth > innerWidth + 2,
        surfaceOverflow: [...document.querySelectorAll('.endpoint-details-page .surface')].filter(el => el.scrollWidth > el.clientWidth + 2).length,
        controls: [...document.querySelectorAll('.ant-btn, .ant-tag')].filter(el => el.getClientRects().length).map(el => ({ text: el.textContent, whiteSpace: getComputedStyle(el).whiteSpace, shrink: getComputedStyle(el).flexShrink })),
        selectedContrast: (levels[1] + .05) / (levels[0] + .05),
        selectedColor: selected.color, backgroundColor,
        evidence: { radius: styles('.brand-evidence-list > li').borderRadius, padding: styles('.brand-evidence-list > li').padding, border: styles('.brand-evidence-list > li').borderColor },
        identifierWrap: styles('.brand-evidence-list .brand-evidence-wrap').overflowWrap,
        titleSize: styles('.brand-inference-details h4').fontSize,
      }
    })
    const audit = JSON.stringify({ ...probe, errors, cancelledRequests }, null, 2)
    await writeFile(testInfo.outputPath('dom-style-probe.json'), audit)
    await testInfo.attach('dom-style-probe', { body: audit, contentType: 'application/json' })
    expect(probe.overflow).toBe(false)
    expect(probe.surfaceOverflow).toBe(0)
    expect(probe.selectedContrast).toBeGreaterThanOrEqual(4.5)
    expect(probe.evidence).toEqual({ radius: '8px', padding: viewport.width < 560 ? '14px' : '20px', border: 'rgb(226, 232, 240)' })
    expect(probe.identifierWrap).toBe('anywhere')
    expect(parseFloat(probe.titleSize)).toBeGreaterThan(14)
    for (const control of probe.controls) { expect(control.whiteSpace).toBe('nowrap'); expect(control.shrink).toBe('0') }
    expect(errors).toEqual([])
  })
}
