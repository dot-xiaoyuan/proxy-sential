import { expect, test } from '@playwright/test'

for (const viewport of [{ width:390, height:844 }, { width:1198, height:1171 }, { width:1280, height:800 }, { width:1440, height:900 }]) {
  test(`abstract background and centered login at ${viewport.width}`, async ({ page }, info) => {
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const fetchOriginal = window.fetch
      window.fetch = (...args) => {
        const path = new URL(String(args[0]), window.location.href).pathname
        if (path === '/api/v1/session' || path === '/api/v1/auth/login') {
          return Promise.resolve(new Response('{}', { status:401, headers:{ 'Content-Type':'application/json' } }))
        }
        return fetchOriginal(...args)
      }
    })
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('requestfailed', request => errors.push(request.url()))
    const imageResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/login-traffic-network.svg')
    await page.goto('/devices?tab=discovery')
    await expect(page.getByRole('heading', {name:'登录'})).toBeVisible()
    const backdropResponse = await imageResponse
    expect(backdropResponse.ok()).toBe(true)
    expect(backdropResponse.headers()['content-type']).toContain('image/svg+xml')
    const probe = await page.locator('.login-card').evaluate(card => {
      const panel = card.getBoundingClientRect()
      const backdrop = card.closest('.login-page')!
      const backdropBounds = backdrop.getBoundingClientRect()
      const button = getComputedStyle(card.querySelector('button[type=submit]')!)
      const active = getComputedStyle(card.querySelector('.ant-input-affix-wrapper')!)
      return {
        overflows: document.documentElement.scrollWidth > innerWidth + 2,
        backgroundSize: getComputedStyle(backdrop).backgroundSize,
        fullViewport: backdropBounds.width >= innerWidth - 1 && backdropBounds.height >= innerHeight - 1,
        cardFits: panel.right <= innerWidth && panel.left >= 0,
        panelCenter: (panel.left + panel.right) / 2,
        panelWidth: panel.width,
        buttonHeight: card.querySelector('button[type=submit]')!.getBoundingClientRect().height,
        radius: getComputedStyle(card).borderRadius,
        wrap: button.whiteSpace,
        shrink: button.flexShrink,
        focusBorder: active.borderTopColor,
        focusShadow: active.boxShadow,
      }
    })
    expect(probe).toMatchObject({
      overflows:false, backgroundSize:'cover', fullViewport:true, cardFits:true,
      radius:'8px', wrap:'nowrap', shrink:'0', focusBorder:'rgb(37, 99, 235)', focusShadow:'none',
    })
    if (viewport.width < 680) {
      expect(Math.abs(probe.panelCenter - viewport.width / 2)).toBeLessThan(2)
      expect(probe.panelWidth).toBeGreaterThanOrEqual(350)
      expect(probe.buttonHeight).toBeGreaterThanOrEqual(48)
    } else {
      expect(probe.panelCenter).toBeGreaterThan(viewport.width * .52)
      expect(probe.panelCenter).toBeLessThan(viewport.width * .58)
      expect(probe.panelWidth).toBeGreaterThanOrEqual(500)
      expect(probe.buttonHeight).toBeGreaterThanOrEqual(54)
    }
    await page.screenshot({path:info.outputPath(`login-${viewport.width}.png`), animations:'disabled'})
    await page.getByLabel('账号').fill('layout-test')
    await page.getByLabel('密码').fill('rejected-fixture-password')
    await page.getByRole('button', {name:'登录'}).click()
    await expect(page.getByText('账号或密码不正确，请重新输入。')).toBeVisible()
    expect(errors).toEqual([])
  })
}
