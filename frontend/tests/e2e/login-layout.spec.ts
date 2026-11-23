import { expect, test } from '@playwright/test'

for (const viewport of [{ width:390, height:844 }, { width:1280, height:800 }, { width:1440, height:900 }]) {
  test(`login card and campus image at ${viewport.width}`, async ({ page }, info) => {
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
    const imageResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/login-campus.webp')
    await page.goto('/devices?tab=discovery')
    await expect(page.getByRole('heading', {name:'登录'})).toBeVisible()
    expect((await imageResponse).ok()).toBe(true)
    const probe = await page.locator('.login-layout').evaluate(layout => {
      const panel = layout.querySelector('.login-main')!.getBoundingClientRect()
      const visual = layout.querySelector('.login-visual')!.getBoundingClientRect()
      const button = getComputedStyle(layout.querySelector('button[type=submit]')!)
      const active = getComputedStyle(layout.querySelector('.ant-input-affix-wrapper')!)
      return {
        overflows: document.documentElement.scrollWidth > innerWidth + 2,
        photoAboveForm: visual.bottom <= panel.top + 2,
        formLeftOfPhoto: panel.right <= visual.left + 2,
        radius: getComputedStyle(layout).borderRadius,
        wrap: button.whiteSpace,
        shrink: button.flexShrink,
        focusBorder: active.borderTopColor,
        focusShadow: active.boxShadow,
      }
    })
    expect(probe).toMatchObject({
      overflows:false, photoAboveForm:viewport.width < 680, formLeftOfPhoto:viewport.width >= 680,
      radius:'8px', wrap:'nowrap', shrink:'0', focusBorder:'rgb(37, 99, 235)', focusShadow:'none',
    })
    await page.screenshot({path:info.outputPath(`login-${viewport.width}.png`), animations:'disabled'})
    await page.getByLabel('账号').fill('layout-test')
    await page.getByLabel('密码').fill('rejected-fixture-password')
    await page.getByRole('button', {name:'登录'}).click()
    await expect(page.getByText('账号或密码不正确，请重新输入。')).toBeVisible()
    expect(errors).toEqual([])
  })
}
