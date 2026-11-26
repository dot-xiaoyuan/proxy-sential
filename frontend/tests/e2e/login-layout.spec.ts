import { expect, test } from '@playwright/test'

for (const viewport of [{ width: 390, height: 844 }, { width: 1198, height: 1171 }, { width: 1280, height: 800 }, { width: 1440, height: 900 }]) {
  test(`minimal centered login and single focus border at ${viewport.width}`, async ({ page }, info) => {
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const fetchOriginal = window.fetch
      window.fetch = (...args) => {
        const path = new URL(String(args[0]), window.location.href).pathname
        if (path === '/api/v1/session' || path === '/api/v1/auth/login') {
          return Promise.resolve(new Response('{}', { status: 401, headers: { 'Content-Type': 'application/json' } }))
        }
        return fetchOriginal(...args)
      }
    })
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('requestfailed', request => errors.push(request.url()))

    await page.goto('/devices?tab=discovery')
    await expect(page.getByRole('heading', { name: '登录' })).toBeVisible()
    await expect(page.getByRole('img', { name: 'Proxy Sentinel' })).toBeVisible()

    const probe = await page.locator('.login-card').evaluate(card => {
      const panel = card.getBoundingClientRect()
      const backdrop = card.closest('.login-page')!
      const backdropBounds = backdrop.getBoundingClientRect()
      const button = getComputedStyle(card.querySelector('button[type=submit]')!)
      return {
        overflows: document.documentElement.scrollWidth > innerWidth + 2,
        fullViewport: backdropBounds.width >= innerWidth - 1 && backdropBounds.height >= innerHeight - 1,
        cardFits: panel.right <= innerWidth && panel.left >= 0,
        panelCenter: (panel.left + panel.right) / 2,
        panelWidth: panel.width,
        buttonHeight: card.querySelector('button[type=submit]')!.getBoundingClientRect().height,
        radius: getComputedStyle(card).borderRadius,
        wrap: button.whiteSpace,
        shrink: button.flexShrink,
      }
    })
    expect(probe).toMatchObject({
      overflows: false,
      fullViewport: true,
      cardFits: true,
      radius: '8px',
      wrap: 'nowrap',
      shrink: '0',
      buttonHeight: 40,
    })
    expect(Math.abs(probe.panelCenter - viewport.width / 2)).toBeLessThan(2)
    expect(probe.panelWidth).toBe(Math.min(400, viewport.width - 32))

    const username = page.getByLabel('账号')
    const password = page.getByLabel('密码', { exact: true })
    await expect(username).toBeFocused()
    for (const input of [username, password]) {
      await expect(input).toBeFocused()
      const wrapper = page.locator('.ant-input-affix-wrapper').filter({ has: input })
      await expect(wrapper).toHaveCSS('border-top-color', 'rgb(34, 87, 167)')
      await expect(wrapper).toHaveCSS('border-top-width', '1px')
      await expect(input).toHaveCSS('box-shadow', 'none')
      await expect(input).toHaveCSS('outline-style', 'none')
      if (input === username) await input.press('Tab')
    }
    await username.focus()
    await page.screenshot({ path: info.outputPath(`login-${viewport.width}.png`), animations: 'disabled' })
    await username.fill('layout-test')
    await password.fill('rejected-fixture-password')
    await page.getByRole('button', { name: '登录' }).click()
    await expect(page.getByText('账号或密码不正确，请重新输入。')).toBeVisible()
    expect(errors).toEqual([])
  })
}
