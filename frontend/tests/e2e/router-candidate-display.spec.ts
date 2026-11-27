import { expect, test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

test('current router role candidates remain visible and clearly qualified at three widths', async ({
  page,
}, info) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text())
  })
  page.on('requestfailed', (request) => {
    if (request.failure()?.errorText !== 'net::ERR_ABORTED')
      errors.push(`${request.failure()?.errorText} ${request.url()}`)
  })
  page.on('response', (response) => {
    if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`)
  })
  await page.addInitScript(() => {
    const original = window.fetch.bind(window)
    window.fetch = async (input, init) => {
      const raw =
        typeof input === 'string' ? input : input instanceof Request ? input.url : input.href
      const url = new URL(raw, location.origin)
      if (!url.pathname.endsWith('/router-observations')) return original(input, init)
      const items =
        url.searchParams.get('include_candidates') === 'true'
          ? [
              {
                assessment_id: 'ssdp-router-candidate',
                role: 'router',
                status: 'candidate',
                confidence: 55,
                ip: '192.0.2.30',
                mac: '02:00:00:00:00:30',
                conflicts: ['infrastructure_role'],
                sources: ['ssdp'],
                score_components: [],
                libraries: [],
                last_seen: new Date().toISOString(),
              },
            ]
          : []
      return new Response(
        JSON.stringify({
          items,
          page: { limit: 20, total: 0, next_cursor: null, has_more: false },
        }),
        { headers: { 'Content-Type': 'application/json' } },
      )
    }
  })
  for (const viewport of [
    { width: 390, height: 844 },
    { width: 1280, height: 800 },
    { width: 1440, height: 900 },
  ]) {
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=network&routers_view=router')
    const role = page.locator('.router-detail-page > .router-observations-panel').first()
    await expect(role.getByText('路由器线索', { exact: true })).toBeVisible()
    await expect(role.getByText(/候选记录仅是待核验的路由角色线索/)).toBeVisible()
    await expect(role.getByText('192.0.2.30', { exact: true })).toBeVisible()
    await expect(role.getByText(/未确认：/)).toBeVisible()
    await expect(role.getByText('无认证账号')).toHaveCount(0)
    const probe = await page.evaluate(() => {
      const note = document.querySelector('.router-candidate-note')!
      const noteStyle = getComputedStyle(note)
      const role = document.querySelector('.router-detail-page > .router-observations-panel')!
      const controls = [...role.querySelectorAll('.ant-btn,.ant-tag')].filter(
        (element) => element.getBoundingClientRect().width > 0,
      )
      return {
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        roleOverflow: role.scrollWidth > role.clientWidth + 2,
        noteOverflow: note.scrollWidth > note.clientWidth + 2,
        noteForeground: noteStyle.color,
        noteBackground: noteStyle.backgroundColor,
        brokenControls: controls
          .filter(
            (element) =>
              getComputedStyle(element).whiteSpace !== 'nowrap' ||
              getComputedStyle(element).flexShrink !== '0',
          )
          .map((element) => element.textContent),
      }
    })
    await writeFile(
      info.outputPath(`router-candidate-${viewport.width}-dom.json`),
      JSON.stringify({ viewport, probe, errors }, null, 2),
    )
    await page.screenshot({
      path: info.outputPath(`router-candidate-${viewport.width}.png`),
      fullPage: true,
      animations: 'disabled',
    })
    expect(probe).toMatchObject({
      documentOverflow: false,
      roleOverflow: false,
      noteOverflow: false,
      noteForeground: 'rgb(120, 53, 15)',
      noteBackground: 'rgb(255, 251, 235)',
      brokenControls: [],
    })
  }
  expect(errors).toEqual([])
})
