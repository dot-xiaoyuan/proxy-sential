import { expect, test } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`router observation remains distinct from shared behavior at ${viewport.width}x${viewport.height}`, async ({page}) => {
    await page.setViewportSize(viewport)
    await page.goto('/cases/router-e2e-current')
    await expect(page.getByText('较可信路由器观察')).toBeVisible()
    await expect(page.getByText('风险分 82 · 置信度 82%')).toBeVisible()
    await page.getByRole('tab',{name:'证据快照'}).click()
    await expect(page.getByText('较可信路由设备观察 · 置信度 82% · 独立证据源 2 类')).toBeVisible()
    await expect(page.getByText('TP-Link')).toBeVisible()
    await expect(page.getByText('DHCP 厂商类标识与路由设备特征一致')).toBeVisible()
    await expect(page.getByText('共享行为已确认')).toHaveCount(0)

    const probe=await page.evaluate(() => ({
      viewport:{width:innerWidth,height:innerHeight},
      documentWidth:document.documentElement.scrollWidth,
      page:[...document.querySelectorAll('.page')].map(el=>({width:el.clientWidth,scrollWidth:el.scrollWidth})),
      cards:[...document.querySelectorAll('.surface-card')].map(el=>({radius:getComputedStyle(el).borderRadius,border:getComputedStyle(el).borderTopColor})),
      controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].map(el=>({whiteSpace:getComputedStyle(el).whiteSpace,flexShrink:getComputedStyle(el).flexShrink})),
      identifiers:[...document.querySelectorAll('.mono')].map(el=>({overflowWrap:getComputedStyle(el).overflowWrap})),
    }))
    expect(probe.viewport).toEqual(viewport)
    expect(probe.documentWidth).toBeLessThanOrEqual(viewport.width+2)
    for(const item of probe.page)expect(item.scrollWidth).toBeLessThanOrEqual(item.width+2)
    for(const card of probe.cards){expect(card.radius).toBe('8px');expect(card.border).toBe('rgb(226, 232, 240)')}
    for(const control of probe.controls){expect(control.whiteSpace).toBe('nowrap');expect(control.flexShrink).toBe('0')}

    const directory=path.resolve('../artifacts/router-case-detail/ui')
    fs.mkdirSync(directory,{recursive:true})
    fs.writeFileSync(path.join(directory,`router-case-${viewport.width}x${viewport.height}-probe.json`),JSON.stringify(probe,null,2))
    await page.screenshot({path:path.join(directory,`router-case-${viewport.width}x${viewport.height}.png`),fullPage:true})

    await page.goto('/cases')
    await expect(page.getByLabel('包含路由设备观察')).toBeChecked()
    await expect(page.getByRole('link',{name:'192.0.2.63'}).first()).toBeVisible()
    const queueProbe=await page.evaluate(() => ({
      viewport:{width:innerWidth,height:innerHeight},
      documentWidth:document.documentElement.scrollWidth,
      page:[...document.querySelectorAll('.page')].map(el=>({width:el.clientWidth,scrollWidth:el.scrollWidth})),
      controls:[...document.querySelectorAll('.ant-btn,.ant-tag,.ant-switch')].map(el=>({whiteSpace:getComputedStyle(el).whiteSpace,flexShrink:getComputedStyle(el).flexShrink})),
    }))
    expect(queueProbe.documentWidth).toBeLessThanOrEqual(viewport.width+2)
    for(const item of queueProbe.page)expect(item.scrollWidth).toBeLessThanOrEqual(item.width+2)
    for(const control of queueProbe.controls){expect(control.whiteSpace).toBe('nowrap');expect(control.flexShrink).toBe('0')}
    fs.writeFileSync(path.join(directory,`router-queue-${viewport.width}x${viewport.height}-probe.json`),JSON.stringify(queueProbe,null,2))
    await page.screenshot({path:path.join(directory,`router-queue-${viewport.width}x${viewport.height}.png`),fullPage:true})
  })
}

test('router observations can be hidden from the queue without hiding shared cases', async ({page}) => {
  await page.goto('/cases')
  await expect(page.getByRole('link',{name:'192.0.2.63'}).first()).toBeVisible()
  await page.getByLabel('包含路由设备观察').click()
  await expect(page.getByRole('link',{name:'192.0.2.63'})).toHaveCount(0)
  await expect(page.getByRole('link',{name:'192.0.2.22'}).first()).toBeVisible()
})
