import { expect, test } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`shared case evidence stays coherent at ${viewport.width}x${viewport.height}`, async ({page}) => {
    await page.setViewportSize(viewport)
    await page.goto('/cases/shared-e2e-current')
    await expect(page.getByText('风险分 90 · 置信度 90%')).toBeVisible()
    await page.getByRole('tab',{name:'证据快照'}).click()
    await expect(page.getByText('共享行为已确认 · 置信度 90% · 当前设备下界 2 台')).toBeVisible()
    await expect(page.getByText('强锚点：IEEE 1905.1 / EasyMesh 当前关联终端 · 覆盖状态：完整覆盖已验证')).toBeVisible()
    await expect(page.getByText('暂无证据快照')).toHaveCount(0)

    const probe=await page.evaluate(() => ({
      viewport:{width:innerWidth,height:innerHeight},
      documentWidth:document.documentElement.scrollWidth,
      page:[...document.querySelectorAll('.page')].map(el=>({width:el.clientWidth,scrollWidth:el.scrollWidth})),
      cards:[...document.querySelectorAll('.surface-card')].map(el=>({radius:getComputedStyle(el).borderRadius,border:getComputedStyle(el).borderTopColor})),
      controls:[...document.querySelectorAll('.ant-btn,.ant-tag')].map(el=>({whiteSpace:getComputedStyle(el).whiteSpace,flexShrink:getComputedStyle(el).flexShrink})),
      identifiers:[...document.querySelectorAll('.case-history-id')].map(el=>({overflowWrap:getComputedStyle(el).overflowWrap})),
      inlineStyles:document.querySelectorAll('.page [style]').length,
    }))
    expect(probe.viewport).toEqual(viewport)
    expect(probe.documentWidth).toBeLessThanOrEqual(viewport.width+2)
    for(const item of probe.page)expect(item.scrollWidth).toBeLessThanOrEqual(item.width+2)
    for(const card of probe.cards){expect(card.radius).toBe('8px');expect(card.border).toBe('rgb(226, 232, 240)')}
    for(const control of probe.controls){expect(control.whiteSpace).toBe('nowrap');expect(control.flexShrink).toBe('0')}
    for(const identifier of probe.identifiers)expect(identifier.overflowWrap).toBe('anywhere')

    const directory=path.resolve('../artifacts/shared-case-detail/ui')
    fs.mkdirSync(directory,{recursive:true})
    fs.writeFileSync(path.join(directory,`shared-case-${viewport.width}x${viewport.height}-probe.json`),JSON.stringify(probe,null,2))
    await page.screenshot({path:path.join(directory,`shared-case-${viewport.width}x${viewport.height}.png`),fullPage:true})
  })
}
