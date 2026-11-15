import { expect, test } from '@playwright/test'

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`coverage has its own page and discovery keeps the list first ${viewport.width}`, async ({page}, info) => {
    const errors:string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => {if(message.type()==='error')errors.push(message.text())})
    page.on('response', response => {if(response.status()>=400)errors.push(`${response.status()} ${response.url()}`)})
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=discovery')
    const list = page.locator('.passive-ledger-table')
    await expect(list).toBeVisible()
    await expect(page.getByLabel('设备发现覆盖报表')).toHaveCount(0)
    await expect(page.getByLabel('镜像可见标识统计')).toHaveCount(0)
    const listTop = await list.evaluate(element=>element.getBoundingClientRect().top)
    expect(listTop).toBeLessThan(viewport.height)
    await page.screenshot({path:info.outputPath(`discovery-list-${viewport.width}.png`),animations:'disabled'})

    await page.goto('/devices/coverage')
    const report = page.getByLabel('设备发现覆盖报表')
    await expect(report).toContainText('IPv4 地址')
    await expect(report).toContainText('类型缺口：按 IPv4 地址拆解')
    await expect(page.getByLabel('设备事实原因分析')).toContainText('Fingerbank 采购判断')
    await expect(page.locator('.discovery-diagnostics-table tbody tr')).toHaveCount(46)
    await expect(page.getByLabel('镜像可见标识统计')).toBeVisible()
    const probe = await page.evaluate(() => ({
      overflow:document.documentElement.scrollWidth>innerWidth+2,
      badControls:[...document.querySelectorAll('.discovery-coverage-page .ant-btn,.discovery-coverage-page .ant-tag')].filter(element=>{const style=getComputedStyle(element);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).length,
      clippedMetrics:[...document.querySelectorAll('.discovery-report-metric')].filter(element=>element.scrollWidth>element.clientWidth+2).length,
      clippedDiagnosis:[...document.querySelectorAll('.discovery-diagnostics-stage,.discovery-diagnostics-examples article,.discovery-diagnostics-table tr')].filter(element=>element.getBoundingClientRect().right>innerWidth+2).length,
      selected:[...document.querySelectorAll('.ant-menu-item-selected')].map(element=>element.textContent?.trim()),
    }))
    expect(probe.overflow).toBe(false)
    expect(probe.badControls).toBe(0)
    expect(probe.clippedMetrics).toBe(0)
    expect(probe.clippedDiagnosis).toBe(0)
    expect(probe.selected).toContain('发现覆盖报表')
    await page.screenshot({path:info.outputPath(`coverage-report-${viewport.width}.png`),fullPage:true,animations:'disabled'})
    expect(errors).toEqual([])
  })
}
