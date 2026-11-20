import { expect, test } from '@playwright/test'

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`coverage has its own page and discovery starts with a compact summary and list ${viewport.width}`, async ({page}, info) => {
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
    const overviewTop = await page.getByLabel('发现设备总览').evaluate(element=>element.getBoundingClientRect().top)
    expect(overviewTop).toBeLessThan(viewport.height)
    expect(overviewTop).toBeLessThan(listTop)
    expect(listTop).toBeLessThan(viewport.height)
    await page.getByRole('button',{name:/^(筛选|更多筛选)/}).click()
    await expect(page.getByRole('checkbox',{name:'本地管理 MAC'})).toBeVisible()
    await page.screenshot({path:info.outputPath(`discovery-list-${viewport.width}.png`),animations:'disabled'})

    await page.goto('/devices/coverage')
    const report = page.getByLabel('设备发现覆盖报表')
    await expect(report).toContainText('当前无有效 MAC 配对的 IPv4')
    await expect(report).toContainText('当前有效的 IP–MAC 配对')
    await expect(report.getByText('当前无有效 MAC 配对的 IPv4').locator('..')).not.toContainText('共 9 个 IPv4')
    await expect(report.getByText('当前无有效 IPv4 配对的 MAC').locator('..')).not.toContainText('共 6 个 MAC')
    await expect(report).toContainText('绑定状态截至')
    await expect(report).not.toContainText('包含窗口内历史换绑')
    await expect(report).toContainText('已识别设备类型的配对')
    await expect(report).toContainText('类型待确认的配对')
    await expect(report).toContainText('配对占比，不是物理设备台数占比')
    await expect(report.getByLabel('已识别设备类型的配对占比')).toContainText('40.0%')
    await expect(report).not.toContainText('有设备记录的组合占比')
    await expect(report.getByLabel('MAC OUI 匹配占比')).toContainText('33.3%')
    await expect(report).toContainText('近期新配对可能还在处理中')
    await expect(report).toContainText('已按固定标志位计算')
    await expect(report).toContainText('无法确认随机 MAC 的准确数量')
    await expect(report).toContainText('无 OUI 且非本地管理 MAC')
    await expect(report).not.toContainText('可信设备身份')
    await expect(report.getByText('设备发现观测')).not.toBeVisible()
    await expect(page.getByLabel('设备事实原因分析')).not.toBeVisible()
    await page.screenshot({path:info.outputPath(`coverage-report-${viewport.width}.png`),fullPage:true,animations:'disabled'})
    await report.getByLabel('已识别设备类型的配对占比').scrollIntoViewIfNeeded()
    await page.screenshot({path:info.outputPath(`coverage-type-rate-${viewport.width}.png`),animations:'disabled'})
    await report.getByText('查看设备观测与类型统计（另一统计口径）').click()
    await expect(report.getByText('设备发现观测')).toBeVisible()
    await page.getByText('查看原因分析与镜像明细').click()
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
    await page.screenshot({path:info.outputPath(`coverage-details-${viewport.width}.png`),fullPage:true,animations:'disabled'})
    expect(errors).toEqual([])
  })
}
