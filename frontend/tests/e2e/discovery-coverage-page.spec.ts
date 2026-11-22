import { expect, test, type Page } from '@playwright/test'

async function assertCoverageLayout(page: Page) {
  const probe = await page.evaluate(() => {
    const visible = (el: Element) => el.getClientRects().length > 0
    const activeTab = document.querySelector('.coverage-tabs .ant-tabs-tab-active .ant-tabs-tab-btn')!
    const rgb = (value: string) => value.match(/[\d.]+/g)?.map(Number) ?? []
    const luminance = (color: number[]) => color.slice(0,3).reduce((sum, value, index) => {
      const channel = value / 255
      return sum + (channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4) * [0.2126, 0.7152, 0.0722][index]
    }, 0)
    let background = [255,255,255]
    for (let element: Element | null = activeTab; element; element = element.parentElement) {
      const fill = rgb(getComputedStyle(element).backgroundColor)
      if (fill.length === 3 || fill[3] === 1) { background = fill; break }
    }
    const foregroundLight = luminance(rgb(getComputedStyle(activeTab).color))
    const backgroundLight = luminance(background)
    return {
      overflow:document.documentElement.scrollWidth>innerWidth+2,
      badControls:[...document.querySelectorAll('.discovery-coverage-page .ant-btn,.discovery-coverage-page .ant-tag')].filter(visible).filter(element=>{const style=getComputedStyle(element);return style.whiteSpace!=='nowrap'||style.flexShrink!=='0'}).length,
      clipped:[...document.querySelectorAll('.coverage-metric,.coverage-panel,.discovery-diagnostics-stage,.discovery-diagnostics-table tr')].filter(visible).filter(element=>element.getBoundingClientRect().right>innerWidth+2||element.scrollWidth>element.clientWidth+2).length,
      selected:[...document.querySelectorAll('.ant-menu-item-selected')].map(element=>element.textContent?.trim()),
      contrast:(Math.max(foregroundLight, backgroundLight)+.05)/(Math.min(foregroundLight, backgroundLight)+.05),
    }
  })
  expect(probe.overflow).toBe(false)
  expect(probe.badControls).toBe(0)
  expect(probe.clipped).toBe(0)
  expect(probe.selected).toContain('发现覆盖报表')
  expect(probe.contrast).toBeGreaterThanOrEqual(4.5)
}


for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`coverage keeps live metrics, network groups and historical evidence in their own views ${viewport.width}`, async ({page}, info) => {
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
    const report = page.getByRole('region',{name:'设备发现覆盖报表'})
    const stages = report.getByRole('region',{name:'IPv4 识别进度'})
    await expect(stages).toContainText('33.3%')
    await expect(report.getByRole('region',{name:'类型待确认的证据'})).toContainText('仅网络层')
    await expect(report).toContainText('滞后约 22 分钟')
    await expect(page.getByRole('region',{name:'镜像标识与配对'})).not.toBeVisible()
    await expect(page.getByLabel('设备事实原因分析')).not.toBeVisible()
    await assertCoverageLayout(page)
    await page.screenshot({path:info.outputPath(`coverage-report-${viewport.width}.png`),fullPage:true,animations:'disabled'})

    await page.getByRole('tab',{name:'网段与 VLAN'}).click()
    const networks = page.getByRole('region',{name:'网段与 VLAN 分布'})
    const subnet = networks.getByRole('link',{name:'查看 192.0.2.0/24 的发现记录'})
    await expect(subnet).toHaveAttribute('href',/tab=discovery&discovery_window=24h&discovery_subnet=192.0.2.0%2F24/)
    const subnetSearch = networks.getByRole('textbox',{name:'搜索网段'})
    await subnetSearch.fill('203.0.113')
    await expect(networks.getByText('没有匹配的分组。')).toBeVisible()
    await subnetSearch.clear()
    await expect(subnet).toBeVisible()
    await assertCoverageLayout(page)
    await page.screenshot({path:info.outputPath(`coverage-networks-${viewport.width}.png`),animations:'disabled'})
    await subnet.click()
    await expect(page).toHaveURL(/\/devices\?tab=discovery&discovery_window=24h&discovery_subnet=192.0.2.0%2F24/)
    await expect(page.getByLabel('已应用筛选')).toContainText('192.0.2.0/24')
    await page.goBack()

    await page.getByRole('tab',{name:'镜像与配对'}).click()
    const mirror = page.getByRole('region',{name:'镜像标识与配对'})
    const pairCounts = mirror.getByRole('region',{name:'有效 IP–MAC 配对'})
    await expect(pairCounts).toContainText('40.0%')
    await expect(pairCounts.getByRole('progressbar',{name:'已确认设备类型'})).toHaveAttribute('max','5')
    await expect(mirror).toContainText('绑定状态截至')
    await expect(mirror).toContainText('5 个无有效 MAC 配对')
    await expect(page.getByLabel('镜像可见标识统计')).not.toBeVisible()
    await page.getByText('查看 MAC 管理位和厂商前缀').click()
    await expect(mirror.getByText('全局管理 · 匹配 OUI')).toBeVisible()
    await assertCoverageLayout(page)
    await page.screenshot({path:info.outputPath(`coverage-mirror-${viewport.width}.png`),fullPage:true,animations:'disabled'})
    await page.getByText('镜像明细与台账对照').click()
    await expect(page.getByLabel('镜像可见标识统计')).toBeVisible()

    await page.getByRole('tab',{name:'历史核查'}).click()
    await expect(page.getByLabel('历史现场核查')).toContainText('11 月 15 日')
    await expect(page.locator('.discovery-diagnostics-table tbody tr')).toHaveCount(46)
    await assertCoverageLayout(page)
    expect(errors).toEqual([])
  })
}
