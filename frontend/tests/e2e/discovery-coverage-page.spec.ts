import { writeFile } from 'node:fs/promises'
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
      clipped:[...document.querySelectorAll('.coverage-metric,.coverage-panel,.coverage-composition-columns .coverage-type-block')].filter(visible).filter(element=>element.getBoundingClientRect().right>innerWidth+2||element.scrollWidth>element.clientWidth+2).length,
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
    const funnel = report.getByRole('region',{name:'发现与识别'})
    await expect(report.locator('.coverage-lead')).toContainText('共发现 7,575 个 IPv4 地址，其中 3,438 个有设备层报文')
    await expect(funnel).toContainText('4,137 个只在流量中出现')
    await expect(funnel.getByRole('img',{name:'已有类型判断 1,755 个，其中硬件规则确认 347 个，画像识别 1,408 个'})).toBeVisible()
    await expect(funnel).toContainText('占设备层 51.0%')
    const reasons = report.getByRole('region',{name:'尚无类型判断的原因'})
    await expect(reasons).toContainText('1,683 个有设备层报文的地址尚无类型判断')
    await expect(reasons.locator('.coverage-reason-head').first()).toContainText('只有 ARP 等地址层报文728')
    await expect(report.getByRole('region',{name:'哑终端'})).toBeVisible()
    await expect(report).toContainText('发现处理滞后约 22 分钟')
    await expect(report.getByText('硬件规则未确认的地址明细')).not.toBeVisible()
    await page.screenshot({path:info.outputPath(`coverage-overview-${viewport.width}.png`),animations:'disabled'})
    await report.getByText('查看技术明细').click()
    const matrix = report.getByRole('table',{name:'硬件规则未确认 IPv4 的画像及协议证据'})
    await expect(matrix.getByRole('row',{name:/画像已识别类型/}).getByRole('cell').first()).toHaveText('35')
    await expect(matrix.getByRole('row',{name:/地址归属待核实/})).toBeVisible()
    const freshness = report.getByRole('region', {name:'IPv4 绑定时效', exact:true})
    await expect(freshness.getByRole('progressbar',{name:'当前有效绑定'})).toHaveAttribute('value','1370')
    await expect(report.getByRole('region',{name:'IPv6 绑定时效',exact:true})).toBeVisible()
    await expect(page.getByRole('region',{name:'镜像标识与配对'})).not.toBeVisible()
    await expect(page.getByLabel('设备事实原因分析')).not.toBeVisible()
    await assertCoverageLayout(page)
    await page.screenshot({path:info.outputPath(`coverage-report-${viewport.width}.png`),fullPage:true,animations:'disabled'})

    await page.getByRole('tab',{name:'网段与 VLAN'}).click()
    const networks = page.getByRole('region',{name:'网段与 VLAN 分布'})
    await expect(networks.getByRole('figure',{name:'IPv4 网段按发现身份排序'})).toBeVisible()
    await networks.getByText('IPv6',{exact:true}).click()
    await expect(networks.getByRole('figure',{name:'IPv6 网段按发现身份排序'})).toContainText('链路本地')
    await networks.getByText('VLAN',{exact:true}).click()
    await expect(networks.getByRole('link',{name:'查看 32 的发现记录'})).toHaveAttribute('href',/discovery_vlan=32/)
    await networks.getByText('IPv4',{exact:true}).click()
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
    await expect(pairCounts).toContainText('79.5%')
    await expect(pairCounts.getByRole('img',{name:/有效配对的身份与类型构成/})).toBeVisible()
    await expect(pairCounts).toContainText('身份待关联')
    await expect(pairCounts).toContainText('其中经硬件规则确认')
    await expect(mirror).toContainText('绑定状态截至')
    await expect(mirror.getByRole('region',{name:'镜像 IPv4 绑定时效'}).getByRole('progressbar',{name:'仅有过期绑定'})).toHaveAttribute('value','2100')
    await expect(page.getByLabel('镜像可见标识统计')).not.toBeVisible()
    await page.getByText('查看 MAC 管理位和厂商前缀').click()
    await expect(mirror.getByText('全局管理 · 匹配 OUI')).toBeVisible()
    await assertCoverageLayout(page)
    await page.screenshot({path:info.outputPath(`coverage-mirror-${viewport.width}.png`),fullPage:true,animations:'disabled'})
    await page.getByText('镜像明细与台账对照').click()
    await expect(page.getByLabel('镜像可见标识统计')).toBeVisible()
    await expect(page.getByRole('tab',{name:'历史核查'})).toHaveCount(0)
    expect(errors).toEqual([])
  })
}

for (const viewport of [{width:390,height:844}, {width:1280,height:800}, {width:1440,height:900}]) {
  test(`weekly and monthly hardware trends remain readable at ${viewport.width}px`, async ({page}, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(String(response.status())) })
    page.on('requestfailed', request => {
      if (request.failure()?.errorText !== 'net::ERR_ABORTED') errors.push(request.url())
    })
    await page.setViewportSize(viewport)
    for (const [hours, days] of [[168,7],[720,30]]) {
      await page.goto(`/devices/coverage?window=${hours}h`)
      const trend = page.getByRole('region', {name:`近 ${days} 天硬件身份变化`})
      await expect(trend).toContainText('仅上期有观测')
      await expect(trend).toContainText('覆盖待核查')
      await trend.scrollIntoViewIfNeeded()
      await assertCoverageLayout(page)
      await page.screenshot({path:info.outputPath(`trend-${days}d-${viewport.width}.png`),animations:'disabled'})
    }
    expect(errors).toEqual([])
  })
}

for (const viewport of [{width:390,height:844}, {width:1280,height:800}, {width:1440,height:900}]) {
  test(`planned IPv4 coverage uses the published ranges at ${viewport.width}px`, async ({page}, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    const cancelled = new Set<string>()
    const successful = new Set<string>()
    page.on('response', response => {
      if (response.ok()) successful.add(response.url())
      if (response.status() >= 400) errors.push(String(response.status()))
    })
    page.on('requestfailed', request => {
      if (request.failure()?.errorText === 'net::ERR_ABORTED') cancelled.add(request.url())
      else errors.push(request.url())
    })
    await page.setViewportSize(viewport)
    await page.goto('/devices/coverage?window=24h')
    await page.getByText('查看技术明细').click()
    const panel = page.getByRole('region', {name:'规划设备网段的可见 IPv4'})
    await expect(panel.locator('header strong')).toHaveText('2 个地址')
    await expect(panel.getByRole('listitem').first()).toHaveText('192.0.2.2-192.0.2.10 · 摄像头2 个地址')
    await expect(panel).toContainText('可用起点')
    await expect(panel).toContainText('镜像统计截至')
    await panel.scrollIntoViewIfNeeded()
    await assertCoverageLayout(page)
    expect(await panel.evaluate(e => e.scrollWidth <= e.clientWidth + 1)).toBe(true)
    await page.screenshot({path:info.outputPath('planned-ranges.png'), animations:'disabled'})
    expect([...cancelled].filter(url => !successful.has(url))).toEqual([])
    expect(errors).toEqual([])
  })
}

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`coverage overview reads as one funnel without overflow at ${viewport.width}px`, async ({page}, info) => {
    const errors:string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => {if(message.type()==='error')errors.push(message.text())})
    page.on('response', response => {if(response.status()>=400)errors.push(`${response.status()} ${response.url()}`)})
    await page.setViewportSize(viewport)
    await page.goto('/devices/coverage?window=24h')
    const funnel = page.getByRole('region',{name:'发现与识别'})
    await expect(funnel).toBeVisible()
    const labels = await funnel.locator('.coverage-funnel-label strong').allTextContents()
    expect(labels).toEqual(['共发现 IPv4 地址','有设备层报文','已有类型判断'])
    const layout = await page.evaluate(() => {
      const panels = [...document.querySelectorAll('.coverage-lead,.coverage-funnel,.coverage-panel,.coverage-funnel-step,.coverage-reasons li,.coverage-type-groups li')]
      const bars = [...document.querySelectorAll('.coverage-funnel-step .coverage-funnel-bar')].map(bar => bar.getBoundingClientRect().width)
      return {
        pageOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        clipped: panels.filter(el => el.getClientRects().length > 0 && (el.scrollWidth > el.clientWidth + 1 || el.getBoundingClientRect().right > innerWidth + 2)).length,
        narrowBars: bars.filter(width => width < 120).length,
        barSpread: Math.max(...bars) - Math.min(...bars),
        leadTop: document.querySelector('.coverage-lead')!.getBoundingClientRect().top,
        funnelBottom: document.querySelector('.coverage-funnel')!.getBoundingClientRect().bottom,
      }
    })
    expect(layout.pageOverflow).toBe(false)
    expect(layout.clipped).toBe(0)
    expect(layout.narrowBars).toBe(0)
    expect(layout.barSpread).toBeLessThanOrEqual(1)
    expect(layout.leadTop).toBeLessThan(viewport.height)
    if (viewport.width >= 1280) expect(layout.funnelBottom).toBeLessThan(viewport.height + 120)
    await expect(page.locator('body')).not.toContainText('未识别')
    await page.screenshot({path:info.outputPath(`coverage-overview-full-${viewport.width}.png`), fullPage:true, animations:'disabled'})
    await page.locator('.coverage-content > .coverage-panels').first().screenshot({path:info.outputPath(`coverage-overview-panels-${viewport.width}.png`), animations:'disabled'})
    expect(errors).toEqual([])
  })
}

for (const [width, height, selectedWindow] of [[390, 844, '24h'], [1280, 800, '168h'], [1440, 900, '720h']] as const) {
  test(`composition renders visual report cards with proportion bars and drill-down chips at ${width}px`, async ({page}, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`) })
    page.on('requestfailed', request => {
      if (request.failure()?.errorText !== 'net::ERR_ABORTED') errors.push(request.url())
    })
    await page.setViewportSize({width, height})
    await page.addInitScript(() => {
      const fetch = window.fetch.bind(window)
      window.fetch = (input, init) => {
        const url = new URL(input instanceof Request ? input.url : String(input), location.href)
        if (url.pathname.endsWith('/discovery/devices/metadata') && !url.searchParams.has('state')) {
          return Promise.resolve(Response.json({
            count_unit:'trusted_discovery_identity', window:url.searchParams.get('window'), as_of:'2026-11-26T01:00:00Z',
            total:253, identified:83, profile_typed:162, ip_product_only:8, dumb_terminals:118,
            types:[{device_type:'printer',count:64},{device_type:'camera',count:12},{device_type:'wireless_host',count:7}],
            candidate_types:[{device_type:'mobile',count:120},{device_type:'printer',count:15},{device_type:'environment_monitor',count:27}],
            ip_product_types:[{device_type:'switch',count:8}],
          }))
        }
        return fetch(input, init)
      }
    })
    await page.goto(`/devices/coverage?window=${selectedWindow}`)
    const section = page.getByRole('region', {name:'识别出了什么', exact:true})
    await expect(section.getByRole('table')).toHaveCount(0)
    await expect(section.locator('.report-confidence-strip')).toBeVisible()
    await expect(section).not.toContainText(/其中哑终端\s*[\d,]+\s*个/)

    const dumb = section.getByRole('region', {name:'哑终端', exact:true})
    await expect(dumb).toBeVisible()
    await expect(dumb.locator('h5')).toContainText('118')
    await expect(dumb.getByRole('link', {name:'打印机 硬件规则确认 64'})).toHaveAttribute('href', `/devices?tab=discovery&discovery_window=${selectedWindow}&discovery_state=identified&discovery_type=printer`)
    await expect(dumb.getByRole('link', {name:'打印机 画像识别 15'})).toHaveAttribute('href', `/devices?tab=discovery&discovery_window=${selectedWindow}&discovery_state=profile_typed&discovery_type=printer`)

    const network = section.getByRole('region', {name:'网络设备', exact:true})
    await expect(network).toBeVisible()
    await expect(network.locator('h5')).toContainText('7')
    await expect(network.getByRole('link', {name:'无线分布式主机 硬件规则确认 7'})).toHaveAttribute('href', `/devices?tab=discovery&discovery_window=${selectedWindow}&discovery_state=identified&discovery_type=wireless_host`)

    const products = section.getByRole('region', {name:'IP 自报的产品类型', exact:true})
    await expect(products).toBeVisible()
    await expect(products).toContainText('归属待核实')
    await expect(products.getByRole('link', {name:'交换机 8'})).toHaveAttribute('href', `/devices?tab=discovery&discovery_window=${selectedWindow}&discovery_state=ip_product_only&discovery_type=switch`)

    const geometry = await section.evaluate(element => {
      const blocks = [...element.querySelectorAll('.coverage-category-card, .coverage-ip-products-strip')]
      const pills = [...element.querySelectorAll<HTMLElement>('.coverage-basis-pill, .coverage-ip-product-chip')]
      const problems: string[] = []
      for (const block of blocks) {
        if (block.scrollWidth > block.clientWidth + 2) problems.push('block overflow')
      }
      for (const pill of pills) {
        const style = getComputedStyle(pill)
        if (style.whiteSpace !== 'nowrap' || style.flexShrink !== '0') problems.push('pill wrap')
      }
      const rgb = (color: string) => color.match(/[\d.]+/g)!.map(Number)
      const luminance = (color: number[]) => color.slice(0,3).reduce((total, value, i) => {
        const c = value / 255
        return total + (c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4) * [0.2126,0.7152,0.0722][i]
      }, 0)
      const linkContrasts = [...element.querySelectorAll('a')].map(link => {
        let background = [255,255,255]
        for (let el: Element | null = link; el; el = el.parentElement) {
          const fill = rgb(getComputedStyle(el).backgroundColor)
          if (fill.length === 3 || fill[3] === 1) { background = fill; break }
        }
        const a = luminance(rgb(getComputedStyle(link).color)), b = luminance(background)
        return (Math.max(a,b) + .05) / (Math.min(a,b) + .05)
      })
      const box = element.getBoundingClientRect()
      return {
        pageWidth:document.documentElement.scrollWidth,
        sectionWidth:box.width,
        left:box.left,
        right:box.right,
        blocks:blocks.length,
        pills:pills.length,
        linkMinContrast:Math.min(...linkContrasts),
        problems,
      }
    })
    expect(geometry.problems).toEqual([])
    expect(geometry.blocks).toBe(4)
    expect(geometry.pills).toBe(7)
    expect(geometry.linkMinContrast).toBeGreaterThanOrEqual(4.5)
    expect(geometry.pageWidth).toBeLessThanOrEqual(width + 2)
    expect(geometry.left).toBeGreaterThanOrEqual(-1)
    expect(geometry.right).toBeLessThanOrEqual(width + 1)
    await assertCoverageLayout(page)
    const domPath = info.outputPath(`composition-dom-${width}.json`)
    await writeFile(domPath, JSON.stringify(geometry, null, 2))
    await info.attach('composition-dom', {path:domPath, contentType:'application/json'})
    await section.screenshot({path:info.outputPath(`composition-${width}.png`), animations:'disabled'})

    for (const [label, state] of [
      ['打印机 硬件规则确认 64', 'identified'],
      ['打印机 画像识别 15', 'profile_typed'],
    ] as const) {
      await dumb.getByRole('link', {name:label}).click()
      await expect(page).toHaveURL(url => url.pathname === '/devices' && url.searchParams.get('tab') === 'discovery'
        && url.searchParams.get('discovery_window') === selectedWindow && url.searchParams.get('discovery_type') === 'printer'
        && url.searchParams.get('discovery_state') === state)
      await expect(page.getByLabel('已应用筛选')).toContainText('打印机')
      await page.goBack()
      await expect(section).toBeVisible()
    }
    expect(errors).toEqual([])
  })
}
