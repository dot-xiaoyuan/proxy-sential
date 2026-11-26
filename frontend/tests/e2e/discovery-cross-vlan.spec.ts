import { expect, test } from '@playwright/test'

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`跨 VLAN 发现身份和采集范围 ${viewport.width}`, async ({page}, info) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', msg => {if (msg.type() === 'error') errors.push(msg.text())})
    page.on('response', res => {if (res.status() >= 400) errors.push(String(res.status()) + ' ' + res.url())})
    await page.setViewportSize(viewport)
    await page.addInitScript(() => {
      const original = window.fetch.bind(window)
      window.fetch = async (input, init) => {
        const response = await original(input, init)
        const url = new URL(input instanceof Request ? input.url : input, location.href)
        if (!response.ok || !/\/discovery\/devices(?:\/metadata)?$/.test(url.pathname)) return response
        const scoped = url.searchParams.get('identity_scope') === 'scoped_devices'
        const value = await response.json()
        const at = new Date().toISOString()
        value.classification_version = 'passive-hardware/v2'
        value.count_unit = scoped ? 'trusted_discovery_identity' : 'cross_vlan_discovery_identity'
        if (url.pathname.endsWith('/metadata')) {
          Object.assign(value,{total:scoped?487:1,candidate:scoped?487:1,identified:0})
        } else {
          value.items = [{id:'scope-a',sensor_id:'campus-204',domain:'mirror',vlan:'2701/14',
            mac:'c4:07:78:08:20:02',primary_ip:'222.204.69.254',current_addresses:['222.204.69.254'],
            vlan_scope_count:scoped?undefined:487,classification_status:'candidate',hardware_type_status:'candidate',
            candidate_device_type:'desktop',identity_kind:'mac',protocols:['arp'],observations:[],capabilities:[],
            addresses:['222.204.69.254'],current:true,first_seen:at,last_seen:at}]
        }
        return Response.json(value)
      }
    })
    await page.goto('/devices?tab=discovery&discovery_search=222.204.69.254')
    await expect(page.getByText('共 1 个发现身份').first()).toBeVisible()
    const scopeButton = page.getByRole('button',{name:'487 个采集范围'})
    await expect(scopeButton).toBeVisible()
    const probe = await scopeButton.evaluate(el => ({overflow:document.documentElement.scrollWidth>innerWidth+1,
      wrap:getComputedStyle(el).whiteSpace,shrink:getComputedStyle(el).flexShrink}))
    expect(probe).toEqual({overflow:false,wrap:'nowrap',shrink:'0'})
    await page.screenshot({path:info.outputPath('grouped.png')})
    await page.getByRole('button',{name:'查看详情'}).first().click()
    const detail=page.getByRole('dialog')
    await expect(detail).toContainText('此身份出现在 487 个采集范围')
    await page.screenshot({path:info.outputPath('detail.png')})
    await detail.getByRole('button',{name:'按范围查看此 MAC'}).click()
    await expect(page).toHaveURL(/discovery_identity_scope=scoped_devices/)
    await expect(page.getByText('共 487 条范围记录').first()).toBeVisible()
    expect(errors).toEqual([])
  })
}
