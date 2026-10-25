import { test, expect } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`discovered devices ${viewport.width}`, async ({page}, info) => {
    const errors:string[]=[]
    page.on('pageerror',error=>errors.push(error.message))
    page.on('console',message=>{if(message.type()==='error')errors.push(message.text())})
    page.on('response',response=>{if(response.status()>=400)errors.push(`${response.status()} ${response.url()}`)})
    await page.setViewportSize(viewport)
    await page.goto('/devices?tab=discovery')
    await expect(page.getByRole('heading',{name:'发现设备',level:1})).toBeVisible()
    await expect(page.getByText('192.0.2.10',{exact:true}).filter({visible:true})).toBeVisible()
    await expect(page.getByText('HP LaserJet Pro MFP',{exact:true}).filter({visible:true})).toBeVisible()
    await expect(page.getByText('服务证据有效不代表设备在线。',{exact:false})).toBeVisible()
    const probe=await page.evaluate(()=>({
      overflow:document.documentElement.scrollWidth>innerWidth+2,
      panelRight:document.querySelector('.passive-discovery-panel')!.getBoundingClientRect().right,
      controls:[...document.querySelectorAll('.passive-discovery-panel .ant-btn,.passive-discovery-panel .ant-tag')].filter(e=>e.getBoundingClientRect().width>0).map(e=>({text:e.textContent,wrap:getComputedStyle(e).whiteSpace,shrink:getComputedStyle(e).flexShrink})),
      rowDisplay:getComputedStyle(document.querySelector('.passive-discovery-panel .ant-table-tbody > tr[data-row-key]')!).display,
      selected:[...document.querySelectorAll('.ant-menu-item-selected')].map(e=>({text:e.textContent,color:getComputedStyle(e).color,background:getComputedStyle(e).backgroundColor})),
      titleSize:getComputedStyle(document.querySelector('h1')!).fontSize,
    }))
    expect(probe.overflow).toBe(false)
    expect(probe.panelRight).toBeLessThanOrEqual(viewport.width)
    expect(probe.controls.every(c=>c.wrap==='nowrap'&&c.shrink==='0')).toBe(true)
    if(viewport.width<560)expect(probe.rowDisplay).not.toBe('table-row')
    await writeFile(info.outputPath('dom.json'),JSON.stringify(probe,null,2))
    await page.screenshot({path:info.outputPath('discovered-devices.png'),fullPage:true,animations:'disabled'})
    await page.getByRole('button',{name:'查看证据'}).first().click()
    await expect(page.getByRole('dialog')).toContainText('DNS-SD 服务响应与地址记录自动关联')
    await page.screenshot({path:info.outputPath('evidence.png'),fullPage:true,animations:'disabled'})
    await page.getByRole('button',{name:'Close',exact:true}).click()
    await page.getByRole('button',{name:'更多筛选'}).click()
    await expect(page.getByRole('combobox',{name:'设备类型'})).toBeVisible()
    await page.getByRole('combobox',{name:'发现协议'}).click()
    await page.getByText('DHCP',{exact:true}).last().click()
    await expect(page).toHaveURL(/discovery_protocol=dhcp/)
    await expect(page.getByText('第 1 页',{exact:true})).toBeVisible()
    await page.screenshot({path:info.outputPath('filters.png'),fullPage:true,animations:'disabled'})
    expect(errors).toEqual([])
    await page.goto('/discovery?tab=records&discovery_protocol=dns_sd')
    await expect(page).toHaveURL(/tab=discovery/)
    await expect(page).toHaveURL(/discovery_protocol=dns_sd/)
    await expect(page.getByRole('heading',{name:'发现设备',level:1})).toBeVisible()
  })
}
