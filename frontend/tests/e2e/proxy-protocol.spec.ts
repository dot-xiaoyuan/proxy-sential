import { expect,test } from '@playwright/test'
import { mkdir,writeFile } from 'node:fs/promises'
import path from 'node:path'
for(const width of [390,1280,1440]) test(`proxy protocol evidence ${width}`,async({page})=>{
 await page.setViewportSize({width,height:width===390?844:width===1280?800:900})
 await page.goto('/events/proxy-fixture')
 await expect(page.getByRole('heading',{name:'检测到成功代理连接',exact:true})).toBeVisible()
 await expect(page.getByText('staff-001',{exact:true})).toBeVisible()
 const folder=path.resolve('test-results/proxy-protocol');await mkdir(folder,{recursive:true})
 await page.locator('.proxy-protocol-evidence').screenshot({path:path.join(folder,`event-${width}.png`),animations:'disabled'})
 const probe=await page.locator('.proxy-protocol-evidence').evaluate(e=>({overflow:document.documentElement.scrollWidth>innerWidth+2,padding:getComputedStyle(e).paddingTop,border:getComputedStyle(e).borderTopColor,radius:getComputedStyle(e).borderRadius,bad:[...e.querySelectorAll('.ant-tag')].some(t=>getComputedStyle(t).whiteSpace!=='nowrap'||getComputedStyle(t).flexShrink!=='0'),heading:getComputedStyle(e.querySelector('h5')!).fontWeight}))
 await writeFile(path.join(folder,`dom-${width}.json`),JSON.stringify(probe,null,2));expect(probe.overflow).toBe(false);expect(probe.bad).toBe(false);expect(probe.radius).toBe('8px');expect(probe.border).toBe('rgb(226, 232, 240)');expect(probe.padding).toBe(width===390?'14px':'20px');expect(Number(probe.heading)).toBeGreaterThanOrEqual(500)
 await page.goto('/actions?tab=executions');await expect(page.getByText('检测到成功代理连接，需人工复核是否违规',{exact:true})).toBeVisible()
 await page.locator('.policy-execution').screenshot({path:path.join(folder,`policy-${width}.png`),animations:'disabled'})
 await page.goto('/policies');await page.getByRole('button',{name:'新建设备配额策略',exact:true}).click()
 await expect(page.getByRole('dialog').locator('.ant-steps').getByText('配额超限认定条件',{exact:true})).toBeVisible()
 await expect(page.getByLabel('触发类型')).toHaveCount(0)
 expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2)).toBe(false)
})
