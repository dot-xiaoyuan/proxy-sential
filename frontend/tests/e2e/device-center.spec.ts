import { test,expect } from '@playwright/test'
for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
 test(`device center compact layout ${viewport.width}`,async({page})=>{
  await page.setViewportSize(viewport)
  const errors:string[]=[];page.on('pageerror',error=>errors.push(error.message))
  await page.goto('/devices')
  await expect(page.getByRole('heading',{name:'设备中心',exact:true})).toBeVisible()
  for(const tab of ['终端','网络设备','哑终端']){
   await page.getByRole('tab',{name:tab,exact:true}).click()
   await expect(page.getByRole('tab',{name:tab,exact:true})).toHaveAttribute('aria-selected','true')
   if(tab==='哑终端')await expect(page.locator('.passive-protocol-card').first()).toContainText('采集正常')
   await expect(page.locator('.center-primary-ip:visible').first()).toBeVisible()
   await page.screenshot({path:`test-results/device-center-${tab}-${viewport.width}.png`,fullPage:true})
   const audit=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+1,buttons:[...document.querySelectorAll('.ant-btn,.ant-tag')].filter(el=>{const s=getComputedStyle(el);return s.display!=='none'&&(s.whiteSpace!=='nowrap'||s.flexShrink!=='0')}).map(el=>el.textContent),primary:[...document.querySelectorAll('.center-primary-ip')].map(el=>{const s=getComputedStyle(el);return {font:s.fontSize,weight:s.fontWeight,whiteSpace:s.whiteSpace,overflow:s.textOverflow}})}))
   expect(audit.overflow).toBe(false);expect(audit.buttons).toEqual([])
   await test.info().attach(`dom-${tab}-${viewport.width}`,{body:JSON.stringify(audit,null,2),contentType:'application/json'})
   for(const p of audit.primary){expect(p).toEqual({font:'14px',weight:'600',whiteSpace:'nowrap',overflow:'ellipsis'})}
  }
  await page.getByRole('button',{name:'查看证据'}).filter({visible:true}).first().click()
  await page.getByRole('tab',{name:'变化历史',exact:true}).click()
  await expect(page.getByText('27 次观测').first()).toBeVisible()
  await page.getByRole('button',{name:'查看原始记录'}).first().click()
  await expect(page.locator('.center-raw-history details')).toHaveCount(10)
  await page.screenshot({path:`test-results/device-center-history-${viewport.width}.png`,fullPage:true})
  expect(errors).toEqual([])
 })
}
test('legacy links and canonical detail return context',async({page})=>{
 await page.goto('/discovery?tab=routers&router_keyword=Huawei');await expect(page).toHaveURL(/devices\?.*tab=network/)
 await expect(page.getByRole('textbox',{name:''}).first()).toHaveValue('Huawei')
 await page.getByRole('link',{name:'查看详情'}).first().click();await expect(page).toHaveURL(/devices\/network\//)
 await page.getByRole('tab',{name:'变化历史'}).click();await expect(page.getByText('27 次观测').first()).toBeVisible()
 await page.getByRole('link',{name:'返回设备中心'}).click();await expect(page).toHaveURL(/router_keyword=Huawei/)
 await page.goto('/shared-access?tab=devices');await expect(page).toHaveURL(/devices\?.*tab=network/)
 await page.goto('/shared-access');await expect(page.getByRole('tab',{name:'当前共享'})).toHaveAttribute('aria-selected','true');await expect(page.getByRole('tab',{name:'设备档案'})).toHaveCount(0)
})
