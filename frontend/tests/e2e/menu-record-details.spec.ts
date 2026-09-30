import {test,expect} from '@playwright/test'

test('business detail translates only states and preserves identifiers and real errors',async({page},info)=>{
 await page.setViewportSize({width:390,height:844})
 await page.addInitScript(()=>{const original=window.fetch;window.fetch=async(...args)=>String(args[0]).includes('/api/v1/audit-logs/audit-preserve')?new Response(JSON.stringify({audit_id:'audit-preserve',actor:'normal',action:'record',target:'confirmed',outcome:'failed',summary:'未获取上游响应，连接失败',created_at:'2026-09-30T12:00:00Z'}),{headers:{'Content-Type':'application/json'}}):original(...args)})
 await page.goto('/audit/audit-preserve');await expect(page.getByRole('heading',{name:'审计详情'})).toBeVisible()
 const summary=page.locator('.ant-descriptions')
 for(const value of ['normal','record','confirmed','失败','未获取上游响应，连接失败'])await expect(summary.getByText(value,{exact:true})).toBeVisible()
 expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2)).toBe(false)
 await page.screenshot({path:info.outputPath('audit-preserve.png'),fullPage:true,animations:'disabled'})
})
