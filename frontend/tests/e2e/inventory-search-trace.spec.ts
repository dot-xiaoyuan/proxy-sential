import { expect,test } from '@playwright/test'
import { mkdir,writeFile } from 'node:fs/promises'
import path from 'node:path'

test('typed search is URL-persisted and detail traces are lazy backend pages',async({page})=>{
 const requests:string[]=[]
 await page.addInitScript(()=>{const original=window.fetch.bind(window);(window as unknown as {inventoryFetches:string[]}).inventoryFetches=[];window.fetch=(input,init)=>{const url=new URL(typeof input==='string'?input:input instanceof Request?input.url:input.href,location.href);(window as unknown as {inventoryFetches:string[]}).inventoryFetches.push(url.pathname+url.search);return original(input,init)}})
 page.on('request',r=>requests.push(r.url()))
 await page.goto('/devices?view=history&search_type=mac&q=00:1b:21:00:00:41')
 await expect(page.getByPlaceholder('输入完整 MAC')).toHaveValue('00:1b:21:00:00:41')
 await expect(page.locator('.device-desktop-table .ant-table-row')).toHaveCount(1)
 await page.locator('.device-desktop-table .device-mac-link').click()
 await expect(page.getByRole('heading',{name:/office-mac41.local/})).toBeVisible()
 expect(await page.evaluate(()=>(window as unknown as {inventoryFetches:string[]}).inventoryFetches.filter(u=>u.includes('/observations')).length)).toBe(0)
 expect(await page.evaluate(()=>(window as unknown as {inventoryFetches:string[]}).inventoryFetches.filter(u=>u.includes('limit=500')).length)).toBe(0)
 await page.getByRole('tab',{name:'身份溯源'}).click()
 await expect(page.locator('.endpoint-observation-card')).toHaveCount(20)
 await page.getByRole('button',{name:'下一页',exact:true}).click()
 await expect(page.locator('.endpoint-trace-pagination')).toContainText('第 2 页')
 await expect(page.locator('.endpoint-observation-card').first()).toContainText('mock-event-20')
 await page.getByRole('button',{name:'下一页',exact:true}).click()
 await expect(page.locator('.endpoint-observation-card')).toHaveCount(5)
 await page.getByRole('link',{name:'返回终端列表'}).click()
 await expect(page).toHaveURL(/search_type=mac/)
})

for(const viewport of [{width:390,height:844},{width:743,height:774},{width:1280,height:800},{width:1440,height:900}]){
 test(`indexed ledger and trace visual contract ${viewport.width}`,async({page})=>{
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));await page.setViewportSize(viewport)
  const dir=path.resolve('../artifacts/inventory-indexed-trace',String(viewport.width));await mkdir(dir,{recursive:true})
  await page.addInitScript(()=>{const original=window.fetch.bind(window);window.fetch=async(input,init)=>{const response=await original(input,init);const url=new URL(typeof input==='string'?input:input instanceof Request?input.url:input.href,location.href);if(url.pathname.endsWith('/device-inventory')&&response.ok){const data=await response.json();data.read_model_state={available:true,complete:false,updating:true,as_of:new Date().toISOString(),status:'backfilling'};return new Response(JSON.stringify(data),{status:response.status,headers:response.headers})}return response}})
  await page.goto('/devices?view=history');await expect(page.locator('.device-semantic-icon').first()).toBeVisible()
  await expect(page.getByText('历史关联正在回填')).toBeVisible()
  const probe=async()=>page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,controls:[...document.querySelectorAll('main .ant-btn,main .ant-tag')].filter(e=>e.getBoundingClientRect().width>0).map(e=>({nowrap:getComputedStyle(e).whiteSpace,shrink:getComputedStyle(e).flexShrink})),cardRadius:getComputedStyle(document.querySelector('.surface')!).borderRadius,icons:[...document.querySelectorAll('.device-semantic-icon')].map(e=>({width:e.getBoundingClientRect().width,height:e.getBoundingClientRect().height,svg:e.querySelector('svg')?.getBoundingClientRect().width}))}))
  const ledger=await probe();expect(ledger.overflow).toBe(false);expect(ledger.controls.every(c=>c.nowrap==='nowrap'&&c.shrink==='0')).toBe(true);expect(ledger.icons.every(i=>i.width===24&&i.height===24&&i.svg===18)).toBe(true)
  await page.screenshot({path:path.join(dir,'ledger.png')})
  await page.goto('/devices/mac%3A00%3A1b%3A21%3A00%3A00%3A41?tab=identity');await expect(page.locator('.endpoint-observation-card')).toHaveCount(20)
  const trace=await probe();expect(trace.overflow).toBe(false);expect(trace.cardRadius).toBe('8px');expect(trace.controls.every(c=>c.nowrap==='nowrap'&&c.shrink==='0')).toBe(true)
  await page.screenshot({path:path.join(dir,'trace.png')});await writeFile(path.join(dir,'dom.json'),JSON.stringify({ledger,trace,errors},null,2));expect(errors).toEqual([])
 })
}
