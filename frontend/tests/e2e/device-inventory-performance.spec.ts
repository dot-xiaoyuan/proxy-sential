import { expect,test } from '@playwright/test'
import { writeFile } from 'node:fs/promises'

test('list renders before delayed exact metadata and campus filters are lazy',async({page})=>{
 await page.addInitScript(()=>{
  const fetchOriginal=window.fetch.bind(window)
  const pending:Array<()=>void>=[]
  ;(window as unknown as {releaseInventoryStatistics:()=>void}).releaseInventoryStatistics=()=>pending.splice(0).forEach(release=>release())
  window.fetch=(input,init)=>{
   const url=new URL(typeof input==='string'?input:input instanceof Request?input.url:input.href,location.href)
   if(url.pathname==='/api/v1/device-inventory/metadata')return new Promise((resolve,reject)=>pending.push(()=>{void fetchOriginal(input,init).then(resolve,reject)}))
   return fetchOriginal(input,init)
  }
 })
 let organizations=0
 page.on('request',request=>{if(new URL(request.url()).pathname==='/api/v1/organization')organizations++})
 await page.goto('/devices?view=history&window=24h')
 await expect(page.locator('.device-desktop-table .ant-table-row')).toHaveCount(6)
 await expect(page.getByRole('button',{name:'下一页',exact:true})).toBeVisible()
 await expect(page.getByText('0 个终端身份')).toHaveCount(0)
 expect(organizations).toBe(0)
 await page.evaluate(()=>(window as unknown as {releaseInventoryStatistics:()=>void}).releaseInventoryStatistics())
 await expect(page.getByText('6 个终端身份')).toBeVisible()
 await expect(page.locator('.app-server-pagination')).toBeVisible()
 await page.locator('.device-filter-disclosure summary').click()
 await expect(page.getByPlaceholder('院系')).toBeVisible()
})

test('statistics failure does not replace rows and can be retried separately',async({page})=>{
 await page.addInitScript(()=>{
  const fetchOriginal=window.fetch.bind(window)
  let fail=true
  window.fetch=(input,init)=>{
   const url=new URL(typeof input==='string'?input:input instanceof Request?input.url:input.href,location.href)
   if(url.pathname==='/api/v1/device-inventory/metadata'&&fail){fail=false;return Promise.resolve(new Response('statistics unavailable',{status:503}))}
   return fetchOriginal(input,init)
  }
 })
 await page.goto('/devices?view=history&window=24h')
 await expect(page.getByRole('button',{name:'重试统计'})).toBeVisible()
 await expect(page.locator('.device-desktop-table .ant-table-row')).toHaveCount(6)
 await page.getByRole('button',{name:'重试统计'}).click()
 await expect(page.getByText('6 个终端身份')).toBeVisible()
})

test('manual refresh bypasses both caches and keeps visible rows',async({page})=>{
 const refreshed:string[]=[]
 page.on('request',request=>{const url=new URL(request.url());if(url.pathname.startsWith('/api/v1/device-inventory')&&url.searchParams.get('refresh')==='true')refreshed.push(url.pathname)})
 await page.goto('/devices?view=history&window=24h')
 await expect(page.getByText('6 个终端身份')).toBeVisible()
 await page.getByRole('button',{name:'刷新数据'}).click()
 await expect(page.locator('.device-desktop-table .ant-table-row')).toHaveCount(6)
 await expect.poll(()=>new Set(refreshed).size).toBe(2)
 expect(refreshed).toContain('/api/v1/device-inventory')
 expect(refreshed).toContain('/api/v1/device-inventory/metadata')
 await expect(page.locator('.device-list-freshness')).toContainText('列表刷新')
})

test('sidebar navigation records entry to visible rows independently of metadata',async({page},info)=>{
 await page.goto('/overview')
 await page.getByText('资产与画像',{exact:true}).click()
 await page.getByRole('link',{name:'终端画像',exact:true}).click()
 await expect(page.locator('.device-desktop-table .ant-table-row')).toHaveCount(4)
 await expect.poll(()=>page.evaluate(()=>performance.getEntriesByName('device-inventory-visible').length)).toBe(1)
 const measures=await page.evaluate(()=>['device-inventory-visible','device-inventory-api'].map(name=>({name,duration:performance.getEntriesByName(name).at(-1)?.duration})))
 await info.attach('navigation-timing',{body:JSON.stringify(measures),contentType:'application/json'})
 await writeFile(info.outputPath('timing.json'),JSON.stringify(measures,null,2))
 expect(measures[0].duration).toBeLessThan(1000)
})
