import { expect, test } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'

const output='../artifacts/identity-pipeline-20261013/ui'
for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
 test(`authentication manual refresh and layout ${viewport.width}`,async({page})=>{
  const errors:string[]=[]
  const failed:string[]=[]
  page.on('pageerror',e=>errors.push(e.message))
  page.on('console',e=>{if(e.type()==='error')errors.push(e.text())})
  page.on('response',r=>{if(r.url().includes('/api/v1/')&&r.status()>=400)failed.push(`${r.status()} ${r.url()}`)})
  await page.setViewportSize(viewport)
  await page.addInitScript(()=>{
   const original=window.fetch
   const counters:Record<string,number>={}
   Object.assign(window,{identityRequestCounts:counters})
   window.fetch=async(...args)=>{
    const url=String(args[0] instanceof Request?args[0].url:args[0])
    if(/\/integrations\/identity\/bridge$|\/actions\/connectors$|\/integrations\/srun4k$/.test(url))counters[url]=(counters[url]??0)+1
    return original(...args)
   }
  })
  await page.clock.install()
  await page.goto('/settings/actions')
  await expect(page.getByText('当前账号',{exact:true})).toBeVisible()
  await expect(page.getByText('当前会话',{exact:true})).toBeVisible()
  await expect(page.getByText('服务端待处理',{exact:true})).toBeVisible()
  const initial=await page.evaluate(()=>Reflect.get(window,'identityRequestCounts'))
  expect(Object.values(initial).length).toBeGreaterThan(0)
  await page.clock.fastForward(5*60*1000)
  await page.evaluate(()=>{window.dispatchEvent(new Event('focus'));window.dispatchEvent(new Event('online'))})
  expect(await page.evaluate(()=>Reflect.get(window,'identityRequestCounts'))).toEqual(initial)
  await page.getByRole('button',{name:'刷新认证状态'}).click()
  await expect.poll(()=>page.evaluate(()=>Object.values(Reflect.get(window,'identityRequestCounts') as Record<string,number>).reduce((a,b)=>a+b,0))).toBe(Object.values(initial).reduce((a,b)=>Number(a)+Number(b),0)+1)
  await page.getByRole('button',{name:'刷新数据'}).click()
  await page.clock.runFor(100)
  const final=await page.evaluate(()=>Reflect.get(window,'identityRequestCounts'))
  for(const [key,count]of Object.entries(initial))expect(final[key]).toBe(Number(count)+(key.endsWith('/identity/bridge')?2:1))
  const probe=await page.evaluate(()=>({
   width:innerWidth,overflow:document.documentElement.scrollWidth>innerWidth+2,
   controls:[...document.querySelectorAll('.page .ant-btn,.page .ant-tag')].map(el=>({text:el.textContent,nowrap:getComputedStyle(el).whiteSpace,shrink:getComputedStyle(el).flexShrink})),
   cards:[...document.querySelectorAll('.identity-bridge-panel,.four-k-authority-card')].map(el=>({border:getComputedStyle(el).borderColor,radius:getComputedStyle(el).borderRadius,padding:getComputedStyle(el.querySelector('.ant-card-body')!).padding})),
   forbidden:[...document.querySelectorAll('.page')].map(el=>el.textContent??'').filter(s=>/未识别|未获取|未关联|未观测/.test(s))
  }))
  expect(probe.overflow).toBe(false)
  expect(probe.controls.filter(c=>c.nowrap!=='nowrap'||c.shrink!=='0')).toEqual([])
  expect(probe.forbidden).toEqual([])
  expect(errors).toEqual([]);expect(failed).toEqual([])
  await mkdir(output,{recursive:true})
  await writeFile(`${output}/${viewport.width}-dom.json`,JSON.stringify({probe,initial,final,errors,failed},null,2))
  await page.screenshot({path:`${output}/${viewport.width}x${viewport.height}.png`,fullPage:true})
  await page.locator('.app-content').evaluate(el=>{el.scrollTop=el.scrollHeight})
  await page.screenshot({path:`${output}/${viewport.width}x${viewport.height}-bottom.png`,fullPage:true})
 })
}
