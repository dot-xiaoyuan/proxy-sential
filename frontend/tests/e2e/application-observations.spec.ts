import { expect, test } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
const viewports=[{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]
for(const viewport of viewports) test(`application observations ${viewport.width}`,async({page})=>{
 await page.setViewportSize(viewport)
 await page.goto('/activity')
 await expect(page.getByRole('heading',{name:'应用相关服务访问'})).toBeVisible()
 await expect(page.getByText('流量统计口径',{exact:true})).toBeVisible()
 await expect(page.getByRole('button',{name:'微信',exact:true})).toBeVisible()
 const folder=path.resolve('test-results/application-visuals');await mkdir(folder,{recursive:true})
 await page.locator('.application-panel h4').evaluate(el=>el.scrollIntoView({block:'start'}))
 await page.screenshot({path:path.join(folder,`activity-${viewport.width}.png`),animations:'disabled'})
 await page.getByRole('button',{name:'微信',exact:true}).scrollIntoViewIfNeeded()
 await page.screenshot({path:path.join(folder,`cards-${viewport.width}.png`),animations:'disabled'})
 const probe=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+2,buttons:[...document.querySelectorAll('.application-panel .ant-btn,.application-panel .ant-tag')].filter(el=>{const s=getComputedStyle(el);return s.whiteSpace!=='nowrap'||s.flexShrink!=='0'}).map(el=>el.textContent),cards:getComputedStyle(document.querySelector('.application-mobile-cards')!).display,heading:getComputedStyle(document.querySelector('.application-panel h4')!).fontWeight}))
 expect(probe.overflow).toBe(false);expect(probe.buttons).toEqual([]);expect(Number(probe.heading)).toBeGreaterThanOrEqual(500);expect(probe.cards).toBe(viewport.width<560?'block':'none')
 await page.getByRole('button',{name:'微信',exact:true}).click()
 await expect(page.getByText('long-subdomain.weixin.qq.com',{exact:true})).toBeVisible()
 await expect(page.getByText('tls.sni / 未评估',{exact:true})).toBeVisible()
 await expect.poll(()=>page.locator('.ant-drawer-content-wrapper').evaluate(el=>Math.round(el.getBoundingClientRect().right))).toBe(viewport.width)
 await page.screenshot({path:path.join(folder,`detail-${viewport.width}.png`),animations:'disabled'})
 expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2)).toBe(false)
 await page.keyboard.press('Escape')
 await page.goto('/settings/rules')
 await page.getByRole('tab',{name:'应用域名特征库'}).click()
 await expect(page.getByLabel('特征库服务地址')).toHaveValue('http://192.168.0.30:8081')
 await expect(page.getByRole('switch',{name:'启用应用识别'})).toBeChecked()
 await expect(page.getByRole('button',{name:'保存运行配置'})).toBeEnabled()
 await expect(page.getByRole('button',{name:'拉取并回填'})).toBeEnabled()
 await expect(page.getByRole('button',{name:'校验并导入'})).toBeDisabled()
 await expect(page.getByRole('button',{name:'重分类最近 7 天'})).toBeEnabled()
 await page.locator('.application-runtime-config').scrollIntoViewIfNeeded()
 await page.screenshot({path:path.join(folder,`library-${viewport.width}.png`),animations:'disabled'})
 for(let i=0;i<3;i++){await page.locator('.application-task-card').nth(i).scrollIntoViewIfNeeded();await page.locator('.application-task-card').nth(i).screenshot({path:path.join(folder,`task-${i}-${viewport.width}.png`),animations:'disabled'})}
 await page.locator('[aria-label="历史任务控制"]').scrollIntoViewIfNeeded()
 await page.screenshot({path:path.join(folder,`controls-${viewport.width}.png`),animations:'disabled'})
 expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2)).toBe(false)
 const runtimeProbe=await page.locator('.application-runtime-config').evaluate(el=>({padding:getComputedStyle(el).paddingTop,border:getComputedStyle(el).borderTopColor,radius:getComputedStyle(el).borderRadius,bad:[...el.querySelectorAll('.ant-btn')].some(b=>getComputedStyle(b).whiteSpace!=='nowrap'||getComputedStyle(b).flexShrink!=='0')}))
 const taskProbe=await page.locator('.application-task-grid').evaluate(el=>({cards:[...el.querySelectorAll('.application-task-card')].map(card=>{const cs=getComputedStyle(card);return {padding:cs.paddingTop,border:cs.borderTopColor,radius:cs.borderRadius,overflow:card.scrollWidth>card.clientWidth+1}}),inline:el.querySelectorAll('[style]').length}))
 for(const card of taskProbe.cards){expect(card.overflow).toBe(false);expect(card.radius).toBe('8px');expect(card.border).toBe('rgb(226, 232, 240)');expect(card.padding).toBe(viewport.width<560?'14px':'20px')}
 const selected=await page.locator('.ant-tabs-tab-active .ant-tabs-tab-btn').evaluate(el=>{
 const fg=getComputedStyle(el).color;let parent:Element|null=el;let bg='rgb(255, 255, 255)'
 while(parent){const color=getComputedStyle(parent).backgroundColor;if(color!=='rgba(0, 0, 0, 0)'&&color!=='transparent'){bg=color;break}parent=parent.parentElement}
 const luminance=(color:string)=>{const values=(color.match(/[\d.]+/g)||[]).slice(0,3).map(Number).map(x=>{const n=x/255;return n<=0.04045?n/12.92:((n+0.055)/1.055)**2.4});return values[0]*0.2126+values[1]*0.7152+values[2]*0.0722}
 const a=luminance(fg),b=luminance(bg);return {foreground:fg,background:bg,contrast:(Math.max(a,b)+0.05)/(Math.min(a,b)+0.05)}
 })
 expect(selected.contrast).toBeGreaterThanOrEqual(4.5)
 await writeFile(path.join(folder,`probe-${viewport.width}.json`),JSON.stringify({viewport,activity:probe,runtime:runtimeProbe,tasks:taskProbe,selected},null,2))
 expect(taskProbe.cards).toHaveLength(3)
 expect(runtimeProbe.bad).toBe(false);expect(runtimeProbe.radius).toBe('8px');expect(runtimeProbe.border).toBe('rgb(226, 232, 240)');expect(runtimeProbe.padding).toBe(viewport.width<560?'14px':'20px')
})

test('history control shows requested and effective states',async({page})=>{
 test.setTimeout(60000)
 await page.goto('/settings/rules')
 await page.getByRole('tab',{name:'应用域名特征库'}).click()
 await page.getByRole('button',{name:'重分类最近 7 天',exact:true}).click()
 await expect(page.getByRole('button',{name:'暂停重分类',exact:true})).toBeEnabled()
 await page.getByRole('button',{name:'暂停重分类',exact:true}).click()
 await expect(page.getByText('已请求暂停，等待批次提交',{exact:true})).toBeVisible()
 await expect(page.getByRole('button',{name:'恢复重分类',exact:true})).toBeEnabled({timeout:25000})
 await page.getByRole('button',{name:'恢复重分类',exact:true}).click()
 await expect(page.getByRole('button',{name:'取消重分类',exact:true})).toBeEnabled()
 await page.getByRole('button',{name:'取消重分类',exact:true}).click()
 await expect(page.getByText('已请求取消，等待批次提交',{exact:true})).toBeVisible()
 await expect(page.getByText('已取消',{exact:true})).toBeVisible({timeout:25000})
})
