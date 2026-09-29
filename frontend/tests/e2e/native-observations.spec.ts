import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width,height] of [[390,844],[1280,800],[1440,900]]) test(`native action observations ${width}`,async({page})=>{
  await page.setViewportSize({width,height})
  await page.goto('/settings/actions')
  await expect(page.getByRole('tab',{name:/处置动作/})).toBeVisible()
  await page.evaluate(async()=>{await fetch('/api/v1/actions/execute',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action_type:'disconnect',subject_id:'campus-lab',account_id:'campus-lab',connector_id:'portal-gateway',mode:'shadow'})})})
  await page.getByRole('button',{name:'刷新数据'}).click()
  await page.getByRole('tab',{name:/处置动作/}).click()
  await page.getByRole('button',{name:'执行记录',exact:true}).filter({visible:true}).first().click()
  const dialog=page.getByRole('dialog')
  await expect(dialog.getByText('发送结果不确定',{exact:true})).toBeVisible()
  await expect(dialog.getByText('记录 9007199254740993',{exact:true})).toBeVisible()
  await dialog.getByRole('button',{name:'较早记录'}).click()
  await expect(dialog.getByText('记录 9007199254740992',{exact:true})).toBeVisible()
  await expect(dialog.getByRole('button',{name:'较早记录'})).toBeDisabled()
  await dialog.getByRole('button',{name:'较新记录'}).click()
  await expect(dialog.getByText('发送结果不确定',{exact:true})).toBeVisible()
  const probe=await dialog.evaluate(el=>({overflow:el.scrollWidth>el.clientWidth+2,bad:[...el.querySelectorAll('.native-observations .ant-btn,.native-observations .ant-tag')].filter(e=>{const s=getComputedStyle(e);return s.whiteSpace!=='nowrap'||s.flexShrink!=='0'}).map(e=>e.textContent),radius:getComputedStyle(el.querySelector('.native-observation')!).borderRadius,padding:getComputedStyle(el.querySelector('.native-observation')!).paddingTop}))
  expect(probe.overflow).toBe(false);expect(probe.bad).toEqual([]);expect(probe.radius).toBe('8px');expect(probe.padding).toBe(width===390?'14px':'20px')
  const dir=path.resolve('test-results/native-observations');await mkdir(dir,{recursive:true});await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2))
  await dialog.screenshot({path:path.join(dir,`${width}.png`),animations:'disabled'})
  await page.evaluate(()=>{const original=window.fetch;window.fetch=(...args)=>String(args[0]).includes('/native-observations')?Promise.reject(new Error('simulated unavailable')):original(...args)})
  await dialog.getByRole('button',{name:'刷新记录'}).click()
  await expect(dialog.getByText('执行记录查询失败',{exact:true})).toBeVisible()
  await expect(dialog.getByText('暂无原生执行记录')).toHaveCount(0)
})
