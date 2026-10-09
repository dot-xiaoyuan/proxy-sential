import { test, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

for (const [width,height] of [[390,844],[1280,800],[1440,900]]) test(`native connector kind ${width}`,async ({page})=>{
 await page.setViewportSize({width,height})
 await page.goto('/settings/actions')
 await expect(page.getByRole('button',{name:'配置 4K 接入'})).toBeVisible()
 await page.getByRole('button',{name:'新增通用连接器'}).click()
 const dialog=page.getByRole('dialog')
 await expect(dialog.getByLabel('HMAC 密钥')).toBeVisible()
 await dialog.getByLabel('连接器类型').click()
 await expect(page.getByText('原生 4K 连接器',{exact:true})).toHaveCount(0)
 await page.keyboard.press('Escape')
 await expect(dialog.getByLabel('连接器 ID')).toBeVisible()
 await expect(dialog.getByLabel('名称',{exact:true})).toBeVisible()
 await expect(dialog.getByLabel('北向 HTTP 地址')).toBeVisible()
 await dialog.getByLabel('运行模式').click()
 await expect(page.locator('.ant-select-item-option-disabled').filter({hasText:'真实模式'})).toBeVisible()
 await page.keyboard.press('Escape')
 const probe=await dialog.evaluate(el=>({overflow:document.documentElement.scrollWidth>window.innerWidth+2,titleTop:el.querySelector('.ant-modal-title')!.getBoundingClientRect().top,footerBottom:el.querySelector('.ant-modal-footer')!.getBoundingClientRect().bottom,controls:[...el.querySelectorAll('.ant-btn,.ant-tag')].filter(e=>getComputedStyle(e).whiteSpace!=='nowrap'||getComputedStyle(e).flexShrink!=='0').map(e=>e.textContent)}))
 expect(probe.overflow).toBe(false)
 expect(probe.titleTop).toBeGreaterThanOrEqual(0)
 expect(probe.footerBottom).toBeLessThanOrEqual(height)
 expect(probe.controls).toEqual([])
 const dir=path.resolve('test-results/native-connector-kind');await mkdir(dir,{recursive:true})
 await writeFile(path.join(dir,`dom-${width}.json`),JSON.stringify(probe,null,2))
 await page.screenshot({path:path.join(dir,`${width}.png`),animations:'disabled'})
})
