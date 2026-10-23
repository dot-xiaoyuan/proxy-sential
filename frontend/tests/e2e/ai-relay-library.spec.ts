import { expect, test } from '@playwright/test'

test('规则与特征库展示 AI 中转站域名库', async ({page}) => {
  const failures:string[]=[]
  page.on('pageerror',error=>failures.push(error.message))
  page.on('response',response=>{if(response.url().includes('/api/v1/ai-relay/indicators')&&response.status()>=400)failures.push(`${response.status()} ${response.url()}`)})
  for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
    await page.setViewportSize(viewport)
    await page.goto('/settings/rules?tab=ai-relay')
    await expect(page.getByText('yunwu.ai')).toBeVisible()
    await expect(page.getByText('2026.10.21')).toBeVisible()
    await expect(page.getByText('米醋中转站')).toBeVisible()
    await expect(page.getByText('CCTQ 中转站')).toBeVisible()
    await page.screenshot({path:`/tmp/proxy-sentinel-ai-relay-library-${viewport.width}x${viewport.height}.png`,fullPage:true})
    const probe=await page.evaluate(()=>({document:document.documentElement.scrollWidth-window.innerWidth,library:(()=>{const el=document.querySelector('.ai-relay-library');return el?el.scrollWidth-el.clientWidth:0})(),domainWrap:getComputedStyle(document.querySelector('.ai-relay-library .ai-relay-domain')!).overflowWrap}))
    expect(probe.document).toBeLessThanOrEqual(2)
    expect(probe.library).toBeLessThanOrEqual(2)
    expect(probe.domainWrap).toBe('anywhere')
  }
  expect(failures).toEqual([])
})
