import { expect, test } from '@playwright/test'

test('AI 中转站使用方页面在三个视口可读且无溢出', async ({page}) => {
  const failures:string[]=[]
  page.on('pageerror', error=>failures.push(error.message))
  page.on('console', message=>{if(message.type()==='error')failures.push(message.text())})
  page.on('requestfailed', request=>failures.push(`${request.failure()?.errorText} ${request.url()}`))
  page.on('response', response=>{if(response.url().includes('/api/v1/ai-relay/')&&response.status()>=400)failures.push(`${response.status()} ${response.url()}`)})
  for(const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]){
    await page.setViewportSize(viewport)
    await page.goto('/ai-relay')
    await expect(page.getByText('近 7 天', {exact:true})).toBeVisible()
    await expect(page.getByText('云雾 API').first()).toBeVisible()
    await expect(page.locator('.ai-relay-page .ant-alert-info')).toHaveCount(0)
    await page.locator('.ai-relay-page .ant-table-row-expand-icon').first().click()
    await expect(page.getByText('api.yunwu.ai').first()).toBeVisible()
    await expect(page.getByRole('link',{name:'查看事件'}).first()).toBeVisible()
    await page.screenshot({path:`/tmp/proxy-sentinel-ai-relay-${viewport.width}x${viewport.height}.png`,fullPage:true})
    const probe=await page.evaluate(()=>({
      document:document.documentElement.scrollWidth-window.innerWidth,
      page:(()=>{const el=document.querySelector('.ai-relay-page');return el?el.scrollWidth-el.clientWidth:0})(),
      buttonWrap:[...document.querySelectorAll('.ai-relay-page .ant-btn')].filter(el=>getComputedStyle(el).whiteSpace!=='nowrap').map(el=>`${el.className}:${getComputedStyle(el).whiteSpace}`),
      domainWrap:getComputedStyle(document.querySelector('.ai-relay-domain')!).overflowWrap,
    }))
    expect(probe.document).toBeLessThanOrEqual(2)
    expect(probe.page).toBeLessThanOrEqual(2)
    expect(probe.buttonWrap).toEqual([])
    expect(probe.domainWrap).toBe('anywhere')
  }
  expect(failures).toEqual([])
})
