import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`asynchronous application export design audit ${viewport.width}x${viewport.height}`, async ({page}) => {
    await page.setViewportSize(viewport);
    await page.goto('/activity');
    await expect(page.getByText('统计时间：')).toBeVisible();
    await page.getByRole('button',{name:'导出待补特征域名',exact:true}).click();
    await expect(page.getByText('导出任务：正在生成文件')).toBeVisible();
    await expect(page.getByText('导出任务：已完成 · 2 条')).toBeVisible();
    const downloadPromise=page.waitForEvent('download');
    await page.getByRole('button',{name:'下载文件',exact:true}).click();
    const download=await downloadPromise;
    expect(download.suggestedFilename()).toBe('unknown-domains.jsonl');
    const probe=await page.evaluate(()=>({
      viewport:{width:innerWidth,height:innerHeight},documentWidth:document.documentElement.scrollWidth,
      buttons:[...document.querySelectorAll('.application-toolbar .ant-btn')].map(el=>({whiteSpace:getComputedStyle(el).whiteSpace,flexShrink:getComputedStyle(el).flexShrink})),
      cards:[...document.querySelectorAll('.application-card')].filter(el=>getComputedStyle(el).display!=='none').map(el=>({width:el.clientWidth,scrollWidth:el.scrollWidth,radius:getComputedStyle(el).borderRadius})),
    }));
    expect(probe.documentWidth).toBeLessThanOrEqual(viewport.width+2);
    for(const button of probe.buttons){expect(button.whiteSpace).toBe('nowrap');expect(button.flexShrink).toBe('0');}
    for(const card of probe.cards){expect(card.scrollWidth).toBeLessThanOrEqual(card.width+2);expect(card.radius).toBe('8px');}
    const directory=path.resolve('../artifacts/api-performance-fix-20260917/ui');fs.mkdirSync(directory,{recursive:true});
    fs.writeFileSync(path.join(directory,`application-export-${viewport.width}x${viewport.height}-probe.json`),JSON.stringify(probe,null,2));
    await page.screenshot({path:path.join(directory,`application-export-${viewport.width}x${viewport.height}.png`)});
  });
}

 test('cancel queued or running unknown-domain export',async({page})=>{
 await page.goto('/activity');
 await page.getByRole('button',{name:'导出待补特征域名',exact:true}).click();
 await page.getByRole('button',{name:'取消导出',exact:true}).click();
 await expect(page.getByText('导出任务：已取消')).toBeVisible();
 await expect(page.getByRole('button',{name:'下载文件',exact:true})).toHaveCount(0);
 });
