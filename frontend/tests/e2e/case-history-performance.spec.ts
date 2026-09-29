import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`paged case history design audit ${viewport.width}x${viewport.height}`, async ({page}) => {
    await page.setViewportSize(viewport);
    await page.goto('/cases/proxy-review-openvpn');
    await page.getByRole('tab',{name:'证据快照'}).click();
    await page.getByRole('button',{name:/查看证据历史/}).click();
    await expect(page.locator('.case-history-record')).toHaveCount(20);
    await page.getByRole('button',{name:'加载更早记录'}).click();
    await expect(page.locator('.case-history-record')).toHaveCount(40);
    await page.locator('.case-history-record summary').first().click();
    await page.locator('.case-history-section').scrollIntoViewIfNeeded();
    const probe=await page.evaluate(() => ({
      viewport:{width:innerWidth,height:innerHeight},documentWidth:document.documentElement.scrollWidth,
      records:[...document.querySelectorAll('.case-history-record')].map(el=>({width:el.clientWidth,scrollWidth:el.scrollWidth,radius:getComputedStyle(el).borderRadius,border:getComputedStyle(el).borderTopColor})),
      buttons:[...document.querySelectorAll('.case-history-section .ant-btn')].map(el=>({whiteSpace:getComputedStyle(el).whiteSpace,flexShrink:getComputedStyle(el).flexShrink})),
      ids:[...document.querySelectorAll('.case-history-id')].map(el=>({overflowWrap:getComputedStyle(el).overflowWrap})),
    }));
    expect(probe.documentWidth).toBeLessThanOrEqual(viewport.width+2);
    for(const record of probe.records){expect(record.scrollWidth).toBeLessThanOrEqual(record.width+2);expect(record.radius).toBe('8px');expect(record.border).toBe('rgb(226, 232, 240)');}
    for(const button of probe.buttons){expect(button.whiteSpace).toBe('nowrap');expect(button.flexShrink).toBe('0');}
    for(const id of probe.ids)expect(id.overflowWrap).toBe('anywhere');
    const directory=path.resolve('../artifacts/api-performance-fix-20260917/ui');fs.mkdirSync(directory,{recursive:true});
    fs.writeFileSync(path.join(directory,`case-history-${viewport.width}x${viewport.height}-probe.json`),JSON.stringify(probe,null,2));
    await page.screenshot({path:path.join(directory,`case-history-${viewport.width}x${viewport.height}.png`)});
  });
}
