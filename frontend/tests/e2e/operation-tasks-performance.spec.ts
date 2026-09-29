import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

for (const viewport of [{width:390,height:844},{width:1280,height:800},{width:1440,height:900}]) {
  test(`durable task progress design audit ${viewport.width}x${viewport.height}`, async ({page}) => {
    await page.setViewportSize(viewport);
    await page.goto('/settings/rules');
    await page.getByRole('tab',{name:'应用域名特征库',exact:true}).click();
    await page.getByRole('button',{name:'拉取并回填',exact:true}).click();
    await expect(page.getByText('应用规则拉取 · 等待执行')).toBeVisible();
    await expect(page.getByText('应用规则拉取 · 正在执行')).toBeVisible();
    await expect(page.getByText('应用规则拉取 · 已完成')).toBeVisible();
    await page.locator('.operation-task-progress').scrollIntoViewIfNeeded();
    const probe=await page.evaluate(()=>({
      viewport:{width:innerWidth,height:innerHeight},documentWidth:document.documentElement.scrollWidth,
      container:{width:document.querySelector('.operation-task-progress')!.clientWidth,scrollWidth:document.querySelector('.operation-task-progress')!.scrollWidth,radius:getComputedStyle(document.querySelector('.operation-task-progress')!).borderRadius,border:getComputedStyle(document.querySelector('.operation-task-progress')!).borderTopColor},
      buttons:[...document.querySelectorAll('.operation-task-progress .ant-btn')].map(el=>({whiteSpace:getComputedStyle(el).whiteSpace,flexShrink:getComputedStyle(el).flexShrink})),
      ids:[...document.querySelectorAll('.operation-task-id')].map(el=>({overflowWrap:getComputedStyle(el).overflowWrap})),
    }));
    expect(probe.documentWidth).toBeLessThanOrEqual(viewport.width+2);
    expect(probe.container.scrollWidth).toBeLessThanOrEqual(probe.container.width+2);
    expect(probe.container.radius).toBe('8px');expect(probe.container.border).toBe('rgb(226, 232, 240)');
    for(const button of probe.buttons){expect(button.whiteSpace).toBe('nowrap');expect(button.flexShrink).toBe('0');}
    for(const id of probe.ids)expect(id.overflowWrap).toBe('anywhere');
    const directory=path.resolve('../artifacts/api-performance-fix-20260917/ui');fs.mkdirSync(directory,{recursive:true});
    fs.writeFileSync(path.join(directory,`operation-tasks-${viewport.width}x${viewport.height}-probe.json`),JSON.stringify(probe,null,2));
    await page.screenshot({path:path.join(directory,`operation-tasks-${viewport.width}x${viewport.height}.png`)});
  });
}

test('cancel queued library task without reporting success',async({page})=>{
  await page.goto('/settings/rules');
    await page.getByRole('tab',{name:'应用域名特征库',exact:true}).click();
  await page.getByRole('button',{name:'拉取并回填',exact:true}).click();
  await expect(page.getByText('应用规则拉取 · 等待执行')).toBeVisible();
  await page.getByRole('button',{name:'取消任务',exact:true}).click();
  await expect(page.getByText('应用规则拉取 · 已取消')).toBeVisible();
  await expect(page.getByText('操作成功，配置已保存或规则已加载')).not.toBeVisible();
});

test('resume pending task status after page reload',async({page})=>{
 await page.goto('/settings/rules');
 await page.evaluate(()=>localStorage.setItem('sentinel-pending-tasks',JSON.stringify([{task_id:'library-pull-demo',kind:'/application-library/pull',status:'queued',created_at:new Date().toISOString()}])));
 await page.reload();
 await expect(page.getByText('应用规则拉取 · 已完成')).toBeVisible();
});
