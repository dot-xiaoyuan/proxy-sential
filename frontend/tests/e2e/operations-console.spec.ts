import { expect, test } from '@playwright/test'

test('filters risks and opens an IP detail page', async ({ page }) => {
  await page.goto('/risks')
  await page.getByLabel('风险等级').click()
  await page.getByTitle('高风险').click()
  await expect(page.getByText('10.255.0.98')).toBeVisible()
  await page.getByText('10.255.0.98').click()
  await expect(page.getByRole('heading', { name: '10.255.0.98' })).toBeVisible()
  await expect(page.getByRole('heading', { name: '证据时间线' })).toBeVisible()
})

test('submits a review label on IP detail', async ({ page }) => {
  await page.goto('/ips/10.255.0.59')
  await page.getByLabel('复核结论').click()
  await page.getByTitle('确认代理').click()
  await page.getByLabel('复核原因').fill('证据链完整，确认共享上网')
  await page.getByRole('button', { name: '提交标注' }).click()
  await expect(page.getByText('标注已写入审计队列')).toBeVisible()
})

test('shows shadow run summaries', async ({ page }) => {
  await page.goto('/shadow-runs')
  await expect(page.getByText('20260724-131645')).toBeVisible()
  await expect(page.getByText('truncated')).toBeVisible()
})

test('shows ingest diagnostics and normalized event samples', async ({ page }) => {
  await page.goto('/ingest')
  await expect(page.getByRole('heading', { name: '采集诊断' })).toBeVisible()
  await expect(page.getByText('suricata', { exact: true })).toBeVisible()
  await expect(page.getByText('ens1f1', { exact: true })).toBeVisible()
  await expect(page.getByText('flow', { exact: true })).toBeVisible()
  await expect(page.getByText('collector run completed with skipped or malformed input records')).toBeVisible()
  await expect(page.getByText('event-http-59-a')).toBeVisible()
})
