import { expect, test } from "@playwright/test";
for (const viewport of [
  { width: 390, height: 844 },
  { width: 1280, height: 800 },
  { width: 1440, height: 900 },
]) {
  test(`fingerprint catalog ${viewport.width}`, async ({ page }, info) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.setViewportSize(viewport);
    await page.goto("/settings/rules");
    await page.getByRole("tab", { name: "设备特征库", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "多来源设备指纹库" }),
    ).toBeVisible();
    for (const tab of ["总览", "来源目录", "规则检索", "现场覆盖"]) {
      await page.getByRole("tab", { name: tab, exact: true }).click();
      await expect(
        page.locator(".fingerprint-catalog .ant-skeleton"),
      ).toHaveCount(0);
      await page.screenshot({
        path: info.outputPath(`${tab}.png`),
        fullPage: true,
      });
      const probe = await page
        .locator(".fingerprint-catalog")
        .evaluate((el) => ({
          overflow: document.documentElement.scrollWidth > innerWidth + 2,
          controls: [...el.querySelectorAll(".ant-btn,.ant-tag")]
            .filter((e) => {
              const s = getComputedStyle(e);
              return s.whiteSpace !== "nowrap" || s.flexShrink !== "0";
            })
            .map((e) => e.textContent),
          missing: /未识别|未获取|未关联|未观测/.test(el.textContent ?? ""),
        }));
      await info.attach(`${tab}-dom`, {
        body: JSON.stringify(probe),
        contentType: "application/json",
      });
      expect(probe).toEqual({ overflow: false, controls: [], missing: false });
    }
    expect(errors).toEqual([]);
  });
}
