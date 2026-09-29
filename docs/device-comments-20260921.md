# 终端列表反馈处理（2026-09-21）

发布版本：2026.09.21-device-name-search，上一版本 2026.09.20-device-names-r3。

完整 IP 搜索改为 PostgreSQL inet 精确匹配，仍搜索历史关联。截图中的 .79、.54、.45 终端均曾使用 .82，不是这次截图中的模糊误命中。页面明确历史搜索与最近 IP 展示的差异。读取 .82 DHCP 记录，9 月 20 日 13:55 对应 82:1b:e5:56:da:d1，9 月 21 日 10:44 对应 d8:f2:ca:04:14:33（北京时间）。历史 MAC 数不等同物理设备数，也不代表同时使用。

自动名称新增精确默认名过滤：localhost、localhost6、unknown、android、iphone、ipad，以及现场确认的默认型号标签 ADY-AL00、ICL-AL10、HONOR-100。这是保守清单，不声称识别所有型号，也不据此推断型号/品牌。迁移 057 清理这些名称证据，保留原始事件与人工备注。mDNS 仅在返回 device_name 的显示值中去掉 .local；证据和服务目标不变，继续使用完整名称进行 TTL/归属关联。

验证：Go 竞态测试（store、controlplane、zeek）；隔离 PostgreSQL 回放验证精确 IP 不匹配类似地址或备注、历史地址命中、默认名称清理、mDNS 展示/原始值分离。前端 npx tsc --noEmit、生产构建通过；14 项 Playwright 测试通过，390×844、1280×800、1440×900 截图、DOM 样式探针核对无横向页面溢出，按钮不压缩，移动端卡片布局。

日志与现场只读验证见 artifacts/device-comments-20260921。
