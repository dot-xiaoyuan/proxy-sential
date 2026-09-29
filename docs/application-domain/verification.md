# 首版验证记录

2026-09-08，本次修改验证范围：

- internal/appdomain：包校验、域名边界、六应用共同向量、损坏包、冲突规则、三版本保留、回滚、并发切换、观测去重、累计流量、多应用连接、未知导出、持久化与重分类恢复、迟到数据。
- internal/store：FileStore 与 ClickHouse HTTP 模拟响应的观测结果一致，稳定游标、不使用 OFFSET；不是实际数据库容量压测。
- internal/controlplane：独立开关、导入、查询参数验证、重分类、全局只读及权限映射。
- internal/adapter/suricata、internal/normalized：大整数流 ID 保真、采集实例和传感器隔离。
- internal/shadow、internal/realtime、cmd：现有相关测试及新增启动参数编译验证。
- go test -race：应用模块、Suricata 适配、标准连接标识。
- 前端 npx tsc --noEmit、生产构建通过；OpenAPI 生成通过。
- Playwright 应用观测专项：390×844、1280×800、1440×900 全部通过。验证页面/抽屉/特征库、无横向爆框、按钮与标签 nowrap/flex-shrink、移动卡片模式及标题字重。已查看截图核对间距、长标识符和卡片布局。

截图保存在 frontend/test-results/application-visuals/，这些是 MSW 演示数据，不是真实流量截图。

未进行生产部署、真实校园流量吞吐压测，也没有执行 featurelib-new 的整改。该项目的可复制整改 prompt 见同目录 featurelib-remediation-prompt.md。样例包及匹配向量用于两边契约联调，不代表人工标注后的识别准确率。

## 2026-09-14 数据库改造验收

新增真实 PostgreSQL/ClickHouse 回放、恢复及十万/百万容量验收，详见 [本轮验收记录](verification-database-20260914.md)。本节更新数据库存储的验收状态，不改变上文首版历史记录或现场验收边界。
