# 高校生产版统一验收记录

本记录对应 T7 统一验收。验收必须同时连接真实 PostgreSQL 与 ClickHouse；未设置测试 DSN 时，相关集成用例会明确跳过，不能据此宣称生产验收通过。

## 自动化门槛

- PostgreSQL：执行全部增量迁移，验证用户会话、身份时点归责、案件、处置、离线画像回填，以及影子运行和审计日志的数据库分页。
- ClickHouse：写入 10 万条标准事件，验证 DPI 总览、协议流和指纹冲突均在 ClickHouse 聚合；评审查询只返回 500 条聚合行而不是 5 万条候选明细。
- 列表：默认响应 20 条、最大 50 条，包含统一 `page`；20 条事件响应不得超过 250KB，前端自动预取 `next_cursor`。
- 安全：覆盖登录失败限流、CSRF、viewer 越权 403、用户停用后的会话失效、处置幂等、冷却、熔断与撤销。
- 前端：TypeScript、lint、单元测试、生产构建和 Playwright 必须全部通过；DOM 探针覆盖 390×844、1280×800、1440×900 三个视口和 12 个核心页面。

## 2026-09-01 本地验收结果

- ClickHouse 使用固定镜像 `clickhouse/clickhouse-server:24.8-alpine`，10 万事件 DPI 总览与评审聚合测试耗时约 0.34 秒，低于 1 秒目标。
- 禁用缓存的 Mock 运营工作台可操作内容约 1.2 秒，低于 1.5 秒目标。
- 三视口探针发现并修复组织管理页栅格负边距造成的 8px 内部溢出；修复后 12 个页面均无页面横向爆框、按钮/标签/标识符换行。
- Go 全量测试、前端 13 个单元测试、生产构建和 19 个 Playwright 用例全部通过。

以上数字是本地验收基线。30 测试机部署完成后仍须使用现场数据复跑同一套命令；真实北向处置还必须另外满足连续七天影子运行和人工确认准确率不低于 95%，不能用本地自动化结果替代。

## 执行命令

```bash
PROXY_SENTINEL_TEST_POSTGRES_DSN='<postgres-dsn>' \
PROXY_SENTINEL_TEST_CLICKHOUSE_DSN='<clickhouse-http-dsn>' \
go test ./...

cd frontend
pnpm exec tsc --noEmit
pnpm lint
pnpm test -- --run
pnpm build
pnpm exec playwright test
```
