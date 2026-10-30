# 识别覆盖分钟增量影子

状态：已在 184 运行分钟级影子表；旧 `recognition-fresh-coverage` 读路径**未切换**。

## 目标

旧路径每分钟对 `stream_discovery_receipts` 最近 24 小时、`recognition_input IS NOT NULL` 的收据做聚合、JSONB 提取和 `percentile_cont` 排序，约 1,126 万行/16 GB。分钟影子把统计拆成：

```text
每分钟 × 协议
  -> recognition_coverage_minute_shadow
  -> 24h 只合并约 1,440 × 协议数的小结果
```

## 实现

- 表：`recognition_coverage_minute_shadow`，迁移 `207_recognition_coverage_minute_shadow.sql`；
- 命令：`cmd/recognition-minute-shadow`；
- 服务：`proxy-sentinel-recognition-minute-shadow.service`；
- 每 60 秒重算最近 10 个已关闭分钟，处理迟到事件；
- 每行保存 inputs/parsed/attributed/features/candidates/conclusions/conflict/processing/unattributed/insufficient/errors/overdue/timed、四个 timing 平均值和分钟 p95；
- 只写影子表，不修改旧覆盖状态。

## 184 验证

- 服务 active；
- 表已有 550 行、216,388 个 inputs（分钟影子持续增长，并接受了 24h 分片回填的部分数据）；
- 单分钟抽样：`06:24` 的 `ssdp` 在迟到事件后从 430 更新到 719，和直接查询收据一致；
- 旧 `recognition-fresh-coverage` 仍是原路径，没有切换；
- 识别覆盖读代码已改为分钟表，但未部署到识别服务。

## 未完成：24h 回填在 184 上不可行

三次回填尝试：

1. 一次大 SQL 聚合 24 小时：查询长期处于 `WALWrite/AioIoCompletion`，主机 load 30+，SSH 重置；已 `pg_cancel_backend`。
2. 逐分钟回填 1,440 次：约 7 分钟只推进到 2h38m，load 升到 38，SSH 再次重置；已终止。
3. 按小时 counts-only 回填：单小时运行超过 3 分钟仍未完成，load 约 35；已 kill 进程并取消 PG 查询。

当前分钟表约 562 行、216k inputs，分钟服务继续运行；旧 `recognition-fresh-coverage` 没有切换。

结论：

- 184 的单块 HDD 已不适合再做识别 24h 回填；继续重试会拖垮控制面和采集；
- 识别覆盖需要迁到 ClickHouse `AggregatingMergeTree`，或在 SSD/独立节点做一次离线回填，再切读；
- 识别覆盖读代码已提交，但识别物化服务未部署该二进制。

## 后续

1. 增加按小时分片回填命令/脚本，记录进度和失败；
2. 用分钟表生成 24h 覆盖 JSON，和旧状态逐项对比；
3. 通过后切换识别覆盖读路径；
4. 把分钟表迁到 ClickHouse `AggregatingMergeTree`，减少 PostgreSQL 热表；
5. 旧 `stream_discovery_receipts` 识别统计职责退役。
