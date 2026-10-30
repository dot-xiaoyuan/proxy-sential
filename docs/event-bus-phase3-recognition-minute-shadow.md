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

## 未完成：24h 回填失败并已取消

尝试用一次大 SQL 把最近 24 小时收据聚合进分钟表，查询在 184 上长时间 `WALWrite/AioIoCompletion`，主机 load 升到 30+，SSH 一度重置。已对 PostgreSQL 执行 `pg_cancel_backend` 取消两个回填查询；主机随后恢复 SSH 和 `/readyz=200`。

结论：

- 单次 24h 回填仍是重查询，不能作为上线步骤；
- 下一步必须按小时/小窗口分批回填，每批限时、可重试、可取消；
- 在分钟表补齐 24h 之前，不切换 `recognition-fresh-coverage` 的读路径。

## 后续

1. 增加按小时分片回填命令/脚本，记录进度和失败；
2. 用分钟表生成 24h 覆盖 JSON，和旧状态逐项对比；
3. 通过后切换识别覆盖读路径；
4. 把分钟表迁到 ClickHouse `AggregatingMergeTree`，减少 PostgreSQL 热表；
5. 旧 `stream_discovery_receipts` 识别统计职责退役。
