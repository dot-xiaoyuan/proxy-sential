# 184 路由识别游标的重置恢复

状态：恢复方案。2026-11-05 只读复核显示活动识别服务已统一运行 r72，下面关于旧 p2 固定二进制的叙述是当时的切换风险记录；当前执行前以活动 unit 和实际进程为准。实时结果见[当前工作](current-work.md)。

## 原因与范围

2026-10-31 授权的测试数据重置清空了 `stream_router_recognition_state`，保留了此前不可变的 `stream_router_fresh_cutovers`。迁移 187 只建表，不会补回已被清空的状态行。识别线程因此每五秒尝试领取却始终无任务；路由证据、评估和依赖它们的共享档案无法从新的镜像事件生成。

这次恢复只重新建立 **10 月 31 日已授权重置起点**之后的读取游标。原 10 月 27 日固定切点及其取消审计保持原值。10 月 27 日到重置起点之间被清理的数据记为“授权重置、未处理”，数量无法从已清空的索引重新证明，审计表保持 `deleted_unprocessed_rows=NULL`；不计入 `processed_events`。

## 只读预检

在 184 核对实际发布目录、迁移账本和服务后，查询 PostgreSQL：

```sql
SELECT version,checksum,applied_at FROM schema_migrations
 WHERE version IN ('187_stream_router_recognition_cursor.sql',
                   '224_stream_router_reset_recovery_audit.sql') ORDER BY version;
SELECT sensor_id,cancel_id,indexed_after,canceled_index_rows,prior_processed_events
 FROM stream_router_fresh_cutovers WHERE sensor_id='ncu-184-router-pilot'
 ORDER BY indexed_after DESC LIMIT 1;
SELECT * FROM stream_router_recognition_state WHERE sensor_id='ncu-184-router-pilot';
SELECT * FROM stream_router_reset_recoveries WHERE sensor_id='ncu-184-router-pilot';
```

应见原最后切点 `2026-10-27T01:56:25Z`、`cancel_id=router-fresh-20261027T015625Z`，状态行和恢复审计行均为空。迁移 224 在运行恢复命令前必须在隔离 PostgreSQL 完成真实执行、外键和不可变触发器验证，再在 184 应用并核对校验值；仅有 sqlmock 单元测试不能替代该门槛。

ClickHouse 按索引时间核对首行及其哈希，再核对首行之前无任何保留索引：

```sql
SELECT indexed_at,event_key,content_sha256,retention_class,body_ref
 FROM stream_router_signal_index
 WHERE sensor_id='ncu-184-router-pilot'
 ORDER BY indexed_at,event_key LIMIT 1
 SETTINGS max_threads=1,max_execution_time=30;

SELECT countIf(indexed_at<toDateTime64('2026-10-31 09:14:01',6,'UTC')) AS before_reset,
       countIf(indexed_at>=toDateTime64('2026-10-31 09:14:01',6,'UTC')) AS reset_to_first
 FROM stream_router_signal_index
 WHERE sensor_id='ncu-184-router-pilot'
   AND indexed_at<toDateTime64('2026-10-31 09:28:37.110320',6,'UTC')
 SETTINGS max_threads=1,max_execution_time=15;
```

2026-11-03 的首行是 `2026-10-31T09:28:37.110320Z`、`dhcp-fresh-20261031T092000Z:stream-02d0b6b5376f7f237544980dc6835916`，标准事件正文 SHA256 为 `fb5cd6d45b9f2d62a7113556ef1f93934eed5ef9bd943e000684970cefe0dfb6`；两个计数均为零。若边界或哈希变化，停止恢复并查明是否已有 TTL 缺口。命令会重新查询这些条件及首行的标准事件权威正文，不能仅凭本记录执行。它没有核验原始 Zeek 日志或镜像源段。

同日只读核对标准事件正文时，首行 `stream_event_body_evidence` 的 1058 字节内容算出的 SHA256 与索引一致；一次要求最多两行的查询在输出首行后触发 ClickHouse 10 秒超时，另一次未限制时间范围的索引首行查询也在 10 秒超时。以首行时间为锚的索引查询约 3.5 秒。超时证明当前 ClickHouse 读端存在负载风险，不表示正文缺失；恢复命令若遇超时会停止而不插入状态。

## 受控恢复

PG224、恢复命令和识别线程门控已在 r72。先在当前活动的 `proxy-sentinel-recognition-materializer.service` 设置 `PROXY_SENTINEL_STREAM_ROUTER_DISABLED=true` 并重启，核对实际二进制仍为 r72 且日志明确记录停用；它只退出专用 stream router 线程，其余识别线程继续运行。环境变量从 184 已保护的运行配置读取，不把 DSN 写入命令行或文档。确认实时链路延迟和 PostgreSQL/ClickHouse 等待处于可观测范围后执行：

2026-11-05 核对：旧 `proxy-sentinel-recognition-materializer-eventbus.service` 已停用，活动的 `proxy-sentinel-recognition-materializer.service` 的有效 `ExecStart` 与 `/proc/<PID>/exe` 均指向 r72。保留当前 `PROXY_SENTINEL_PASSIVE_DISCOVERY_DISABLED=true`；恢复前仍要单独核对停用变量、实际进程和停用日志。**若无法完成门控核验，不执行恢复命令。**

插入状态前应在 `disabled=true` 下短时核对进程不退出、覆盖识别、共享行为和常规识别线程的进度及错误、服务 ready 状态与实时积压；若出现回归，先恢复原 unit 参数，此时状态行仍为空。状态行一旦插入，应保留具备门控的 r72 并维持 `disabled=true`，或停止识别服务，保留 PG224 审计与已写入的状态/证据；不能启动不识别门控的历史二进制自动领取积压。

```sh
proxy-sentinel router reset-recovery \
  --sensor-id ncu-184-router-pilot \
  --reset-id router-reset-20261031T091401Z \
  --authorization-ref docs/discovery-data-reset-20261031.md \
  --fixed-cutover-at 2026-10-27T01:56:25Z \
  --fixed-cancel-id router-fresh-20261027T015625Z \
  --reset-started-at 2026-10-31T09:14:01Z \
  --first-indexed-at 2026-10-31T09:28:37.110320Z \
  --first-event-key dhcp-fresh-20261031T092000Z:stream-02d0b6b5376f7f237544980dc6835916 \
  --first-sha256 fb5cd6d45b9f2d62a7113556ef1f93934eed5ef9bd943e000684970cefe0dfb6
```

命令在一笔 PostgreSQL 事务中持有与 fresh-cutover 相同的 advisory lock，拒绝已有状态行或与最后切点不符的审计，仅插入一条不可变的恢复记录和一条状态行。`fresh_cutoff_at` 与 `cancel_id` 保留原值，`cursor_indexed_at` 从 `2026-10-31T09:14:01Z`、空事件键开始，`processed_events=0`。ClickHouse 首行、哈希、标准事件正文和两段零计数验证失败时，事务不会开始。审计表拒绝 UPDATE、DELETE 和直接或级联 TRUNCATE。**没有线程门控时，插入状态后约五秒即会自动消费积压。**

恢复后先维持门控，核对状态与审计。试运行前把这个 unit 的 `Restart` 临时设为 `no`，记录原值 `on-failure`；再移除 stream router 停用变量，设置 `PROXY_SENTINEL_STREAM_ROUTER_CLAIM_BUDGET=10` 并重启识别服务。该预算**仅对当前 PID 有效**，不是全局持久上限；任何手工或 systemd 重启都会重新获得 10 次领取。每次领取最多 100 条评分事件或 500 条纯弱 TTL；首轮最多约 1000 条评分事件、5000 条总事件。核对 `systemctl show -p MainPID,NRestarts,Restart` 和日志，PID 或 NRestarts 意外变化立即停单元，不能把多次运行算作一次预算。检查游标、处理耗时、PG WAL 与等待、CH 查询、实时发现积压和页面延迟，再按实测逐级增加预算并有意重启。成功领取之间至少暂停一秒；如果单批实际耗时较长，处理速度会更低。预算用尽后不能把线程退出当作“已追平”。恢复常规运行前撤销临时 `Restart=no`，再次核对实际属性。

恢复前必须重新确认 10 月 31 日起点仍在索引保留期内。`short` 索引按 `toDateTime(indexed_at)+6 天` 保留，`toDateTime` 会截去微秒；首条 `short` 为 10 月 31 日 09:29:06.138538Z，对应 TTL 为 11 月 6 日 09:29:06Z。**恢复命令先按重置起点 10 月 31 日 09:14:01Z 作六天硬停检查，因此现场可执行截止时间更早，为 11 月 6 日 09:14:01Z（北京时间 17:14:01）。**消费线程也在游标对应整秒满 6 天时硬停，即使 ClickHouse TTL 后台合并尚未实际删除行，也不继续读后续 evidence 行或推进游标。届时记录未处理缺口与索引覆盖状态，不能把游标移到当前时间或另建 fresh cutover 来绕过检查。

## 现场跟踪

恢复后记录恢复审计行、状态行、首个成功批次的游标和 `last_error`，并连续观察处理速度、ClickHouse 查询时间、PostgreSQL 写等待、实时发现延迟、列表 P95/P99 和索引最早保留边界。状态游标必须持续超过约 25 条/秒的新索引输入，才会减少净积压；恢复时约 569 万条索引待处理，距离首条 `short` 索引 6 天保留期限约 3 天，需要平均超过 47 条/秒才能覆盖全部积压和新输入。实际吞吐若不足，记录缺口与资源事实，不能把尚未处理的记录计作完成。

路由列表只能展示已写入 `router_assessments` 的真实评估；共享档案还需要符合强证据条件。游标推进并不保证会出现路由器或共享设备。旧 `discovery_observation_latest` 在识别服务 `PROXY_SENTINEL_PASSIVE_DISCOVERY_DISABLED=true` 时不会由该线程回填；它是独立的旧投影路径。
