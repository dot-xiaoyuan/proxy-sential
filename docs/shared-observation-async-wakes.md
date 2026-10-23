# 共享观测异步唤醒与 184 切换

## 数据流

`156_shared_observation_async_wakes.sql` 默认保持 `legacy`。身份事件、已投影的完整快照和桥接健康变化在 `shadow` 下仍执行旧的直接任务唤醒，同时写入持久唤醒记录；`async` 下只写记录。完整快照另记录新增、变更、结束的 IP。范围记录复查结果不足或账号归属未确定的当前任务；已因其他证据排队而尚未领取的任务会直接读取最新快照，正在处理的任务仍须加版本以丢弃旧结果。IP 记录每次按 1,000 条批量匹配并唤醒对应的当前任务，已确认的结果只有该 IP 的投影成员发生变化才重算。`157_shared_capture_targeted_wake.sql` 将采集覆盖唤醒限定在覆盖尾端刚越过的事件窗口；完整性变化时复查当前任务。

调度器每次事务按 `job_id` 处理最多 100 个当前有效窗口，提交游标后继续。`shadow` 记录命中数而不再次唤醒；由 `async` 产生的记录在切回 `legacy` 后仍会继续幂等展开。只有 `processed_at` 已确认且超过 30 天的记录会被清理。

`158_shared_observation_current_ip_index.sql` 为当前观测的范围与 IP 更新提供部分索引。旧索引按传感器和时间筛选，当前观测更新仍需检查该传感器的大量索引项。新索引只包含 `current=true` 的观测，读收益是按范围和 IP 定位；写入成本是每次当前观测新增、退休各维护一条索引项。索引随原证据表保留和清理，失效由同一事务中的 `current` 更新驱动。现场大表先执行 `CREATE INDEX CONCURRENTLY`，迁移中的同名创建随后只记录校验值。

worker 以短事务领取 45 秒租约；领取 SQL 只对任务行使用 `FOR UPDATE OF j SKIP LOCKED`，模式表仅作只读条件，避免单行模式记录把 8 个 worker 串行化。读取 ClickHouse 和身份资料时不持有共享任务行锁。最终事务先写观测和审计，再短暂锁定任务核对租约令牌与版本；版本不符则回滚全部写入，匹配时才 ACK。期间新证据令版本递增并释放旧租约，新 worker 可立即领取；旧 worker 的写入在版本核对失败时整事务回滚。`async` 下共 8 个 worker：7 个优先按依赖入库时间处理近期任务，1 个专用处理自然到期；实时领取为空时，最多 2 个实时 worker 可借用到期任务，最多形成 3 路到期处理，实时任务出现后借用者回到实时队列。总 worker 不超过 8，最多 4 个同时读取 ClickHouse。即使事件时间已过新鲜窗口，只要依赖版本尚未完成，仍由实时 worker 先判定。`legacy/shadow` 保持 2 个 worker，避免旧快照长事务期间扩大数据库写入压力。已有保存证据的到期任务直接按该证据完成到期判定与审计；没有保存证据的任务仍查询原始事件。`async` 模式下结果不足的任务等待依赖变化、证据到期或每分钟有上限的补漏扫描；`legacy` 和 `shadow` 保留原来的 5 秒复查。

## 现场切换与核验

发布前核对 `schema_migrations` 校验值、`current`、`previous`、服务、磁盘、现场配置和本地未提交改动。迁移包必须传 `--skip-backup`。发布后先检查 API `/readyz` 和所有受影响服务，确认数据库模式仍是 `legacy`。

切换语句：

```sql
UPDATE shared_observation_wake_mode SET mode='shadow',changed_at=clock_timestamp() WHERE singleton;
-- 至少观察一份完整快照；比较范围记录 matched_jobs、现有任务版本和审计结果。
UPDATE shared_observation_wake_mode SET mode='async',changed_at=clock_timestamp() WHERE singleton;
```

观察两份后续完整快照和至少 1,000 条新任务。每次 `async` 判定提交后写一条 `shared_observation_decision` 结构化日志，包含任务版本、依赖时间、延迟、各处理阶段耗时及 `new_dependency` 标记；只用标记为 `true` 的完成记录计算新任务 P99，自然到期、定期补漏及历史积压另报。`shared_observation_jobs.last_decision_latency_ms` 保留每个 IP 最近一次新依赖的判定延迟，可用于快速看板。日志 `shared_observation_metrics` 提供实时/到期数量和最老年龄、待展开范围、超时租约、入队锁等待及最近一次新依赖延迟的 P99。核对新旧唤醒、判定/审计数量，并确认握手入队没有快照级长锁等待。快照范围记录在投影事务结束前更新时间戳，以接近依赖可见的时刻；指标仍包含事务最后提交耗时。

失败时先执行：

```sql
UPDATE shared_observation_wake_mode SET mode='legacy',changed_at=clock_timestamp() WHERE singleton;
```

保持新应用运行，等待 `producer_mode='async' AND processed_at IS NULL` 的记录降至零；调度器继续按游标将它们补入任务队列。然后才回退应用至 `previous`，复核服务与审计。迁移不反向删除。

本次不在 184 造数，也不启动本地数据库栈；未完成隔离容量测试前不能承诺在线用户数或 3 倍、10 倍容量。
