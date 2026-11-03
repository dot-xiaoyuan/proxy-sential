# 路由识别待处理索引保留候选（未部署）

## 现场事实与目的

184 的 `stream_router_signal_index` 当前按 `indexed_at` 保留 `short` 6 天、`evidence` 8 天。2026-11-03 05:53 UTC 只读统计约 579.5 万条 `evidence` 和 917 条 `short`，后者只有 VRRP、TTL；索引占约 1.11 GiB。首条 `short` 的原保留边界为 11 月 6 日 09:29 UTC。`evidence` 对应权威标准事件正文保留一年，`short` 正文表 v1/v2 保留 7 天，原始段的 `short` 类同样为 7 天。事件检索表的普通 `short` 行也是 7 天，但路由消费者读取索引及权威正文，不经由检索表。

当前路由状态缺失，约 580 万索引未由新窗口识别线程处理；发现采集与 PostgreSQL 投影已饱和，不能依赖三天内完成全部回放。只延长索引会留下过期的 `short` 正文引用。[候选 SQL](candidates/064_router_signal_retention_candidate.sql) 因此先延长两版 `short` 正文及短原始段至 14 天，随后把路由索引改为 `short` 13 天、`evidence` 30 天。标准事件正文仍各只有一份；不新增完整副本或更改现有证据类的一年保留。

这是保全未处理输入的有限时间窗口，不增加识别吞吐。普通 `short` 检索行仍在第 7 天过期，不能用本候选宣称全部详情历史可检索 14 天；如果后续功能需要该能力，须另行设计读取收益和成本。路由游标的失效守卫必须先保持原 6 天硬停，只有现场证明新 TTL 已覆盖旧分区后，才能在后续应用版本中改为不超过 13 天；不得先放宽游标再改存储。

## 容量与写入成本

184 在 11 月 3 日约有 417 GiB 可用空间；`stream_event_body_short` 与 `_v2` 合计约 4.5 GiB，路由索引约 1.11 GiB，`stream_source_raw` 约 0.3 GiB。按重置后约 2.9 天形成的数据粗估，索引从 8 天延至 30 天、短正文从 7 天延至 14 天，长期可能额外占用十余至二十余 GiB；这是混合来源、短窗口估算，不是容量承诺。短原始段是混合段，表中证据类也按一年保留，不能把整表 0.3 GiB 当作短类增长率。现场只有一块旋转盘，近期瞬时利用率约 96%；新增保留与 TTL 合并会增加磁盘压力，迁移应单独分阶段观察。

现场 ClickHouse 为 25.9.2.1，`materialize_ttl_after_modify` 默认 1。候选的每条 `ALTER` 显式传 `SETTINGS materialize_ttl_after_modify = 0`，意图避免自动为所有旧分区排队重算；这**尚未证明旧分区会按新期限保留**。如果旧分区仍按原到期时间清理，本候选不能用于现场。现有 `system.parts.delete_ttl_info_min` 分别显示路由索引首到期 11 月 6 日 09:29、短正文首到期 11 月 7 日 09:29；验证必须覆盖这些旧分区，而非只看新写入行。

已在 184 使用只读 `EXPLAIN AST` 逐条解析四条候选 `ALTER`，ClickHouse 25.9.2.1 均识别为 `MODIFY_TTL` 并携带查询级 `SETTINGS`。这只验证语法解析，没有执行 DDL、重算旧分区或验证到期行为。

## 发布前验证门槛

1. 在独立的 ClickHouse **25.9.2.1** 单节点、小容量实例中建立与现场相同的四张表及原 TTL，插入分别落在原/新到期边界两侧的 `short`、`evidence` 行和至少两个旧数据 part。执行候选 SQL，通过迁移解析器核对四条语句；重启数据库后仍能读取并校验正文哈希。
2. 检查 `system.mutations`、`system.parts.delete_ttl_info_min/max` 和 `SHOW CREATE TABLE`，在旧 TTL 时间跨过后触发小表合并，确认旧 `short` 行及其正文仍存在；到新 TTL 边界再验证清理。不能仅凭 `SHOW CREATE TABLE` 或 `materialize_ttl_after_modify=0` 断言旧分区已受保护。
3. 候选通过后才把原样 SQL 移到 `migrations/clickhouse/064_...sql`，完成代码/迁移校验和包内清单。184 需按完整安装流程、`--skip-backup`、用户授权执行；候选在 `docs/candidates/` 不会被当前迁移 runner 自动应用。
4. 现场按正文 v1、v2、原始段、最后路由索引的顺序执行，每步检查 DDL、mutation、磁盘等待和旧边界锚点；`short`/`evidence` 首行键、哈希、数量与最早时间在操作前后保持一致。放宽游标守卫是后续独立切换，仍须防止在到期前净积压继续增长。

ClickHouse 迁移 runner 对 SQL 文件按文件名排序、逐语句执行，最后写入校验和；DDL 不在事务中。若中途失败，不得修改已应用文件或盲目重试，先核对各表当前 TTL 与迁移账本。应用回退不能撤销 TTL；缩短期限会使积压行进入删除窗口，须在待处理证据转移/审计前禁止。

本机可用空间约 31 GiB，OrbStack/Docker 当前停止；现有 OrbStack 数据映像已占实际约 96 GiB，Docker 磁盘上限为 0、全局配置为 8 CPU/8 GiB。`orb start` 没有可在启动前隔离既有 Docker 容器的参数，无法证明不会恢复完整本地快照；仅给新容器设限也无法约束旧容器。本轮没有改动全局配置或启动 OrbStack，也没有完成独立 ClickHouse 实例验证。**在上述门槛完成前，不把此 SQL 放入自动迁移目录，也不在 184 执行。**
