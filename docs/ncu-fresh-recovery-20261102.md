# NCU 身份新起点恢复（2026-11-02 现场记录）

## r60 发布与新起点切换

- 用户已单独授权在 184 执行本次迁移、部署、切流和验收。`2026.11.02-ncu-shared-recovery-r60` 来自干净提交 `98b031c44d8732bddecec2ffe169648fbdadf317`，发布包 SHA256 为 `9d6b45068a898964772ea4d0aea0865843af6068195e2608196b962e84ae9608`。包外和包内 524 项文件哈希均核对通过；后端全仓测试、构建、vet、定向 race 和打包时前端类型检查/构建通过。前端源码本次未改。
- 184 只读预检确认原 `current=r59b`、`previous=r58`、受保护账号与配置存在。完整安装器传 `--skip-backup --prepare-only` 应用 PostgreSQL 222；之后 223 项 PostgreSQL、63 项 ClickHouse 候选迁移与账本一致。应用升级将 `current` 切到 r60、`previous` 留 r59b，18 个活动进程为 r60。`runtime.env` SHA256 仍为 `1ab730cbf8eff7f8e889895a01177336537ffb88c5d98cabc643b000d70aef32`，没有清库、例行备份或改写旧迁移。
- UTC 12:26:41 停止桥接，NCU 专用派生服务原已 inactive。现场运行配置确认事件 Redis 为 `222.204.3.227:16384`、源键 `list:antiproxy:127.0.0.1`、处理中键为其 `:proxy-sentinel-processing` 后，使用 r60 的只读边界命令生成 0600 文件 `/opt/proxy-sentinel/config/ncu-redis-audit-20261102T1227Z.json`。源/处理中长度为 100000/2，审计文件 SHA256 为 `490150e429b09ed4043f8004b7307fa969c6bccdf37397ebdbb8e0a503de0c95`；只含长度、时间、首尾哈希及冻结批次摘要，不含原文。
- 应用前再次读到旧 b2 起点 784452、accepted 673156、processed 672823、主待办 2041、导出待办 9894，旧 inbox/片段/IP 待办和三张拆分进度表均为零。受限事务创建 `identity-fresh-b3-20261102T1227Z`，新起点固定为 673156、下一个序号 673157；b2 关闭且旧 scope 计数不变。不可变缺口 `672824–673156` 的状态为 `unverifiable_gap`，审计 SHA256 `16c75a67753802510ce914272a3e580831596a8f2b60a5a75c6be9b108c1d48a`；没有清理 Redis 队列，也没有把旧待办记成完成。
- 新建 systemd drop-in `/etc/systemd/system/proxy-sentinel-control-plane-eventbus.service.d/zzzzzzz-ncu-identity-b3.conf`，仅将控制面的 `PROXY_SENTINEL_IDENTITY_STREAM_EPOCH` 设为 b3，实际进程环境与 r60 可执行文件已核对，`/readyz` 200。桥接恢复后开始提交：UTC 12:28:53 的最近事件已更新，源队列由 100000 降至约 88552，提交计数约 11002，事件连续失败为零；UTC 12:29 后 `/18082/readyz` 返回 200。该队列变化不是对上游来源完整性或每条消息去向的证明。

## 派生层旧策略缺失与受限修复

首次启动固定 r25 的 NCU 专用派生服务立即以 0 退出，日志为 `identity fresh cutover admission: sql: no rows in result set`。其入场需要 `identity_derived_fresh_starts` 中原 `ncu-derived-fresh-20261029T051129Z` 策略，但现场该表和取消进度表均为空；r60 的 b3 接收恢复不会创建派生层策略。恢复前只读确认旧截止点 UTC `2026-10-29T05:11:29Z` 之前的 NCU 批次和片段均为零、NCU 旧物化游标不存在，已接收的新批次最早是 UTC 11 月 2 日 12:28:24。

按用户原固定截止点执行[受限 SQL](../scripts/maintenance/ncu-derived-fresh-policy-restore-20261102.sql)（SHA256 `7dcb33acf524ad0c75a33cf066226496413b83d94f662620102a725b8b2bf13e`）：在同一事务中短暂锁住 inbox 写入，复核 b3 活动与缺口审计、原策略不存在、截止点前批次/片段为零，然后插入不可变派生策略和 `done=true`、取消数为零的进度。此零取消只指现场数据库没有截止点前的物理片段，**不改变 b2 的不可核验缺口，也不宣称旧原文已归档**。事务成功后 r25 派生服务重新启动；后续持续消费、派生、归档的最终验收结果见下一节。

派生服务随后报告 ready 状态查询缺少 `identity_derived_ready_scan` 单例。迁移 198 应创建的该行在现场也为空；按[受限恢复 SQL](../scripts/maintenance/ncu-derived-ready-scan-restore-20261102.sql)（SHA256 `2b8d6e06b319f384d58e126f8b60b4187fa6cedf6bee8b8ba201cc09173ff0cc`）复核不可变截止点及增量登记触发器后，只插入初始扫描游标，保留既有 ready 键和片段状态。新鲜派生模式按设计不扫描旧历史，因此游标保持 `-1`、`done=false`；UTC 12:40:01 的状态已更新为 `fresh_index_keys_present`，不是全部派生完成。

## 已核对的阻塞与边界

184 的 `identity-fresh-b2-20261025` 是唯一活动 `identity-http` cutover，`start_offset=784452`。同一作用域的旧汇总仍是 `accepted_sequence=673156`、`processed_sequence=672823`、`pending_records=2041`、`export_pending_records=9894`，而 `identity_ingest_batches`、`identity_ingest_fragments` 和拆分进度三表均无记录。下一条批次在接收事务中被 `identity_cutover_not_active` 拒绝；桥接保留冻结批次并重试，不能把 503 当作成功接收。

旧 b2 行的 `legacy_cancel_id=redis-quarantine:identity-fresh-b2-20261025`，但 `stream_discard_manifest` 没有该身份源的行。旧计数对应的逐批原文、哈希和完成状态不能由 PostgreSQL 证明；恢复审计标记为 `unverifiable_gap`，不称已完成或已取消。用户固定的 NCU 派生新起点为 2026-10-29 13:11:29 CST；现场 Redis source 队列采样的头尾消息均晚于此点，冻结 processing 批次为 10 月 31 日，必须继续消费它们，不能隔离为旧历史。

Redis source 队列维持 100000 条，采样间队头移动，Redis 全局 `LPOP` 计数增长；这证明消息离开本桥接源列表，尚不能证明它们没有其他存档或已经丢失。恢复后的覆盖结论需单独审计上游保留策略和其它消费者，不能把新起点后所有流量说成已完整保留。

## 候选实现

PG 迁移 `222_identity_fresh_recovery_gap_audit.sql` 新建不可变缺口审计；同时防止旧 `identity_initialize_split_progress()` / `identity_restore_legacy_progress()` 在恢复后覆盖新基线或旧缺口。先迁移，再切应用；迁移保持旧应用兼容。`identity-recovery fresh-cutover` 默认只读检查，`--apply` 才进行单事务切换：锁定旧 scope 和 b2，要求旧计数完全匹配、旧 inbox/fragment/IP 待办及拆分进度均为空；记录旧审计链接与 Redis 队列边界样本；为新输入建立从 673156 起算、记录数为零的拆分进度；只把 b2 改为 `closed`，插入唯一活动 b3。旧 `identity_pipeline_scopes` 行一字不改。`historical_gap` 单独显示旧不可核验范围 672824–673156 及待办 2041/导出 9894，不把它并入新输入的完成数。

新的 b3 `legacy_cutoff_at` 沿用 b2 的旧 legacy 边界；b3 实际恢复时间以新行的 `cutover_at` 和缺口审计的 `recorded_at` 为准。不能把 b3 的创建时间作为过滤 Redis 队列中 10 月 31 日以来有效消息的条件。

## 获现场更新授权后的操作与验收

1. 先核对 184 主机、`current`/`previous`、服务文件实际路径、PG/CH 迁移账本、运行环境变量和磁盘。特别核对 NCU 专用 `proxy-sentinel-ncu-identity-materializer.service` 的固定 r25 路径及当前 inactive 状态；不要把全局 identity materializer 当作它。部署包验证和完整安装仍按 AGENTS.md，存在 PG222 时用 `--skip-backup`。
2. 应用已含恢复 CLI 且 PG222 生效后，先停桥接和 NCU 专用物化器；核对二者 `inactive`。不清空、不重命名 Redis source/processing 列表及冻结 manifest。以现场 unit 和配置核实 **两个确切列表键**，用 `identity-recovery redis-audit --addr "$NCU_EVENT_REDIS_ADDR" --password-file /opt/proxy-sentinel/secrets/ncu-event-redis.password --event-list <source-key> --processing-list <processing-key> --output /opt/proxy-sentinel/config/ncu-redis-audit-<time>.json` 生成 0600 审计。该命令前后检查服务停机，只保存长度、首尾时间/哈希和冻结 manifest 哈希；样本只证明采样时边界。
3. 使用 `identity-recovery fresh-cutover --source ncu-srun4k --sensor-id ncu-auth-redis --campus-id ncu --access-domain campus-auth` 只读检查；记录输出。`--apply` 需再传 `--old-epoch identity-fresh-b2-20261025 --new-epoch <唯一b3> --previous-release <实际旧版> --expected-event-list <source-key> --expected-processing-list <processing-key> --redis-audit-file <刚生成的文件>`，以及只读输出的五个 `--expected-*` 数值。样本超过 10 分钟、服务活动、计数变化或出现任何旧批次时直接拒绝，重新核对后才重试。
4. 事务成功后核对 b2 仍存在且仅状态为 `closed`，b3 为该源唯一 `active`、`start_offset=673156`；缺口审计与三张拆分进度表一致，旧 scope 汇总仍原样。184 的 `PROXY_SENTINEL_IDENTITY_STREAM_EPOCH` 目前写在 `proxy-sentinel-control-plane-eventbus.service` 的 systemd 环境中；保留原单元，新增并核对一个优先级更高的受保护 drop-in，把该变量设为 b3，保留 fragment/split 开关。`daemon-reload` 后依次重启控制面、桥接和确认兼容的 NCU 专用物化器，核对实际进程环境与发布目录。应用回退可用兼容 PG222 的旧版二进制继续指向 b3，不撤销迁移、不恢复 b2 起点，也不调用旧进度恢复函数；回退应用时保留 b3 drop-in。
5. 同一冻结 batch 首次应收到 HTTP 202，重试返回同一 receipt；`accepted_sequence` 从 673156 到 673157，原 Redis processing 前缀只有确认后才移除。随后有界观察接收、领取、投影、原文导出、NCU `/18082/readyz`、源/处理中队列和最老消息时间。记录新输入缺口与源端覆盖风险；任何阶段失败保持原始 Redis 消息和缺口审计，停止桥接并保留应用回退入口。

本地只有约 45 GiB 可用空间，未启动完整快照或 PostgreSQL 容器；目前完成定向单元与 sqlmock 事务故障验证，真实 PG 约束、迁移及持续消费仍必须在授权现场验证。
