# 高校生产版运维说明

## 首次启用本地 RBAC

生产模式将用户和会话保存在 PostgreSQL。密码通过环境变量传入，命令不会覆盖已有账号：

```bash
export PROXY_SENTINEL_ADMIN_PASSWORD='请替换为至少 12 位的独立密码'
/opt/proxy-sentinel/bin/proxy-sentinel control-plane bootstrap-admin \
  --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --username admin \
  --name 系统管理员
unset PROXY_SENTINEL_ADMIN_PASSWORD
```

文件用户库仅供显式 `storage-mode=file` 的开发环境使用。生产 HTTPS 入口必须启用 `--auth-cookie-secure=true`。全局 `--read-only` 仍是紧急只读熔断，优先级高于角色权限。

## 风险规则重算

先生成最近七天的新旧规则对比报告，人工确认后再加 `--apply`。应用前会把当前快照归档到历史表，人工结论不会被重算覆盖。

报告的生成时间仅表示重算时间；快照的更新时间继续使用其证据的最新观测时间，避免重算延长历史风险的有效期。迟到的回放结果会保留在历史表，但不能覆盖观测时间更晚的当前结果。同一观测时间允许规则修正重新解释证据，并保留已有人工结论。

证据的观测时间按 IP、账号以及实际贡献的信号分别记录。批次最新时间仅用于选择滚动窗口；其他终端的流量、同一终端的普通流量都不能刷新此前协议命中或账号 MAC 线索的时间。重复观测到同一信号可以更新其时间，乱序事件则取该信号的最新有效时间。TTL 线索只使用被选入证据的方向和路径样本时间。

```bash
proxy-sentinel risk recalculate --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --window 168h --ruleset-version university-v2 --output risk-comparison.json
proxy-sentinel risk recalculate --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --window 168h --ruleset-version university-v2 --apply --output risk-applied.json
```

## 身份接入凭据与处置主密钥

不要把身份接入凭据或处置主密钥写在命令行参数中。使用权限为 `0600` 的 systemd EnvironmentFile：

```ini
PROXY_SENTINEL_IDENTITY_INGEST_KEY=<独立随机凭据>
PROXY_SENTINEL_ACTION_MASTER_KEY=<至少 32 字节随机主密钥>
```

身份批次调用 `/api/v1/integrations/identity/events`，同时携带 `Authorization: Bearer ...` 和稳定的 `Idempotency-Key`。主密钥只用于本地加密北向连接器凭据；丢失后旧凭据不可解密，需要重新录入。

管理端可通过 `GET /api/v1/integrations/identity/batches` 查看每个批次的处理状态、错误明细与重试次数；修复数据源或存储故障后，管理员调用 `POST /api/v1/integrations/identity/batches/{batch_id}/replay` 重放服务端保留的标准事件。重放沿用原事件 ID，不要求上游再次发送原始厂商字段。

## 上线门槛

北向连接器默认保持影子模式。真实模式启用前必须满足至少 7 天影子验证、自动候选人工准确率不低于 95%、无校园 VPN/教学科研/基础设施误处置样本，并验证冷却、熔断、失败回退及人工撤销。身份数据中断时动作硬门槛自动阻断。

控制面对每个北向 JSON 请求设置 `Idempotency-Key`、`X-Proxy-Sentinel-Timestamp` 和 `X-Proxy-Sentinel-Signature`。签名内容为 `HMAC-SHA256(secret, timestamp + "." + raw_body)`，接收端应拒绝超过 5 分钟的时间戳并按幂等键去重。异步结果回调 `/api/v1/actions/callback` 使用相同签名算法，只接受 `succeeded/failed/revoked` 终态。每次请求尝试、响应摘要、重试次数和下次执行时间均持久化；重启后继续执行，人工撤销与到期解除会创建独立的 `release` 动作，避免复用原处罚幂等键。

30 机器继续使用 `--device-fingerprint-auto-update=false`，仅导入本地校验通过的离线特征包，不主动访问 IEEE、GitHub 或 Fingerbank。

## 本地权限矩阵

| 能力 | viewer | reviewer | operator | admin |
| --- | --- | --- | --- | --- |
| 风险、证据、事件、终端、态势、案件、审计只读 | 是 | 是 | 是 | 是 |
| 案件分派、评论、状态与结论 | 否 | 是 | 是 | 是 |
| 终端登记 | 否 | 否 | 是 | 是 |
| 影子动作执行与人工撤销 | 否 | 否 | 是 | 是 |
| 校区、区域、接入点维护 | 否 | 否 | 否 | 是 |
| 身份接入、北向连接器、规则与特征库管理 | 否 | 否 | 否 | 是 |
| 用户管理 | 否 | 否 | 否 | 是 |

前端隐藏无权入口仅用于减少误操作；服务端中间件是权限边界，越权统一返回 `403 permission_denied`。写请求在启用本地登录后还必须携带当前会话的 CSRF Token。

## 实时统计安静窗口与处理检查点

五分钟统计的数据 `as_of` 表示已发布事件窗口的覆盖时间，不会因没有新流量而推进。`read_model_runtime_state` 中的 `activity-v3-realtime-health` 独立记录实时工作循环是否成功检查了采集回执、待执行任务，并完成本轮发布与任务确认。它只保存处理状态、最近成功时间和真实错误，不制造事件或更改原始观测时间。

小时/日汇总保留原有保护：实时覆盖滞后超过 90 秒时暂停；恢复前需要连续五分钟健康（滞后不超过 60 秒）。当最近 30 秒内有成功处理检查点，而且没有到期、待重试或已关闭但未收尾的五分钟任务时，可以将网络安静视为处理健康，让既有小时/日任务正常执行。检查点过期、回执查询失败、发布失败、任务确认失败仍会阻止这一安静分支。升级初次启动尚无检查点时沿用事件覆盖滞后的判断。

五分钟窗口在部分发布后保留收尾代次，到窗口结束后 90 秒最终发布并生成父级小时任务。判断统计时效时需同时查看事件覆盖与处理状态；旧数据在安静网络中保留旧覆盖时间是正常行为，工作进程停滞则会呈现真实错误或过期检查点。

`readyz` 并行执行各个独立检查。统计读模型仍是可选组件，超时会显示 `delayed` 与错误原因；存储、身份库、认证库等必需组件失败仍返回 503。每次请求保持五秒整体截止时间，不允许可选检查先耗尽等待时间再把健康存储误报不可用。

### 信号到达检查

进程存活不代表检测有输入。2026-10-08 起 184 的共享 SYN 采集和 Suricata 停用、10-10 完整安装又停掉设备信号与入库约 70 分钟，期间 `readyz` 一直返回 ready，共享检测因此两天没有任何新观察。控制面可声明“必须持续到达”的信号：

```dotenv
PROXY_SENTINEL_SIGNAL_FRESHNESS='ttl=10m,dhcp=20m,ssdp=30m,identity=10m'
```

写入 `config/runtime.env`（完整安装保留未列入过滤的变量），或用 `control-plane serve --signal-freshness` 传入。格式为 `事件类型=最长间隔` 或 `来源:事件类型=最长间隔`，间隔 1 分钟到 24 小时；来源限定用于区分同类型的不同采集器，例如重新启用共享 SYN 采集后追加 `shared-syn-sidecar:ttl=10m`，避免路由 TTL 正常时掩盖共享 SYN 已停止。

控制面每分钟在后台查询一次 ClickHouse 标准事件，回溯最长间隔的两倍，请求路径只读缓存。结果作为可选组件 `signals` 出现在 `readyz`：全部正常为 `ready`，有信号超时或回溯期内没有到达为 `stale`，查询失败为 `delayed` 并保留上次结果。它不会让 `readyz` 返回 503，避免夜间安静网络或有意停用某个采集器时让应用更新误回退；系统状态接口此时显示 `degraded`，指标输出 `proxy_sentinel_signal_age_seconds` 与 `proxy_sentinel_signal_stale`。年龄由 ClickHouse 按自身时钟计算，不受控制面时区影响。184 实测该查询在 40 分钟回溯下约 0.05 秒。

未配置时不运行该检查。数值应按现场夜间低谷的实际间隔设定，新增或停用采集器时同步调整，否则会持续误报或漏报。

采集回执的最近 N 条查询按传感器使用现有 `(sensor_id, started_at DESC)` 索引取各自最近 N 条，再按 `started_at DESC, run_id DESC` 合并并截取全局 N 条。`sensors` 是回执的外键父表，空闲传感器不产生虚假回执；相同时间用 run_id 保持稳定排序。它不缩短回执保留期、不使用缓存伪造最近时间，也不忽略查询错误。避免健康检查、概览与采集状态为了读取最近一条记录重复排序全部历史。

## 路由观察时间与判定历史

路由观察列表、详情、终端摘要及有效事实统一使用 PostgreSQL 的 `first_seen`、`last_seen`、`expires_at`。新一批事实刷新不会覆盖同一观察的更早首见时间；JSON 中仍保留来源细节，原始标准事件与既有判定历史不删除。

判定历史在状态、分数、规则版本或冲突集合变化时追加。`changed_at` 记录这次重新判定的时间，事实自身的观测时间继续保留在事实字段中。同分同状态下新出现的关联冲突也必须入历史。最新判定及展示顺序按递增历史 ID 取值，防止旧版本使用未来包时间的记录永远占据“最新”，引发重复审计。

共享观察详情的当前状态同时检查数据库有效期、现行规则和近期已结束窗口。仅保留的历史 JSON 判定不能绕过数据库的显式失效。

应用发布在解包前校验 tar 成员路径、文件类型和重复路径，同时依据目标发布目录所在文件系统的可用空间与 inode 预留容量。默认保留 1 GiB 和 1024 个 inode，避免新包挤占在线数据库写入及回退元数据的空间。`PROXY_SENTINEL_UPGRADE_MIN_FREE_BYTES` 可提高预留值，最低不能低于 256 MiB。检查失败不会切换 current 或重启服务，临时 stage 自动清理。容量检查只负责发布准入，不能代替存储扩容或日常保留任务。

## Suricata 辅助日志轮转

安装脚本除 EVE 原始事件外，还为同目录的 `stats.log`、`fast.log` 和 `suricata.log` 配置每小时检查，默认超过64MiB轮转、保留4份。可通过 `PROXY_SENTINEL_SURICATA_AUX_ROTATE_SIZE` 与 `PROXY_SENTINEL_SURICATA_AUX_ROTATE_COUNT` 调整。采用延迟压缩并发送HUP重新打开输出，不重启采集；单次检查间隔内可能超过尺寸阈值。轮转策略不改变EVE及数据库证据保留。

已有大统计日志可以先按配置轮转，确认采集进程已关闭归档文件描述符后压缩归档，保留全部内容。需校验压缩后的解压内容哈希以及采集进程、EVE文件、读取进度和readyz；不要截断仍被写入的日志。压缩后的一号归档与既有delaycompress轮转兼容，应先用临时日志回放确认当前logrotate版本行为。30已在2026-10-01完成此项验证，约1.80GB统计日志归档为115.5MB，根盘可用约8GiB。此数字是现场时点，不能代替后续容量监测。

实时采集在轮转后按设备号/inode匹配保留的未压缩`.1`归档，先读完其未提交完整记录，再读取新文件；仍以原始路径登记检查点，失败重试保留文件身份和批次ID。Zeek表头与记录来自同一文件句柄，防止轮转期间字段错配。归档尾部只有半条记录时保持进度并报错等待补全，不伪装成已经读完。此恢复仅支持身份仍可匹配的未压缩`.1`，不代表能自动恢复已经压缩、删除或采用其他命名方式的旧文件；不要在确认读取完毕前提前压缩EVE一号归档。源切换诊断保留`truncated`，归档读取批次另记`archive_draining`，延迟字节合计归档尾部和新文件待读字节。

[Suricata官方日志轮转文档](https://docs.suricata.io/en/suricata-8.0.6/output/log-rotation.html)说明HUP用于重新打开日志文件。

## 七天终端快照清理的运行预算

`device-retention` 默认只预览；加 `--apply` 后仍逐批重新检查案件引用、每个传感器/窗口最新批次和每个IP最新快照。原始证据、案件历史与审计不在清理范围内。每批最多1000行，常规批次同时限制为8MiB，超大单行独立处理，既有锁等待、语句超时和重试缩批机制继续生效。

每次运行默认最多13分钟，可用 `--max-duration` 缩短。时间预算包含预览、查询、事务及重试等待，给15分钟的systemd上限留出退出时间。预算用尽会主动取消当前操作，并以 `time_budget_exhausted` 记录阶段、已确认提交的批次数和删除行数；本批提交结果无法确认时标记 `batch_outcome_unconfirmed=true`，不将其计入已确认删除。下一次定时运行重新扫描符合条件的快照。真实数据库错误、预览错误和外部SIGTERM仍返回失败，不作为预算结束隐藏。

服务可在 `config/device-retention.env` 设置 `RETENTION_MAX_DURATION=10m` 等较小预算；已有未带此参数的服务使用二进制默认13分钟。该预算不表示所有过期快照已经清完，也不表示操作系统已回收空间，日志中的 `disk_space_reclaimed` 保持 `not_measured`。

逐批候选查询先生成小型传感器/窗口/IP键集，再利用已有索引查询各组最新批次与最新IP快照，避免每批对全部历史做两次大排序。候选窗口、顺序、行数/8MiB约束和最终短事务中的最新/案件引用重检保持一致；候选列表没有删除权限，最终检查仍是执行依据。预览仍使用完整只读聚合，每轮一次。

候选列表不为空而最终删除为0，可能由行锁或并发新增案件引用引起，不能报告“已无可清理快照”。空删除提交确认后返回独立的无进展结果，命令保持批次大小、重新选候选并最多重试两次；仍无进展时以 `candidate_batch_deferred` 结束并保留已确认统计，留给后续定时任务。真正无候选仍报 `no_eligible_snapshots`，语句失败、提交不确认和外部取消仍保留失败语义。

## 根文件系统容量监测

`system/status` 的 `runtime.host.root_filesystem` 与Prometheus的 `proxy_sentinel_root_filesystem_*` 指标读取控制面进程所在命名空间的 `/` 文件系统，只做一次statfs查询。它不代表单独挂载的数据盘；数据库连接是否正常仍由既有健康探针判断，容量告警不自动删除证据或执行处罚。

可用字节采用 `f_bavail`，不把超级用户保留空间算作普通用户可用容量；已用比例按 `已分配 / (已分配 + 可用)` 计算，与df的可用空间口径一致。inode不支持时省略该组指标，采样失败时返回真实错误并将probe_success置0，不发布伪造的零容量。非Linux环境省略此项。计数字段检查零容量、溢出和不一致，避免整数回绕。

运营工作台折叠的“平台健康与运行负载”摘要仍显示容量告警，展开后查看根盘可用/总容量、已用比例和inode。可用不足1GiB或inode不足1024为严重容量告警；已用至少90%或inode已用至少95%为容量紧张。这些是本程序的运维提示阈值，发布准入继续单独执行既有空间预留检查。

[Linux statfs手册](https://www.man7.org/linux/man-pages/man2/statfs.2.html)定义普通用户可用块与inode计数；[GNU容量读取实现](https://github.com/coreutils/gnulib/blob/master/lib/fsusage.c)保留可用空间与保留块的区别。

### 设备画像表达式索引的统计内存

`idx_device_inventory_candidate_ids` 保留完整 devices 数组的 GIN 索引以查询设备 ID。自动 ANALYZE 会先计算并复制样本的索引表达式结果，再应用宽值保护；原始 inventory 列的宽值跳过不会避免该表达式复制。30 的 PostgreSQL 18.4 日志曾在 Analyze Index 上记录22873814592字节已使用内存，导致明显换页压力。

迁移077只将这个表达式索引第一列的统计目标设为0，跳过随后 ANALYZE 的表达式样本计算，保留 GIN 查询、索引文件、全部画像数据和其他列统计。它不禁用自动 vacuum/analyze、不降低其他列统计目标、不改变任何证据或保留策略。整幅设备数组分布无法提供有意义的设备 ID 选择率；若后续需要选择率，应针对小型标识字段单独设计，不能重新采样巨型画像数组。

局部设置只对下一轮分析生效。现场若旧分析仍占用异常内存，应先确认索引统计目标已改为0，再严格匹配数据库、进程ID、backend_start、autovacuum worker类型和 `autovacuum: ANALYZE public.device_inventory_snapshots` 当前语句，记录审计后取消该分析；不得按进程名批量取消、终止数据库或取消正在回收TOAST的VACUUM。以后会由正常维护继续更新其余统计。

依据：[PostgreSQL 18 ALTER INDEX](https://www.postgresql.org/docs/18/sql-alterindex.html) 与 [18.4 analyze.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_4/src/backend/commands/analyze.c) 的 `compute_index_stats`、`examine_attribute`。

单个实时采集源失败不会停止其他源。即使没有配置告警webhook，也会在服务日志中记录源类别/路径，并尝试写入`realtime_ingest/source_error`错误诊断，保留具体错误与原始源路径。按源五分钟限频，诊断写入单独限制为最多五秒或更短的配置写入超时，不更新正常采集心跳。诊断存储自身不可用时不能承诺诊断已落库，应查看服务日志；进程关停取消不会伪造源错误或正常心跳。

失败批次审计采用独立但有界的上下文：事件写入失败或父上下文取消后，最多五秒或更短配置写入超时尝试登记失败；审计失败不覆盖原始事件写入错误，不提交源检查点。避免无超时后台SQL无限阻塞其他源轮询和进程退出。

设备画像事实按传感器及闭合时间窗口选择：last_seen既不早于窗口起点，也不晚于当前批次结束时间。未来信号不参与当前候选数或共享线索，原始事实继续保留供审计；重放历史批次也不能借用后来观测的信号。只有聚合last_seen越界的事实暂不采用，不伪造其窗口内历史计数。

历史发布目录也会占用根盘。`scripts/retire-releases.py --plan PLAN`默认仅验证，`--apply`才退役明确列入计划的旧应用副本。执行前必须把完整发布包和SHA256校验文件保存到`data/release-backups`，核对包内逐文件摘要与计划，并保留当前/上一版、运行中进程和systemd配置引用的所有版本。工具与发布更新共用排他锁，拒绝符号链接、额外文件、备份或发布文件变化；不是按目录日期批量删除。每次动作记录追加审计，压缩恢复包继续保留在30根盘。恢复时先校验相应发布包，再按通常应用发布流程安装；数据库、采集原始文件、案件、审计和当前回退目录不属于退役对象。移除副本字节不等于当时df净变化，应分别记录备份体积和根盘容量。

采集健康与本机采集状态通过传感器ID精确读取最近记录，不借用全局列表最新记录；全局历史列表仍保留原有范围和顺序。采集状态的24小时事件类型统计也按同一传感器统计，并排除统计时刻之后的事件。完成时间无效或超前超过五秒的采集记录不能使就绪检查通过；陈旧/空闲/暂无数据仍保持原有状态语义。新影子回放摘要保存sensor_id，文件模式尊重此标识并选择本机最新摘要；旧摘要缺少此字段时沿用已配置的文件目录命名空间，不据此宣称旧共享目录具备可验证的跨传感器隔离。

## 临时验收构建物的回收

30 的专用临时验收目录会累积旧 Linux 验收程序和发布压缩包。`scripts/deploy/retire-acceptance-artifacts.py --plan PLAN` 默认只核验，`--apply` 才回收明确列出的文件；CLI 限定 `/tmp/sentinel-release-acceptance-30-YYYYMMDD` 和 `/opt/proxy-sentinel`。它不处理业务数据库、证据、采集原始文件或应用发布目录。

计划须逐项记录原文件路径、设备号、inode、大小、修改时间和 SHA-256，以及已经在本地独立核对的恢复副本路径、大小和摘要。调用方必须在执行前重新核验本地副本；远程工具只能核验该副本声明与原文件摘要是否一致，不能替代跨机器的副本实际存在性检查。没有对应副本的文件保留。

工具仅接受不小于 8MiB 的 Linux amd64 ELF 可执行文件及带正确发布身份的旧压缩包。当前及上一版本压缩包、`bin` 保留路径、运行中 inode、systemd 引用的临时目录均受保护；拒绝符号链接、路径穿越、重复路径、硬链接以及摘要或身份变化。与应用发布更新共用非阻塞排他锁，预检失败不删除任何候选。

执行时先将候选原子移入同文件系统的私有暂存目录，全部重新核验后再逐项移除，并持久化目录变更与追加审计。并发创建在原路径的新文件不会被移除；失败时恢复仍在暂存的文件，恢复名冲突时保留两份并记录位置。进程被强制终止时，按审计中的暂存及恢复副本映射检查残留，不把失败或中断当作全部清理成功。

审计保存在 `data/acceptance-artifact-retirement-audit`，保留本地恢复副本及每项摘要。移除文件的逻辑字节量与文件系统可用空间变化分别记录；采集和数据库仍在写入时，不能把两次 df 差值全部归因于本次回收。

## 204 被动发现的交接与核验

204 的默认设备视图使用近 24 小时、7 天和 30 天三个统计窗口。每五分钟为每个窗口分别发布设备数量与排行、覆盖报表。筛选、设备列表和完整导出读取实时索引。CSV 的最后四列记录行的种类、筛选范围、快照时间和总数，空结果只有一条明确标注的导出摘要。按设备记录行计数可复核总数。

先启用迁移 254 的四个地址关联触发器，再在被动发现服务启用 `PROXY_SENTINEL_DISCOVERY_ADDRESS_LINK_WORKER=true`。以 `SELECT discovery_address_links_ready()` 检查存量接入。新旧列表和导出在同一事务对齐后，在控制面的 `PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS` 增加 `address_links`。回退该项时保留原有 list、statistics、coverage 选项。启用 `PROXY_SENTINEL_DISCOVERY_REPORT_PUBLISHER=true` 让被动发现服务生成报表，工作进程的结构化读配置随现场已核验的读路径设置。下列查询的六个结果齐全后，可分别开启控制面的 `published_metadata` 和 `published_coverage`。任一入口可单独退回实时读取。

```sql
SELECT sensor_id, report, hours, bucket_start, as_of, published_at
FROM discovery_report_publications ORDER BY sensor_id, hours, report;
```

原文归档使用迁移 255 的 `passive_archive_capture` 触发器和被动发现服务的 `PROXY_SENTINEL_PASSIVE_RAW_ARCHIVE=true`。204 的文件入库服务也启用同一个开关，给主设备信号文件中的 packet-sidecar 设备记录保存原始行摘要与提交批次，覆盖 TTL、ARP、NDP 和设备公告。已留存的旧观测能否恢复取决于原有批次、行摘要和源文件。每个原文引用都有对应的观测、事件和语义摘要。按源批次的首次成功提交时间计保留期。工作进程校验文件代次、批次摘要和行摘要，重新从 ClickHouse 的 `passive_discovery_raw_archive` 计算归档正文摘要后才登记成功。存量从主键游标恢复，单独开启 `PROXY_SENTINEL_PASSIVE_ARCHIVE_ADOPT=true`；观察队列增长时可独立暂停。原文已轮转或首次提交凭据缺失的引用进入缺口。查询下列账本可区分等待、重试、达到八次重试上限、无原文引用以及已核验。找到对应原文并校验文件身份后，按具体 batch_id、row_hash 重置 attempts 和 next_attempt 即可重试，保留原始入库时间。

```sql
SELECT count(*) FILTER(WHERE verified_at IS NOT NULL) AS verified,
       count(*) FILTER(WHERE verified_at IS NULL AND attempts=0) AS waiting,
       count(*) FILTER(WHERE verified_at IS NULL AND attempts BETWEEN 1 AND 7) AS retrying,
       count(*) FILTER(WHERE verified_at IS NULL AND attempts>=8) AS stopped
FROM passive_archive_rows;
SELECT last_id, complete, examined, started_at FROM passive_archive_adoption;
SELECT count(*) AS missing_reference_members FROM passive_archive_members WHERE batch_id='';
```

隔离恢复时按已核验的 batch_id、row_hash 取出 raw_b64，Base64 解码后的字节应与原始记录（不含行结束符）逐字节相同。重复处理同一批次后复查原文数和 accepted_at。必要证据热查 30 天，保留至首次成功入库满一年；当前版本保留现有热数据，归档没有自动清理规则。存量尚未核验、案件引用未排除或容量尚未实测的区间继续保留。

### 204 只读巡检与容量采样

204 应用包内的 `scripts/passive_health.py` 使用现场已有的 PostgreSQL、ClickHouse 容器和本机控制面生成一行 JSON。204 发布人员核对 `current` 后单独安装包内的 `proxy-sentinel-passive-health.service`、`proxy-sentinel-passive-health.timer`，执行 `systemctl daemon-reload` 和 `systemctl enable --now proxy-sentinel-passive-health.timer`。每轮巡检结束十分钟后再次采样。读取 `journalctl -u proxy-sentinel-passive-health.service` 查看采样，读取 `journalctl -t proxy-sentinel-passive-health -p warning` 查看告警。回退前先停用现场新增加的 timer。

巡检按图表表统计最近一小时成功新增 part 和合并次数。至少两次新增、零次合并且同一分区有多个活跃 part 时告警，运维人员结合连续样本、合并策略与负载判断。单分区活跃 part 达到该表有效 `parts_to_delay_insert` 的 80%、近一小时出现 DelayedInserts 或解析输入错误、硬件队列出错、归档重试耗尽、readyz 非 200、存在失败单元、数据盘可用低于 20% 均会进入告警。采样失败记录指标名称并返回非零。累计错误和各来源处理水位保留在 JSON 中。

从工作区执行 `python3 scripts/maintenance/capacity_204.py collect artifacts/204-operations-20261125`。脚本通过 SSH 在 204 执行只读查询，在本地按北京时间保存 `capacity-YYYY-MM-DD.json`，同日复跑保留第一份成功样本。每天在同一时段采集，使用 `python3 scripts/maintenance/capacity_204.py report artifacts/204-operations-20261125` 查看逐日差量。跳过缺日区间，WAL 字节差按实时间隔折算速率。统计重置或表 OID 变化时重新累计 HOT 比例。连续七个采样日后按表估算净增长，分别列出热历史 30 天与归档 365 天的增量，扣除数据盘 20% 余量。当前态、其他业务和有 TTL 的流量表单列日增长。整机容量结论还需核对这些业务的留存策略及数据库之外的空间变化。

7 天和 30 天覆盖报表从同一份硬件身份投影和类型变更账本读取趋势。后台发布时按传感器计数，随已有报表一起更新。首次观测按身份的最早观测时间计入。类型变更只统计确认类型变为另一确认类型的身份，同一身份同一窗口只计一次。仅上期有观测表示末次观测落在上一个等长时段。迟到证据可改变后续发布结果。页面给出投影的最早留存观测、账本起点和最近成功时间。区间超出留存边界时显示缺口，无支撑记录的项目显示覆盖待核查。流量汇总表的 8 天及 31 天 TTL 与这些硬件身份证据各自独立。


### 204 生产落地治理（容量自愈、巡检监控、受审计轻写与验收门禁）

204 被动资产发现节点围绕长期无人值守运行落地了四层治理能力：

1. **全链路磁盘与保留期治理**：
   - Zeek 启用原生 1 小时轮转（`assets/zeek/local-device-signals.zeek` 的 `Log::default_rotation_interval = 1 hr` 与 `zeek-postrotate.sh`），并由 `proxy-sentinel-zeek-log-prune.timer` 每小时执行 `scripts/zeek_log_prune.py`：保留最近 35 分钟未压缩轮转文件供 `ingest` 尾读追齐，超过 35 分钟自动 `gzip` 压缩，高体积连接日志保留 24 小时、协议发现日志保留 72 小时自动淘汰。
   - ClickHouse 迁移 `077_passive_storage_ttl.sql` 为 `passive_discovery_raw_archive` 绑定 365 天（1 年）TTL，配合既有 7 天/8 天/30 天 TTL 与 `proxy-sentinel-device-retention.timer` 形成完整热/冷生命周期闭环。
   - 部署磁盘安全余量默认上调至 `PROXY_SENTINEL_MIN_FREE_KB=104857600`（100 GiB），同步开启 `--zeek-ssh` 采集 SSH Banner 辅助网络设备与主机识别。
2. **故障可感知与容量监控**：
   - `proxy-sentinel-passive-health.timer` 每 10 分钟写入原子快照 `/opt/proxy-sentinel/data/passive-health/latest.json`，覆盖数据盘使用率（80% 预警 / 90% 告警）、PostgreSQL / ClickHouse / Zeek 字节分解、发现源最大水位滞后（>15 分钟告警）、定时器激活状态、失败 systemd 单元及可选 Webhook 推送；单次探针超时写入 `errors` 字段但不中断快照输出。
   - 控制面提供 `GET /api/v1/ingest/passive-health` 供前端「数据流与采集 → 系统健康与容量」面板只读展示，同时在 `/metrics` 暴露 `proxy_sentinel_passive_health_*` Prometheus 指标。
3. **受审计的资产运营轻写层**：
   - 在全局 `--read-only=true` 继续硬锁策略配置、北向处置、采集器与扫描配置的前提下，可通过 `PROXY_SENTINEL_ASSET_ANNOTATIONS_WRITE=true`（或 `--asset-annotations-write`）仅放行资产人工核验纠偏（`PUT/DELETE /api/v1/discovery/annotations`）与校方资产台账导入管理（`POST/DELETE /api/v1/discovery/ledgers`），权限收敛于 `endpoints:write` 并保留 CSRF 校验与全量 `audit_logs` 审计记录，绝不改写底层原始观测证据。
   - 迁移 `260_asset_annotations_and_ledgers.sql` 建立 `asset_manual_annotations`、`asset_ledger_snapshots`、`asset_ledger_entries` 三张业务表，支持在「发现设备详情弹窗」内人工核验/纠偏并在「覆盖报表 → 人工核实」持久化导入校方 AC/交换机/安防/打印机 CSV 台账，实时生成“已登记在线 / 新发现未登记 / 台账离线 / 属性不符”四象限差异清单并导出 CSV。
4. **一键验收门禁与 7 天烤机清单**：
   - 每次升级或日常巡检可直接运行 `/opt/proxy-sentinel/current/bin/proxy-sentinel doctor --samples 20`（传入 `--auth-user`/`--auth-pass` 可额外采样认证态发现列表、元数据、覆盖报表与健康接口的 P50/P95/P99，默认门禁 P95 ≤ 500ms、P99 ≤ 1000ms），支持 `--format json` 接入自动化流水线。
   - 7 天无人值守烤机复核项：连续 7 日观察 `disk_used_ratio` 稳态波动（不单调爬升）、`max_watermark_lag_seconds < 900`、`systemd_failed_units = 0`、5 个运维定时器均保持 `active`，以及校方真实台账对账与人工核验闭环运行正常。
