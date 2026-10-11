# 本地 Zeek 回放（方案 B）

## 目标

把 `192.168.0.30` 上 Zeek 实采的日志只读拉到本机，灌进本地 PostgreSQL + ClickHouse，
跑通 `ingest -> 风险物化 -> 读模型 -> 控制面`，让前后端逻辑可以对着真实数据调整。

本流程**只服务本机开发**：

- 对 0.30 只做 `stat` / `tail -c` / `rsync` 读操作，不写它的任何文件、配置、数据库或服务。
- 不改 `deploy/compose/storage.yml`、不改业务代码；本地镜像与资源限制单独放在
  `scripts/local/` 与 `deploy/compose/local.yml`。
- `192.168.0.30` 是开发影子节点，不是现场 `root@222.204.3.184`；本流程不授权、也不执行任何部署。

## 前置条件

| 项 | 要求 |
| --- | --- |
| Docker | OrbStack 已启动（`docker context` = `orbstack`） |
| 内存 | 建议把 OrbStack VM 提到 12GB；默认 8GB 时 `local.yml` 会把 ClickHouse 限制到 6GB |
| 工具 | `python3`、`jq`、`rsync`、`ssh`、`curl`、`go`、`pnpm` |
| 磁盘 | `data/` 余量 ≥ 5GB（一次全量快照约 61MB，数据库按事件量增长） |
| SSH | `ssh root@192.168.0.30` 免密可用（只读账号即可） |
| 端口 | `25432`、`28123`、`18080` 同一时刻只能有一套本地栈占用 |

先做环境自检：

```sh
make local-doctor
```

## 快速开始

```sh
# 1. 从 0.30 拉一份 Zeek 快照（约 50 秒 / 61MB）
make local-pull

# 2. 起完整本地栈（首次会构建 Go 二进制与前端产物）
make local-up

# 3. 查看状态与日志
make local-status
make local-logs LOG=ingest

# 4. 停止 / 重置
make local-down
make local-reset
```

一次性快照适合复现某个时间点；如果需要让实时窗口（共享行为、风险滚动窗口）持续有新数据，
用增量镜像模式：

```sh
# 1. 建增量镜像（首次可用尾部播种控制体量），并保存配置
./scripts/local/local-stack.sh sync --with-eve --eve-bytes 50M --with-ttl --ttl-bytes 50M

# 2. 重建本地栈：up 会发现 live/ 目录，ingest 改读增量镜像并启动常驻镜像进程
./scripts/local/local-stack.sh reset

# 3. 之后随时手工补一轮，或让常驻进程按间隔自动补
./scripts/local/local-stack.sh sync
make local-status          # sync 进程应显示"运行中"
```

浏览器打开 <http://127.0.0.1:18080> 登录。初始管理员账号在
`deploy/compose/storage.env` 的 `PROXY_SENTINEL_ADMIN_USERNAME` /
`PROXY_SENTINEL_ADMIN_PASSWORD`（首次 `up` 随机生成，文件已被 gitignore）。

前端热更新调试走本地 API：

```sh
cd frontend
VITE_ENABLE_MOCKS=false pnpm dev
```

## 数据流与目录

```text
0.30: /opt/proxy-sentinel/data/zeek/logs/current/*.log   (LogAscii::use_json=T，逐行 JSON)
0.30: /var/log/suricata/eve.json                        (Suricata EVE，默认不拉)
0.30: /opt/proxy-sentinel/data/device-signals/ttl.jsonl (packet-sidecar 设备信号，默认不拉)
        | rsync 只读（--append 可对 raw/ 做增量续拉）
        v
data/zeek/<sensor>/raw/        原始镜像，跨次拉取累积
        | 复制，或 zeek_replay.py 按单一全局偏移量平移时间
        v
data/zeek/<sensor>/replay/     ingest 输入，每次 pull 重建
        +-- manifest.json      文件清单、时间范围、平移量、总行数、异常行数
        | 增量镜像（sync）：按远端 inode/偏移量续读，轮转时用 <名>.1 续尾
        v
data/zeek/<sensor>/live/       ingest 输入，持续追加；存在时优先于 replay/
        | proxy-sentinel ingest run --sensor-id <sensor> --zeek-* / --device-signals / --eve
        v
ClickHouse normalized_events（7 天 TTL）+ normalized_event_features
        | risk materialize --once --window=<跨度>   （历史校准，仅快照模式）
        | read-model run --lane realtime|coarse|recognition|identity
        v
PostgreSQL 读模型 / 风险快照 / 运行账本
        v
control-plane serve --sensor-id <sensor> --frontend-dir frontend/dist
```

`raw/` 始终是原始数据；`replay/` 才是 ingest 的输入，因此时间平移不会污染原始镜像。

## 增量镜像（实时模式）

一次性快照的问题是快照会随时间变旧：风险滚动窗口、共享行为物化器都只看 `now` 附近的窗口
（共享行为是 `now-90s` 往前 10 分钟），静态数据几分钟后就落空。增量镜像解决这一点。

工作方式（`pull-zeek-30.sh --live`）：

- 每个文件在 `live/.sync-state.tsv` 记录**远端 inode + 已消费的远端偏移量**，与本地文件大小解耦。
- 远端 inode 未变且变大：`tail -c +<偏移>` 追加增量，本地 inode 保持不变，
  ingest 检查点按 (路径, inode) 只读新增字节。
- 远端 inode 变了（logrotate 改名轮转，例如 Suricata `eve.json`）：先从远端 `<路径>.1`
  补齐旧文件尾部，再把补齐后的本地文件改名为 `<名>.1`。这正好对上 realtime worker 的轮转续读约定
  （`internal/realtime/worker.go` 在文件标识变化时会去找 `<path>.1`），最后拉取新文件。
- 远端变小（copytruncate）：直接重建本地文件，检查点按 `truncated` 从 0 重读。
- 首次可用 `--eve-bytes` / `--ttl-bytes` 只取尾部若干字节播种（`tail -c` 会切开行，
  脚本会丢掉第一行残行），避免为了一个 234MB 的文件先跑几分钟。
- 每次追加后会校验本地新增字节数与远端增量是否一致，不一致就重建，避免静默错位。

配置保存在 `data/run/sync.conf`，`local-up` 与常驻进程复用它；命令行参数优先于保存值。

| 选项 | 说明 |
| --- | --- |
| `--daemon` | 常驻进程运行（pidfile `data/run/sync.pid`，日志 `data/logs/sync.log`） |
| `--interval N` | 常驻间隔秒数，默认 60 |
| `--with-eve` / `--eve-bytes N` | 镜像 Suricata `eve.json`，可只播种尾部 N 字节 |
| `--with-ttl` / `--ttl-bytes N` | 镜像 packet-sidecar `ttl.jsonl`，可只播种尾部 N 字节 |
| `--files "..."` | 覆盖 Zeek 文件清单 |
| `--no-eve` / `--no-ttl` | 关闭对应来源 |

## 命令参考

### scripts/local/pull-zeek-30.sh

| 参数 | 说明 |
| --- | --- |
| `--target USER@HOST` | 远端地址，默认 `root@192.168.0.30` |
| `--remote-dir DIR` | 远端日志目录，默认 `/opt/proxy-sentinel/data/zeek/logs/current` |
| `--source-dir DIR` | 离线模式：从本地目录取文件，不走 SSH（测试与离线回放） |
| `--dest DIR` | 本地目标目录，默认 `<repo>/data/zeek/<sensor-id>` |
| `--sensor-id ID` | 传感器标识，默认 `office-30`，必须与本地栈一致 |
| `--files "a.log b.log"` | 覆盖默认清单 |
| `--with-ttl` | 额外拉 `device-signals/ttl.jsonl`（默认关闭，该文件约 234MB） |
| `--ttl-bytes N` | 拉 TTL 流时只取尾部 N 字节，例如 `50M` |
| `--shift-to-now` | 生成时间平移到"当前"的 `replay/` |
| `--append` | `raw/` 使用 `rsync --append` 增量续拉 |
| `--dry-run` | 只打印将要拉取的文件与字节数 |

默认文件清单：`dhcp software mdns nbns llmnr conn dns http ssl x509 snmp lldp ssdp proxy_transactions`。
不存在的文件与 0 字节文件（例如当前为空的 `proxy_transactions.log`）会记入 manifest 的 `skipped`。

### scripts/local/local-stack.sh

| 子命令 | 说明 |
| --- | --- |
| `doctor` | 自检 Docker、工具、磁盘、端口、0.30 可达性、前端产物 |
| `up` | 生成配置 -> 存储 -> 迁移 -> 统计回填 -> 管理员 -> ingest -> 风险 -> 4 条读模型 lane -> 控制面 |
| `down` | 逆序停止进程并关闭容器，保留 `data/db` |
| `status` | 容器、进程、`/readyz`、事件/风险/运行账本计数 |
| `logs [名]` | 查看 `data/logs/<名>.log`，不带名字则列出全部日志 |
| `sync` | 增量镜像到 `live/`；`--daemon` 常驻，详见上一节 |
| `reset` | 停栈、删除 `data/db`、重新拉起 |
| `purge --yes` | 删除 `data/db`、`data/zeek`、`data/run`、`data/logs` 与运行时配置 |

选项：`--force`（up/reset 无条件重建数据库）、`--sync`（up 前先同步一轮并启动常驻镜像）、
`--frontend-dir DIR`（复用已有前端产物）、`--no-build`（跳过 Go 二进制重建），
以及增量镜像选项（见上一节）。

`live/` 目录存在且非空时，`up` 自动按增量镜像模式运行：ingest 读 `live/`，跳过快照一致性校验，
并在 `data/run/sync.conf` 存在时拉起常驻镜像进程。

## 时间戳策略

30 的 Zeek 日志时间戳是采集时的真实时间，默认**不平移**（faithful 回放）。为保证读模型能覆盖历史数据，
`local-up` 会把 `PROXY_SENTINEL_ACTIVITY_V3_CUTOVER` 设为快照最早事件时间前 1 小时
（`internal/store/activity_v3_read_model.go` 只在首次插入该状态，必须在 realtime lane 首次启动前设置）；
增量镜像模式下数据本身是新鲜的，`risk materialize` 回落到生产的 `10m` 窗口，无需时间平移。

如果快照跨度超过 6 天，或希望页面数据看起来"新鲜"，使用：

```sh
make local-pull PULL_ARGS="--shift-to-now"
```

时间平移使用**单一全局偏移量**（不是逐文件），保留跨文件相对顺序与文件内先后关系。
注意：平移后的时间轴与 0.30 不再对应，跨系统比对必须用未平移的快照。

## 已知约束

1. **7 天 TTL**。`normalized_events` 是 `TTL toDateTime(timestamp) + INTERVAL 7 DAY`
   （`migrations/clickhouse/001_production_schema.sql`），比 7 天更早的事件插入后仍会被删除。
   回放窗口只能取近 7 天。
2. **重新灌库必须 reset**。`normalized_events` 是纯 `MergeTree`，没有按 `event_id` 去重；
   ingest 的检查点按 `(路径, dev, inode)` 记录。因此同一份快照重复 ingest 会产生重复事件。
   `up` 会比对 `replay/manifest.json` 的 sha256 与 `data/run/last-ingest.json`：
   不一致时直接报错，要求先 `reset` 或加 `--force`。
3. **sensor_id 必须一致**。0.30 是 `office-30`，本地 ingest、风险物化、4 条 lane、控制面与页面过滤
   都使用同一个 `PROXY_SENTINEL_SENSOR_ID`，否则页面查不到数据。
4. **风险窗口本地放大**。`risk materialize` 只接受 `10m` / `1h` / `24h` / `7d` 四档
   （`internal/materialize.queryWindow`），且 `--window` 是 Go duration，7 天要写成 `168h`；
   生产 unit 用 `10m`，用它回放历史数据会被 `ExpireRiskSnapshots(now-window-1m)` 立刻清掉。
   `local-up` 因此按快照跨度选取能覆盖整段数据的最大档位
   （≤10 分钟取 `10m`，≤1 小时取 `1h`，≤24 小时取 `24h`，否则取 `168h`）。
   这是对生产语义的有意偏离，只影响本地。
5. **同一时刻只能跑一套栈**。容器名与端口固定，切换检出（例如主检出与 worktree）前先 `local-down`。
6. **统计读模型回填**。空库必须执行 `migrate --backfill-application-read-model`，否则
   `/api/v1/overview` 会返回 `normalized event feature historical backfill is not completed`。
7. **数据合规**。Zeek 日志含 MAC、主机名、SNI、内网 IP；`data/` 已被 gitignore，
   不要把快照、日志或本地口令提交到仓库，也不要复制到受管环境。
8. **读模型开关必须与现场一致**。现场 realtime/coarse 单元带
   `PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3=true`，control-plane 由 systemd drop-in 追加
   `PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3=true` 与 `PROXY_SENTINEL_RECOGNITION_SUMMARY_V1=true`。
   `local-up` 已按同样方式设置；漏掉会让 `/api/v1/overview` 一直返回
   `activity statistics refresh is older than three minutes`（旧的 V2 图表游标不再更新）。
   `local-up` 还会等 `read_model_jobs` 排空后再起控制面，避免读模型追平期间总览不可用。
9. **回放快照会随时间变旧**。V3 健康检查在 worker 无积压且心跳新鲜时按 lag=0 判定，
   因此快照排空后总览可用；但 `collector` 等新鲜度指标会显示 `no_data`/`idle`，
   这是静态快照的正常表现，不是故障。
10. **共享设备档案（设备档案页）需要合格来源，可能长期为空**。
    - 入库闸门：`migrations/postgres/088` 的 `enqueue_shared_device_profile_job` 会丢弃
      `observed_at < shared_device_profile_runtime.cutover_at` 的证据，而 `cutover_at` 默认是迁移执行时刻。
      `local-up` 会在 ingest 之前把它对齐到数据起点（快照模式取最早事件前 1 小时，
      增量镜像模式取 `now-7d`），否则任务永远为 0。
    - 建档条件：`qualifyingSharedProfileSource` 只接受三类来源——路由器评估达到
      `role=router|ap` 且 `status=likely|confirmed` 且非 `brand_reference_only`/非 `ambiguous`（或
      `infrastructure=true`）；`discovery_observation_latest` 中 `device_type` 为
      router/gateway/access_point/switch/network_device 且有 MAC；或
      `shared_behavior_observations` 中 `status=confirmed` 且 `coverage_state=verified` 且
      `strong_anchor` 为 `ieee1905_association`/`coexisting_device_models` 且设备数下界 ≥ 2。
    - 现实情况：30 的 Zeek 只加载 `local-device-signals.zeek`、`software.zeek`、
      `proxy-transactions.zeek`，没有 `lldp.log`/`ssdp.log`，因此回放数据通常只能得到
      `role=unknown`、`status=candidate`、`brand_reference_only=true` 的路由器候选；
      TTL/UA 只能给弱线索（`internal/evidence/router.go` 明确"不从 TTL/UA 单独建立路由器记录"），
      所以单独补 `--with-ttl` 也不足以建档。discovery worker 需要现场 LAN，本地拿不到。
    - 第三条来源（共享行为）具备**实时前提**：物化器只看 `now-90s` 往前 10 分钟的窗口，
      覆盖门还要求 `device-signals` 检查点存在、`suricata` 或 `zeek-http` 检查点新鲜
      （`last_event_at` 距窗口结束 90 秒内、`updated_at` 2 分钟内）。因此静态快照必然不满足；
      用增量镜像 + `--with-eve` + `--with-ttl` 让检查点保持新鲜，才有机会产生共享行为观察。
      30 的 `http.log` 自 10-09 起没有新增，所以覆盖门实际依赖 Suricata EVE 那一路。
    - **实测结论**：用 `sync --with-eve --eve-bytes 5M --with-ttl --ttl-bytes 5M` + 增量镜像后，
      覆盖门变为 `coverage_verified: true`、`coverage_blockers: []`；设备档案从 0 变成有数据
      （网关与交换机，来源是 `router-rules` 认定）。同一批数据在**一次性快照**模式下只有
      `role=unknown` 的路由器候选，因此设备档案要出数据必须走增量镜像并补 EVE/TTL。
      共享行为观察仍可能为 0：夜间园区没有出现"同一出口多机型并存"这类窗口就不建观察，这是正常结果。
    - 参考：30 当前迁移账本停在 `086_ncu_identity_router_bindings.sql`，**并未部署**共享设备档案
      （088–090 来自本分支的 `ff5b184`/`3bf0842`），所以现场也没有可比对的档案数据。

## 验收

离线自动化：

```sh
make local-test
```

端到端（需要真实拉取）：

1. `make local-doctor` 通过，`0.30 SSH` 显示可达。
2. `make local-pull` 输出的 `异常行=0`，`replay/manifest.json` 文件数与行数合理。
3. `make local-up` 后 `/readyz` 返回 200。
4. `make local-status` 中 `normalized_events` 大于 0，`risk_snapshots` 大于 0。
5. 登录后检查 `/api/v1/overview`、`/api/v1/events`、`/api/v1/activity/overview`、
   `/api/v1/dpi/overview`、设备相关页面有 office-30 的数据。
6. 对 0.30 无副作用：拉取前后 `data/zeek/logs/current` 只增不减，`proxy-sentinel*` 服务状态不变。

## 回滚

```sh
make local-down                       # 停本地栈
./scripts/local/local-stack.sh purge --yes   # 删本地数据库、快照与配置
```

代码层面直接丢弃本分支或 worktree 即可；本流程不触碰 0.30 与现场 184。

## 常见故障

| 现象 | 处理 |
| --- | --- |
| `Docker 守护进程不可用` | `open -a OrbStack` 后重试 |
| `本地库已有 N 条事件，但回放快照已变化` | `make local-reset`，或 `local-up LOCAL_ARGS=--force` |
| 端口被占 | 另一套检出还在跑，先在其目录执行 `make local-down` |
| `未发现回放快照，跳过 ingest` | 先执行 `make local-pull`，再 `make local-up` |
| 总览接口返回非 200 | 读模型仍在构建，稍后 `make local-status` 复查；必要时 `make local-logs LOG=lane-realtime` |
| 快照跨度超过 6 天 | 加 `PULL_ARGS="--shift-to-now"` 重新拉取 |
| 设备档案页一直空 / 显示"正在建立新的设备档案" | 见约束 10：先确认 `shared_device_profile_jobs` 有行（`local-up` 已对齐闸门），再确认是否存在合格来源；只用 Zeek 设备信号通常无法建档，需要增量镜像 + `--with-eve` + `--with-ttl` |
| 机器负载飙高、docker 命令卡住 | 全量快照 + 5 天读模型回填会吃满 7GB VM；提高 OrbStack 内存，或先用 `--files` 只拉最近需要的那几类日志 |
| `已有增量镜像在运行，本轮跳过` | 常驻镜像与手动 `sync` 互斥（并发追加会写坏文件），等这一轮结束再执行 |
| `清理陈旧的增量镜像锁` | 上一轮异常退出，脚本已自动接管；若反复出现检查 `data/logs/sync.log` |
| 增量镜像文件疑似错位 | 删掉 `data/zeek/<sensor>/live/` 整个目录重新 `sync`，再 `reset` 重建数据库（本地 inode 变化会让 ingest 从头重读同一批数据，不 reset 会产生重复事件） |
