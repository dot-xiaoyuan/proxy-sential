# 设备信号上报：只在状态变化时记录（2026-10-14 实测与设计）

本文记录 184 现场"设备/控制信号无节制重复上报"的量化结果、已实施的取舍机制与实测数据。
结论均来自现场只读查询与逐项验证。

## 一、问题量化

`identity_signal_events_v1`（184，sensor `ncu-184-router-pilot`）：

| 指标 | 实测 |
|---|---|
| 一天 device 事件数 | **66,795,351** |
| 一天不同的 `(mac,ip)` 状态数 | **309,974** |
| **冗余倍数** | **215.5 次/状态** |
| 事件最多的 MAC | `00:74:9c:26:98:61`：**17,482,926 条/天**（202 条/秒） |
| 次多 | `c4:07:78:08:20:02`：**15,380,709 条/天**（178 条/秒） |
| 第三名 | 57,387 条/天（0.66 条/秒） |

**两个 MAC 就占了全部 device 事件的 49%**，量并不来自"很多设备慢慢上报"，而来自极少数设备
被反复重写。

## 二、根因：每 bucket 原样重写 + 控制信号每帧一条

采集端（`internal/devicesignal`）每 `--bucket 30s`：

1. **packet 路径**：把每个 `(IP, MAC, 方向, scope, 版本, TTL, TCP栈)` key 原样写出，
   只有时间戳与 `observed_count` 变化。`observed_count` 在 Go 代码里**从未被任何消费者读取**
   （全仓 grep 只有写入点）——即这些字段组合本身零信息量。
2. **control 路径**（真正的量）：`controlSignal.key()` 把**整个 payload 的 JSON** 作为键，
   且 `event_id` 由 `(sensor, kind, ip, mac, key, bucket)` 派生，因此每帧都是新事件、
   无法按 id 去重。现场抽样（400 KB，约一个 bucket）：

   - 470 条记录中 **469 条是 `ssdp`**；
   - 同一 IP `192.168.1.1` 在**同一个 bucket 内**就有 **144 个不同 payload**；
   - 其中 `usn` 一个字段 **140 个不同取值**（另有 `nt` 38、`server` 14、`location` 3、`vlan` 12）
     ——即网关在代播 LAN 内大量设备的服务发现通告，**每个服务每 30 秒被重复播报一次**。

`vlan` 与 `usn` 都不是量的乘数：去掉 `vlan` 后身份基数 2,563 → 2,555（1.0×），
再去掉 `usn` → 2,546。重复最多的身份是 **ARP 请求**
（payload 恒为 `{"message":"request","origin":"arp"}`，同一 IP 出现 195 次），
按 `(kind, ip, mac)` 属于不同请求者——它们本质是**设备存活心跳**。

## 三、设计：变化即时上报 + 低频存活重写

`internal/devicesignal/state_change.go` 新增 `stateChangeTracker[K comparable]`（跨 bucket）：

- **首次出现的 key 立即写出**——新的 IP/MAC 绑定、新服务、新 TTL/TCP 组合都是真实变化；
- **持续存在的 key 只在存活间隔内重写一次**（默认 5 分钟），并携带折叠后的计数；
- **超过宽限期未再出现的 key 被遗忘**，之后再次出现算作变化重新上报；
- 跨 bucket 工作集有上限（200,000），超限计入 `dropped`；
- 停机时把当前持有的状态落盘，避免丢最后状态。

同一套规则同时作用于 packet 与 control 两条路径。命令行参数
`--state-liveness`（默认 `5m`；`0` 表示保持旧的"每 bucket 全量写出"行为）。

测试：`state_change_test.go` 覆盖首次写出、未变化不重复、存活间隔重写与计数、
超宽限期重现算变化、静默一个 bucket 不算新、工作集上限，以及
`selectControls` 的新服务立即写 / 重复播报被抑制 / 新增服务不被抑制。

## 四、实测效果（184，采集端已开启）

| 配置 | 稳定产出 | 相对改动前 |
|---|---|---|
| 改动前 | 503 KiB/s（30 秒 15,093,706 B） | 1× |
| change-only，存活 **5m**（代码默认，现场采用） | **100–140 KiB/s** | **约 4–5×** |
| change-only，存活 **30m** | **65 KiB/s** | **约 7.7×** |

同期的整体健康（采集端开启、存活 5m）：`/readyz=200`、ingest 19 批/5 分钟 **0 失败**、
`queue full = 0`、死锁 **0**、设备清单投影积压继续下降（59.7k → **54.2k**，
消费约 300/分钟），`ncu-auth-redis` 身份滞后 0。

**注意冷启动**：重启后 tracker 是空的，第一个 bucket 会把当前活跃身份全部当作新 key 写出，
因此调整存活间隔后必须等这个冲击过去再测稳态（30m 首次测量因此一度显示 358 KiB/s）。

## 五、存活间隔是取舍旋钮

存活间隔直接决定设备中心 `last_seen` 的粒度：

- `5m`：设备"在线"最多显示为 5 分钟前——对运行人员是正常量级；
- `30m`：再省 2.2 倍写入，但 20 分钟前活跃的设备看起来像陈旧。

现场采用代码默认的 **5m**；若要更低写入量，把该参数调到 `30m` 即可，无需改代码。

## 六、仍需处理

1. 其余模块同理核查：进度快照/读模型等是否也存在"只有时间戳变化"的记录
   （`identity_ip_mac_history` 每事件一行、`normalized_event_ids_v1/v2` 等会随事件量同比下降）。
2. 身份物化器仍在追赶 `ncu-184-router-pilot` 约 25 小时的历史积压
   （已查明其中 **100% 是 device 事件**、且设备状态早已由实时路径写到前沿，属冗余重算）。
3. `--bucket` 是否仍需从 30s 放宽，取决于存活间隔确定后的实际速率与磁盘余量。

## 七、"其他模块同理"的审计结果（2026-10-14，第 2 轮）

### 端到端效果（第一轮改动之后）

ClickHouse `normalized_events` 近 10 分钟新增 **130,493 行**（约 18.8M/天），
而改动前仅 device 事件就是 **66.8M/天**。各物化视图目标表同步下降（同一扇出量）。

### PG 逐表写入速率（60 秒增量）

| 表 | 速率 | 判定 |
|---|---|---|
| `endpoint_inventory_projection_deltas` | ins 135.7/s + del 357.1/s | **变更队列**：每个真实变更一行，消费后按 `delta_id` 删除；删除快于插入是在消化积压。语义必要 |
| `endpoint_inventory_contributions` | ins 203.6/s | 投影事实，随真实变更写 |
| `endpoint_inventory_projection_jobs` | upd 156.7/s | 触发器逐次 `dirty_generation+1` |
| `identity_current_addresses` | del 89.1/s（ins 0） | **代际清理**（`identity_calibration.go:260` 删除被取代的 generation）。因 `ncu-identity-sync` 已停、无新快照插入，表现为只删不增，属有限排空 |
| `endpoint_entities` | upd 76.1/s | 已有 no-op 守卫 |
| `identity_ip_mac_history` | ins 34.7/s | 已有 no-op 守卫 |

**关于 `dirty_generation+1` 不能简单合并**：消费端的完成判定
（`inventory_projection.go:365`）是"该 endpoint 是否还有剩余差分行或到期计时器"，
看起来生成号只是脏标志；但**生成号单调递增正是"处理期间又到达变更"的竞态保护**——
若在处理期间到达的变更不 +1，worker 可能先提交"已处理"，随后差分行残留而无人消费。
要安全合并必须引入显式的加锁协议，本轮**不做**这个改动。

### 真正的"只有时间戳变化"：lane 心跳

`read_model_runtime_state` 现场实测 **249 次更新/分钟（4.15 次/秒）**，且每次都是独立
autocommit（本机约 230 ms 的 WAL fsync），等于持续付磁盘税。按 lane 看：
`endpoint-recognition` 每 2 秒、`activity-v3-realtime-health` 每 5 秒、
`activity-v3-dispatch` 每 6 秒各写一次。

最纯粹的一例在 `activity_v3_read_model.go`：ClickHouse 脏日志**没有行**时（大多数周期）
执行 `UPDATE read_model_runtime_state SET updated_at=now() WHERE name=$1`——
这条语句唯一的效果就是改时间戳。

修复沿用代码库已有写法（`shared_device_profile_runtime` 的
`AND updated_at<now()-interval`）：给上述四个心跳（含 `shared-behavior`）加
`AND updated_at < now() - interval '10 seconds'`。其中 activity-v3 的 as_of 水位是
monotonic（`GREATEST` 取最大），抑制中间写入不丢信息。

**实测：心跳写入 249/分钟 → 36/分钟（约 7× 减少）**，各 lane 心跳仍保持 0–7 秒新鲜；
同期 `/readyz=200`、死锁 0、`queue full` 0、投影积压继续下降（53,705 → 53,444）。

### 结论

"只有时间戳变化"的记录已经清掉了两处最大的来源：**采集端的重复上报**（第一轮，
device 事件量降约 4–5×）与**lane 心跳的每周期时间戳更新**（本轮，约 7×）。
剩余的高频写入（差分队列表、投影事实、脏标记计数、代际清理）都对应真实变更或有限排空，
不属于该模式；其中脏标记计数的合并需要先设计加锁协议，留待后续单独评估。

## 八、ClickHouse 图表事实表的重复 revision（2026-10-14，第 3 轮）

`activity_chart_facts_5m_v3` 是 ClickHouse 里行数最多的表（**1.38 GiB / 1.389 亿行**），
现场实测其重复程度：

| 年龄段 | 每个 bucket 的平均 revision 数 |
|---|---|
| 2 天前（已关闭很久） | **20–29** |
| 昨天 | 23–30 |
| 近 2 小时（改动前） | 6–8 |

结构原因：该表是 **带 `revision` 的 MergeTree**（不是 Replacing），写入形如
`INSERT INTO activity_chart_facts_5m_v3 SELECT … toUInt64(<全局递增值>) …`，
每个 5 分钟 bucket 每重算一次就**追加一份完整副本**；读路径按
`activity_chart_bucket_versions_v3` 里发布的那个 revision 取数，因此**旧 revision 对读取
毫无用处**，只能等 `TTL 8 天` 清掉。

### 已实施（安全、效果有限）

把"进行中 bucket"的重算去抖由 30 秒放宽到 `openBucketRebuildDelay = 2 分钟`
（`internal/store/activity_v3_read_model.go`）。这只是延迟重算——构建始终读取全部可用数据，
不影响正确性；代价是当前那根柱子的刷新粒度从 ≤30 秒变为 ≤2 分钟。

实测（发布 `2026.10.14-chart-debounce1`）：近 10 分钟新建 bucket 平均 4 个 revision、
近 25 分钟 5.5 个、近 2 小时 6.1 个。改善有限，因为**桶关闭后的迟到重建占了大头**。

### 记录一个不能用的改法（重要）

用"已发布版本的 `source_as_of` ≥ 脏收据 `written_at`"直接跳过重算，看似能一次砍掉大部分
重复，但 **`source_as_of` 写入的是发布时间（`now64(9)`）**，而构建的读取发生在发布之前。
若构建读取之后、发布之前又到达变更，该判据会错误地判定"已覆盖"并跳过，**导致漏更新**。

要安全使用，必须让写入端记录**构建真正的源水位**（读取上界），再以它作为判据；
在此之前不要采用任何基于 `source_as_of >= written_at` 的跳过逻辑。

### 下一轮可做

1. 在 `publishActivityV3Version` 记录构建的读取上界（而非 `now()`），并据此跳过已覆盖的重算；
   落地后需验证：跳过条数、bucket 的 revision 数应降到 1–2，且图表不出现缺柱。
2. `activity_chart_facts_5m_v3` 换成 `ReplacingMergeTree(revision)` 并调整 `ORDER BY`
   （去掉 key 里的 revision），让后台合并自动回收被取代的副本；这需要一次
   1.38 GiB 的重建 + 换名切换，且要先确认读路径不依赖 key 中的 revision。

## 九、用真实读取水位跳过已覆盖的图表重算（2026-10-14，第 4 轮）

第 3 轮发现 `source_as_of` 写的是发布时间，无法证明覆盖，因此没敢用它跳过重算。本轮把它改对：

- `publishActivityV3Version` 新增 `sourceAsOf` 参数；5 分钟构建与小时汇总在**发起源表读取之前**
  捕获 `time.Now().UTC()` 作为"构建开始读取的时刻"——写入早于该时刻的脏收据必然被读到；
- 现场确认 `source_as_of` 在 Go 代码里**没有任何读取方**（读路径用 `argMax(revision,published_at)`），
  所以改变其语义对读取零影响；
- 派发阶段把脏日志按 `(window_start,sensor,campus)` 折叠后 `LEFT JOIN` 每个 key 的最新版本，
  若 `source_as_of >= written_at + 5 秒`（余量覆盖"源行可见"与"收据时间戳"之间的间隙），
  则**只推进游标、不建任务**。游标取自结果集最后一行，跳过不会让它卡住；桶关闭后的最终发布
  走 `read_model_jobs` 自身的 `dirty_generation/not_before`，不依赖派发，因此不受影响。

### 现场预验证与实测

- 部署前用真库验证新查询语法，并用**旧语义**（发布时间）算出今天 358 个脏 bucket 中 357 个"已覆盖"
  ——这正是需要修正的假阳性方向；换新语义后同一判据立刻回到诚实水平（9 覆盖 / 2 未覆盖）；
- 写入：`activity_chart_facts_5m_v3` 10 分钟写入 **183,042 → 105,589 行（−42%）**，源事件量相当；
- 每个 bucket 的 revision 数：**5.8–6.1 → 3.8**（改动后新建、已走完生命周期的 bucket）；
- 图表任务待处理从堆积降到 **2**；`/readyz=200`、死锁 0。

### 仍然存在

若要在“桶关闭后不再重算”这件事上更彻底，还需要处理两处：
1. **迟到的重建**仍会产生新 revision（每次 1 份完整副本）。彻底解法是把表换成
   `ReplacingMergeTree(revision)` 并调整 `ORDER BY`（去掉 key 中的 revision），
   让后台合并自动回收被取代的副本；需一次 1.38 GiB 重建，且要先确认读路径不依赖 key 中的 revision。
2. 上表 `TTL 8 天`：被取代的副本在此之前一直占空间（当前 1.38 GiB 中大部分是旧 revision）。

## 十、打开 zeek 的容量实测（2026-10-14，第 5 轮）

按授权打开 zeek 集群做承压观察（`systemctl start proxy-sentinel-zeek-cluster`，4 个 worker
分别抓 `enp8s0f0`–`f3`，`CPUQuota=400%`、`MemoryMax=6G`；上次它是崩溃退出，本次启动正常）。

### zeek 自身很轻

| 指标 | 实测 |
|---|---|
| CPU | **0.7–0.8%/进程**（14 个 zeek 进程） |
| `dhcp.log` 产出 | **36 KB/分钟**（device-signal 为 100–157 KB/**秒**，约 0.5%） |
| 日志目录增长 | 不显著（336 MB，磁盘余量 472 GB） |

### 但分析侧刚好越界

| 配置 | domain 队列丢弃 | 投影积压 |
|---|---|---|
| zeek 关闭 | **0** | 持续下降 |
| zeek 开启 + 设备信号存活 5m | **2.6–7.7 批/分钟** | 仍下降（3 次采样 55,486 → 55,241） |
| zeek 开启 + 设备信号存活 15m | **6.3 批/分钟**（未改善） | 55,660（一度上行） |

丢弃是 `enqueueDomainEvents` 的非阻塞发送在队列满时的**设计行为**，日志写明
"durable events will be reconciled"——由身份物化器对账补偿，**不是数据丢失**。
把设备信号存活间隔放宽到 15m 并**没有**可靠地降低丢弃（怀疑受冷启动突发影响），
因此**回退到代码默认 5m**，不保留未经验证的配置。

### 结论与建议

- 系统在 zeek 开启下仍然健康：`/readyz=200`、ingest 批次 **0 失败**、**死锁 0**、
  内存/磁盘在限内；投影积压仍在下降（消费 207–249/分钟）。
- 限速环节是**分析侧（domain 队列消费）**，不是采集、CPU、内存或 zeek 本身。
- 若要做到"开 zeek 且零丢弃"，下一步应提高分析侧吞吐（domain worker）或进一步降低
  设备信号量；这两项都需要单独测量，本文件上一节已给出存活间隔与产出量的对应关系
  （5m ≈ 100–157 KiB/s、15m ≈ 68 KiB/s、30m ≈ 65 KiB/s）。

## 十一、提高 domain 队列消费并发：负结果（2026-10-14，第 6 轮）

第 5 轮把"开 zeek 后出现丢弃"归因到分析侧容量不足，本轮直接验证那是否等于"消费者不够"。

### 实验：把 domain 消费者从 1 提到 3

`StartDomainRecognition` 按 `domainWorkerCount()`（环境变量 `PROXY_SENTINEL_DOMAIN_WORKERS`，
默认 1）启动 N 个消费者共享容量 32 的队列；维护任务只跑一份。设为 3 后：

| 指标 | 1 消费者 | 3 消费者 |
|---|---|---|
| `queue full`（丢弃） | 2.6–7.7 批/分钟 | **0** |
| `domain recognition failed` | ~0–4/分钟 | **~4/分钟（未降）** |
| `domain batch timing > 20s` | 5 次/3 分钟 | **19 次/3 分钟** |
| 投影积压趋势 | 下降 | **上行**（55,561 → 55,748） |

也就是说：**丢弃只是被换成了失败**。3 消费者下每个批次的总耗时达 32–33 秒（而 identity 相位
只有 0.4–0.7 秒），说明多个消费者在**全局身份写锁**上排队，等待超时后报
`domain recognition failed` 并靠对账重试——锁定段并没有变快。这与早期"4 个 domain worker
不解决问题"的负结果一致，只是现在有了更清晰的解释。

**已回退**到默认 1 消费者；回退后投影积压恢复下降（55,543 → 55,476 → 55,444），
>20 秒批次从 19 降到 5。

### 同时更正第 5 轮的归因

回退后 zeek 仍然开启，`queue full` 在若干 3 分钟窗口内为 **0**，积压在下降。逐分钟统计丢弃
分布后可见它是**突发**的（例如 02:25–02:33 连续每分钟 5–10 次，之后数分钟为 0，02:46–02:48
又是 2–7 次），与 zeek 的产出（534 B/s，占 device-signal 的 0.5%）不匹配，也不是严格的
5 分钟周期。因此：**第 5 轮把丢弃归因给 zeek 是不成立的**；它更可能与"重启后的冷启动突发"
（tracker 变冷 → 把当前活跃身份全部当新 key 写出）以及周期性存活重发叠加有关。

### 下一步（两项都已定位到具体改法）

1. **给存活重发加抖动**：目前同一存活间隔到期的 key 会在同一个 bucket 一起重发，
   形成可预测的尖峰。按 key 分配一个固定的偏移（例如阈值取 0.7–1.0 倍存活间隔轮转）
   即可把尖峰摊平，平均量还略降，且 `--state-liveness` 仍是新鲜度上界。
2. **把 tracker 状态跨重启持久化**：现在每次重启都会把当前活跃身份全部当新 key 重发一次，
   这本身就是"重启触发的重复上报"。持久化一份紧凑状态即可消除该突发。
