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
