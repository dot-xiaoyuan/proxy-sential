# 184 设备发现协议分批补开计划

本文是用户授权后的执行计划，不是已完成记录。目标仅为 `root@222.204.3.184`、`/opt/proxy-sentinel`；每次执行前重新只读核对版本、服务参数、配置路径和恢复阶段。恢复任务及本轮现场变更另记在对应发布记录中，不根据本文推定现场状态。

## 进入条件与顺序

先完成既有 `consume-one`、`consume-two`，再恢复原有 DNS-SD、SSDP、WS-Discovery 与 DHCP 输入，完成原定连续两小时 `passive` 观察。检查 `/tmp/discovery-recovery-20261024/stage.json` 和关联观察文件的实际结果，不能用时间已过去或 HTTP ready 代替通过。既有阶段被重启、中断或发现异常时，按恢复记录处理并重新累计有效观察窗口。

随后按以下顺序推进，每批至少连续观察 30 分钟，满足本文门槛才进入下一批。30 分钟只验证该批短期运行，不能据此承诺持续容量或全部积压清理完成。ARP、NDP 是否纳入取决于输入预估和实际净消化，不能为执行完列表而强行开启。

| 批次参数 | 配置增量 | 入口和收益 | 特别核对 |
|---|---|---|---|
| `names` | `nbns=true`、`llmnr=true` | discovery-worker 被动解析 UDP 137/5355 应答，补充设备名称 | 查询不生成设备名称；应答中地址归属不等同于报文发送者 |
| `neighbors` | `lldp=true`、`cdp=true` | discovery-worker 被动邻居公告，补充管理地址、邻居和端口线索 | CDP 接收/解析计数存在下述归类限制；不把邻居公告当用户终端地址绑定 |
| `arp` | `arp=true` | discovery-worker 地址关系，先预估全网广播输入 | 独立一批；请求只作线索，不把目标地址当发送者绑定 |
| `ndp` | `ndp=true` | discovery-worker IPv6 邻居关系 | 独立一批；检查 IPv6 镜像范围、合法 NA 和链路本地地址域 |

其他协议不随上述批次自动开启。DHCP 开关和输入修复由原恢复流程处理；本工具不改变它。每批只启用新增项，不改变 `allowed_cidrs`、site/domain/interface、event bindings、主动任务、富化、规则或历史队列。

## 原恢复阶段的 DHCP V2 补充条件

只启动 `proxy-sentinel-passive-discovery.service` 不足以恢复当前 V2 设备发现的 DHCP。该独立程序通过 `PROXY_SENTINEL_PASSIVE_DISCOVERY_DHCP_ONLY=true` 限定 ClickHouse 响应流，只写旧 `discovery_observations` 和关联记录；它不读 collection、不向 `discovery_batch_work` 入队。命令行没有 `--dhcp-only` 参数。

V2 的 DHCP 任务由现有文件 ingest 在 `StageDiscoveryBatch` 中产生。该路径每批重新读取 `PROXY_SENTINEL_DISCOVERY_CONFIG`，`dhcp.enabled=false` 会被 `IngestOwns` 排除。因此原恢复输入阶段，在二进制能力、真实作用域和采集修复确认后，还必须同步把同一 collection 中的 `{"protocol":"dhcp","source":"zeek","enabled":true}` 启用。不要等到 names 批次才处理这个前置条件，不要把旧 DHCP consumer 的 active/计数增加描述成 V2 已恢复。

### 保留 DHCP 的真实 domain

本轮只读检查确认 Zeek 四个接口 `enp8s0f0` 至 `enp8s0f3` 都是 `bond0` 的 slave。DHCP capture scope 的 `access_domain` 为 `bond0-router-minimal-overnight`，发现 worker 的 domain 为 `bond0-passive-pilot`。这两种域不可仅因都挂在 bond0 上就自动合并。可为 DHCP 添加保留原 domain 的受控 event binding，interface 显式为 `bond0`；site 必须与原 `campus_id`/既有 subject.site 一致。

以下是**合成回放使用的字段增量示例**，不是可直接部署的完整 collection；示例 `valid_from` 不得直接用于现场。现场须确认 `site=ncu`、sensor 和 capture scope 的有效期/collector instance，再填写实际受控绑定生效时间（不早于已核实采集范围的生效时间）。保留现有所有协议与其他 bindings，不能用这段 JSON 整体覆盖配置：

```json
{
  "protocols": [
    {"protocol": "dhcp", "source": "zeek", "enabled": true}
  ],
  "event_bindings": [
    {
      "source": "zeek",
      "protocol": "dhcp",
      "sensor_id": "ncu-184-router-pilot",
      "site": "ncu",
      "domain": "bond0-router-minimal-overnight",
      "interface": "bond0",
      "valid_from": "2026-10-24T08:59:00+08:00"
    }
  ]
}
```

对实际新 DHCP 标准事件逐项核对：

- `Source=zeek`、`SourceEventType=dhcp`、`observer.sensor_id` 必须匹配 binding；`collector_instance_id` 匹配有效 capture scope，`capture_scope_issue` 不应存在。匹配不到的 binding 不会自动拒绝事件，不能只以 selected 数量判断归属正确。
- `subject.campus_id`/site 与 `ncu` 一致，`payload.access_domain`/subject.domain 保持 `bond0-router-minimal-overnight`，时间处于 capture scope 有效期且不早于 binding.valid_from。存在已有非空 site/domain 冲突时直接拒绝；不能用 binding 覆盖为 `bond0-passive-pilot`。
- 最终选入任务的事件必须有 `subject.site=ncu`、原 domain、`observer.interface=bond0`、`observer.discovery_scope_version=1` 与 `raw_ref.source_event_hash`。无 binding 也可能被 SelectEvents 选入，但 interface/绑定标记缺失，这不算完整恢复。
- DHCP ACK/REPLY、释放/撤销等语义由适配层处理；纯 DISCOVER/REQUEST 不作为地址绑定，跨捕获域的 DHCP 聚合冲突不得被绑定掩盖。地址与 VLAN 保持原证据，地址须处于当前允许 CIDR。
- V2 状态 key 包含 sensor、site、domain、VLAN、interface 和地址；因此这组 DHCP 事实会留在原域，不会自动与 `bond0-passive-pilot` 的同 IP 设备合并。两域并存不是可直接去重的重复资产，后续跨域关系需要独立证据。

只对新有效范围开启，不回拨 ingest checkpoint、不重置旧 DHCP 游标、不改变历史原文。绑定生效前的标准事件仍保留于原库；是否补入 V2 属于后续有审计的历史恢复，不冒充当前实时覆盖。

### 核对保留的 ingest 二进制

此次 Zeek 脚本更新保留了原 `proxy-sentinel`，不能仅根据 current 目录名或新 Zeek 脚本判断 ingest 具有 V2 能力。

1. 从实际 ingest MainPID 的 `/proc/<pid>/exe` 确认可执行文件和 SHA256，对照受信发布清单/源码记录；`go version -m` 可辅助确认构建来源。主控制面与 ingest 可能共用文件，不能为验证而整体替换保留了现场补丁的程序。
2. 对复制出的准确二进制可用 `go tool nm` 查 `internal/store.(*DBStore).StageDiscoveryBatch` 及相关发现选择逻辑。去符号构建可能查不到，单独发现字符串/符号只证明代码存在，不证明调用链或运行配置生效；不能因此直接判通过。
3. 核对 ingest 进程实际环境中 `PROXY_SENTINEL_DISCOVERY_V2=true`、collection 路径和 `--zeek-dhcp` 订阅，并只输出所需非敏感键。如果有该精确版本此前运行留下的近期 `zeek-dhcp` ledger 与同 batch_id 的 `discovery_batch_work`，可作实际 staging 证据；没有记录时只读检查不能宣称已经完成端到端验收。
4. 在本轮 DHCP 脚本修复发布且恢复阶段允许输入后，应用已核验的 DHCP 开关/binding，使用真实到达的少量事件逐条核对：`ingest_batches.source_kind=zeek-dhcp`、ledger committed、同 batch_id 的 V2 task、上节 scope 字段、成功回执、`discovery_service_facts_v2.protocol=dhcp`、状态查询和首次入库至可见延迟。仅旧 `discovery_observations` 增加不算通过。没有流量则保持“等待样本”，不现场造数。
5. V2 staged task 保留原 ingest batch/source_kind。正常 `zeek-dhcp` 任务不走 `source_kind=discovery-v2` 才会调用的 normalized archive 写入路径；独立 DHCP consumer 也不写标准事件。仍应对样本检查 event_id 原始记录、派生发现证据和回执，不能把不同表的记录数相加成重复输入，也不能脱离实际 source_kind 推断必然双写。

本地 `scripts/zeek/dhcp_binding_replay_test.go` 已覆盖同域绑定成功、原文不变、关闭/冲突域/冲突站点/生效前/聚合冲突/错误来源/纯请求/越界地址拒绝，并验证无 binding 或 sensor 不匹配会缺失 interface 和绑定标记。这只是合成选择回放，不证明保留的现场二进制已按新配置入队。

## 同一 owner 与日志边界

上述六类协议由 discovery-worker 直接读镜像、解码为标准事件，经持久 spool 进入发现队列。`collection-config` 中 owner 必须保持 `discovery-worker`；`CollectionConfig.IngestOwns` 只接受 owner 为 Zeek 的协议，不把 legacy device-signals 再导入发现链路。

DNS-SD 已由 discovery-worker 负责，不能再新增 `--zeek-mdns` 作为设备发现入口。NBNS/LLMNR 同理，不新增 `--zeek-nbns`、`--zeek-llmnr`。重复接入仍会增加原始日志、标准事件存储和其他旧消费链路成本，不能以 owner 拒绝或事件幂等为理由允许重复生产。

本轮初次只读检查发现 Zeek 8.0.9 的生效脚本和 BPF 为 DHCP UDP 67/68 范围，未加载 `high-load-local.zeek`；conn.log 会产生，但最终 ingest 未订阅。这个事实必须在具体变更前复核。补开上述 discovery-worker 协议不需要扩大 Zeek BPF，不需要打开普通 conn/DNS/HTTP/SSL/X509/software 全网日志，也不需要加载高负载策略文件。

- `software.log` 属于泛软件观测，不是当前发现 collection 的协议 owner；增加它不能替代明确的设备证据链路。DHCP 已可提供厂商和主机名信息。
- 普通 HTTP/SSL 日志覆盖一般浏览、业务流量，扩大到全网会增加协议解析、日志、串行 ingest 轮询及标准事件存储成本；普通 HTTP 响应归属也不能直接当作请求端设备型号。
- 专用 IoT 日志只有候选范围内的响应元数据，TLS 当前只提取版本信息；不能把打开普通 SSL 日志宣传成新增可靠设备识别能力。
- SSH/SMB/NTLM/SIP/RDP 等没有当前 Zeek ingest 输入，单开日志不构成完整交付。

## 生成可审查配置

先从生效 `--collection-config` 或 `PROXY_SENTINEL_DISCOVERY_CONFIG` 确认配置路径，取得本轮只读副本。不要将 runtime.env、数据库口令或完整环境变量打印到日志。以下命令只在本地写候选文件，没有 SSH、服务管理或部署能力：

```bash
python3 scripts/zeek/collection_enable_plan.py prepare \
  --config /absolute/path/current-collection.json \
  --batch names \
  --output-dir /absolute/path/new-names-plan
```

后续依次使用 `--batch neighbors`、`--batch arp`、`--batch ndp`。每批重新导出当时生效配置，不以第一批旧副本生成后续候选。工具要求输出目录尚不存在，只更改该批协议的 `enabled` 字段，保留其他 JSON 数据，包括未知扩展字段；缺失协议、重复协议、错误 owner、非布尔开关会拒绝。

输出包括：

- `rollback.json`：原配置的精确字节副本，权限 0600。
- `candidate.json`：仅该批开关改变，权限 0600。
- `plan.json`：原配置和候选 SHA256、改动协议、最短观察时长；`applied=false`。

再用实际 Go 配置加载器只读校验完整候选（也校验 event bindings），不启动服务：

```bash
go run ./scripts/zeek/validate-collection /absolute/path/new-names-plan/candidate.json
```

现场应用前后执行：

1. 保存本轮唯一变更目录中的原 collection、实际 unit/drop-in、服务活动/启用状态、实际命令行、配置和脚本校验值。该受限配置记录不等于数据库备份；仍不做默认全库备份。
2. 确认现场原配置 SHA256 与 `plan.json.rollback_sha256` 一致，差异仅是该批新增开关。若期间其他线程更新配置，废弃候选并重新生成，不覆盖它的变更。
3. 用现有应用的 `LoadCollectionConfig` 校验候选，核对所有已启用协议 owner 与作用域；确认镜像 VLAN 条件满足下文限制。保留原三协议、已恢复 DHCP 及只读运行约束。
4. 将候选原子替换到已核实的 collection 路径，保留原文件权限/属主；只重启实际读取该配置的 discovery-worker。不要调用会按 enabled 状态启动其他消费者的快捷更新命令，不改 Zeek、ingest、DHCP 服务参数。
5. 检查实际进程配置和新运行代次，等待一轮新心跳。为该批创建全新只读观察文件，每五秒记录；旧样本不覆盖。核验新协议有接收、解析、合法入队、归档、处理回执和查询结果，零流量时明确写“没有观测样本”，不能算覆盖验收。
6. 完成 30 分钟观察并评估后，把本批状态、开始/结束时间、原/新配置哈希、观察文件和结论记录到该批 stage 文件。仅通过后推进下一批。

现有恢复 HTTP 指标字段未部署时，应继续用受控环境加载凭据后执行 `current/bin/discovery-recovery --status` 和既有 CLI 观察器；不能用缺少 pipeline 字段的旧 coverage 页面替代。`scripts/benchmark/discovery-recovery-observe.py --phase passive` 的正式门槛是两小时及四个 15 分钟窗口，不能把其 `--smoke` 结果当作新增批次验收；新增批次按下一节检查完整样本。

## 输入增长、净消化与停止门槛

每批之前保留上一批至少 15 分钟的连续基线；预计输入可能显著增加的 ARP/NDP，先核对既有被动统计或有明确时间、大小上限的报文样本及解码结果。这里不启动旧 `capture-device-sample.sh` 另开一个长期 Zeek，也不主动发包或现场造数。仅看到 packets/s 不等于有效 events/s；记录丢弃、解析失败、作用域排除和合并比例。

每五秒记录：运行代次、每 lane 剩余批次/事件、已处理事件/完成段/重试/超时、最新错误、消费者心跳；新增协议 received/parsed/rejected/admitted、最后成功；spool 文件与字节增长；PostgreSQL/ClickHouse、采集进程 CPU/内存、磁盘可用量/增长、捕获丢包；控制面和身份桥 ready、相关查询延迟。

所有速率用同一代次增量计算，不跨重启相减。总剩余必须相加 `realtime + backfill`，不能把 lane 转移当成消化。若没有独立入队累计计数，可用 `新增入队≈已处理增量+总剩余增量` 作短窗口估计，注明队列汇总更新时间和误差，不能包装成逐条精确计数。与上一批对比新增输入和消费率。

至少两个完整连续 15 分钟窗口满足：

- 有历史积压时，总剩余事件下降，即消费超过输入；已经追平时保持零积压且持续消费成功。只看 realtime 为零或 backfill 暂停不算通过。
- 没有一致性冲突、消费者失联、异常重启、持续超时或 spool 溢出；新增协议在实际有流量的情况下有可追溯成功证据。
- 新实时事件仍逐条检查首次入库至查询可见的 5 秒约束，超限/失败分别保留。既有历史积压的恢复耗时另记，不能混入均值掩盖新事件延迟。相关当前状态查询 P95 ≤500ms、P99 ≤1s。
- 资源与捕获丢包未触及本轮只读预检核实的现场限制。记录实际限制数值，不直接沿用历史 watchdog 的默认值；若丢包指标不可获得，不宣称无丢包。

处理规则：

- `content_conflict` 立即停止新领取，保留证据和任务；不要靠协议回退掩盖一致性错误。
- 连续 60 秒无消费进度、两个连续完整五分钟超时率 >1%、控制面/身份桥异常、OOM、spool 满、磁盘或已核实资源保护阈值触发：停止扩量，回退本批新增输入并复核。不扩大超时或并发来使本批通过。
- 新实时事件超限、相关查询延迟持续不达标，或者完整 15 分钟窗口总积压不下降：不进入下一批；确认不是采样/代次问题后回退本批，继续恢复前一有效范围。不得清队列、删回执、重置 offset 或缩短保留期。
- 如果没有该协议有效样本，可记录 30 分钟运行稳定，但覆盖状态仍未验证；按已有流量与价值决定保留待观测或回退，不宣称该协议识别验收通过。

## 回退

回退前再次核对现场配置哈希仍等于本批 candidate，避免覆盖其他线程后续改动。若一致，原子恢复本批 `rollback.json` 到同一路径、恢复原属主权限，仅重启刚才修改的 discovery-worker，并确认其实际参数、既有已启用协议与运行模式。若不一致，先核对差异，合并撤销本批开关，保留其他修改。

已入队事件和 spool 仍须正常处理；配置回退不删除原始标准事件、发现事实、回执、恢复清单或历史。每次回退用新观察文件检查前一配置恢复正常。只读处罚/通知边界不变，主动扫描、SNMP主动查询、SSDP describe 和富化不随协议开关启动。

## 现有解析与可观测性边界

- NBNS/LLMNR 仅从响应答案取地址和名称，不从查询取名称；本地回放覆盖未打标签和单 VLAN。
- LLDP 保留管理地址与邻居作用域，不把以太网源 MAC 填成远端设备绑定；CDP 当前只有邻居线索，无管理地址时不得推断终端 IP。
- `packetProtocol()` 尚无 CDP 分支，所以 CDP 报文可能计入 `other`，而标准事件与 admitted 为 `cdp`。进入 neighbors 批次前必须用有界 CDP 样本及实际回执补充核对；只看 CDP received=0 不足以判断无流量。如果无法取得这些证据，保持该批待验证，不宣称 CDP 完整覆盖。
- ARP/NDP/CDP 复用的控制帧解码器只保留第一层 VLAN，双层标签不能保证完整作用域。若镜像存在 QinQ，相关协议必须先修复完整 VLAN 作用域并回放，再启用；不得按单 VLAN 测试通过宣称 QinQ 支持。LLDP、NBNS/LLMNR 的服务解码路径保留组合标签，但本批新增回放仅验证未打标签和单 VLAN。
- 采集仅在约 100ms 或 250 条的当前批次内合并同一语义观测，没有跨窗口的全网降采样/限速。ARP/NDP 高频广播不能假定被长期去重；后端按事件回执幂等和事实语义更新不消除每条新事件的归档/消费成本。

## IoT 候选与 128 上限

IoT 不是本轮四批被动协议的一部分。`ipp/rtsp/http/tls/mqtt` 继续关闭，直到存在合适候选且受限链路经过独立验证。候选为 0 表示目前没有可试运行的有效范围，不能因此移除过滤、改成全网 TCP 或人为补造设备事实。

候选生成器从当前有效、未撤销的 `dns_sd/ssdp/ws_discovery/dhcp/arp/ndp/bacnet/coap` 事实读取；`SELECT DISTINCT ... LIMIT 129` 后超过 128 返回错误，不会分页。候选关闭时生成空 BPF，旧的空 TSV 不代表数据库里真实候选一定为 0。用当前 sensor 参数执行以下只读查询，导出 JSON 数组供检查：

```sql
SELECT coalesce(json_agg(t), '[]'::json)
FROM (
  SELECT DISTINCT ip, vlan, domain, interface_name,
         coalesce(observation->>'site', '') AS site
  FROM discovery_service_facts_v2
  WHERE sensor_id = $1
    AND valid_until > now() AND NOT withdrawn
    AND protocol IN ('dns_sd','ssdp','ws_discovery','dhcp',
                     'arp','ndp','bacnet','coap')
  ORDER BY ip, vlan, domain, interface_name, site
  LIMIT 129
) t;
```

```bash
python3 scripts/zeek/collection_enable_plan.py check-iot \
  --config /absolute/path/current-collection.json \
  --candidates /absolute/path/iot-candidates.json
```

工具返回 `candidate_scope_ready`，仅代表候选数量/地址/作用域检查，不代表 logger、输入订阅、性能或应用验收。`no_candidates`、`over_capacity`、`ambiguous_scope` 返回非零。它不修改候选或 collection，不静默截断到前 128 条，不改全局 CIDR。

安全范围要求：

1. 1–128 条明确候选、地址在当前采集范围、IP/VLAN 对应唯一 site/domain/interface；有冲突时先解决归属。先按价值选少量已确认的打印机/摄像头等设备，并只开一种匹配协议。
2. **现有自动生成器没有独立的 IoT allowlist 或公平分页调度。** 如果总候选超过 128，或不能保证试运行期间的数量/范围，先实现受控 allowlist（完整 IP/VLAN/site/domain/interface）、有效期和显式排除/超额报告，再做回放和部署；不得靠 `LIMIT 128`、删除事实、缩小全局发现 CIDR或提高硬上限解决。
3. 不手改自动维护的 TSV 充当限制，worker 每五秒会重写。候选突然超过 128 时生成器返回错误，旧 profile 可能继续留存；此时停止 IoT 新采集、保留证据并修复范围，不能继续把旧 profile 当最新有效范围。
4. 专用脚本 `assets/zeek/iot-metadata.zeek`、候选/开关/过滤 TSV、受限 BPF、`iot_metadata.log`、`--zeek-iot`、collection owner 和原始证据查询需完整贯通。协议普通日志不随脚本加载而全网保留。保持 DHCP 的既有采集范围，验证合并过滤逻辑，不以替换 BPF 破坏 DHCP。
5. 每种 IoT 协议再执行独立至少 30 分钟观察及同样的净消化/延迟/资源检查；MQTT 仅指定发现声明，不留遥测、密码或任意 topic，响应设备归属不得猜测。

## 本地验证

本次只添加本地规划器、只读 Go 校验入口、独立回放测试及本文，未启动数据库栈、未操作服务器。以下验证实际通过：Python 8 项、`scripts/zeek` 的原有 Go 7 组（名称协议含 4 个子用例）及追加 DHCP binding 3 组（8 个拒绝子用例）、相关四个 Go 包、全量构建和 vet；BPF 测试找到 tcpdump 并实际执行，未跳过。配置生成后通过实际 Go 加载器的临时文件校验，差异空白检查通过。

```bash
python3 -m unittest scripts/zeek/test_collection_enable_plan.py
go test ./internal/discovery ./internal/devicesignal ./internal/adapter/zeek ./internal/realtime ./scripts/zeek -count=1
go build ./...
go vet ./...
```

新增测试覆盖配置增量/owner/原字节回退/拒绝覆盖、IoT 0/128/129 和范围冲突；NBNS/LLMNR 响应与查询、LLDP/CDP、ARP请求/应答、NDP NA/NS/hop-limit、单owner和名称批次 BPF。真实 PostgreSQL/ClickHouse入库、现场流量和三十分钟观察不由这些测试替代。
