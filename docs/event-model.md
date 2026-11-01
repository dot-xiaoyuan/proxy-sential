# 标准事件模型

## 设计目标

标准事件模型是 Proxy Sentinel 的核心边界。风险引擎只读取标准事件，不读取 Suricata、Zeek、AF_XDP、DPDK 的原始结构。

目标：

- 支持多采集后端并存。
- 支持事件回放。
- 支持证据追溯。
- 支持后续字段演进。

## 事件总结构

```json
{
  "schema_version": "v1",
  "event_id": "01J...",
  "source": "suricata",
  "source_event_type": "tls",
  "type": "tls",
  "timestamp": "2026-07-22T10:00:00Z",
  "observer": {
    "sensor_id": "campus-mirror-01",
    "interface": "ens192",
    "vlan": 100
  },
  "subject": {
    "ip": "10.1.2.3",
    "user_id": "20260001",
    "account_id": "20260001",
    "endpoint_id": "mac:aa:bb:cc:dd:ee:ff",
    "mac": "aa:bb:cc:dd:ee:ff",
    "access_id": "Dorm-3F-AP08",
    "entity_role": "endpoint",
    "identity_confidence": 0.9
  },
  "flow": {
    "src_ip": "10.1.2.3",
    "dst_ip": "1.1.1.1",
    "src_port": 54321,
    "dst_port": 443,
    "proto": "tcp",
    "app_protocol": "http2",
    "direction": "outbound",
    "bytes_toserver": 1024,
    "bytes_toclient": 2048,
    "pkts_toserver": 6,
    "pkts_toclient": 8
  },
  "payload": {},
  "confidence": 1.0,
  "raw_ref": {
    "backend": "suricata",
    "line_offset": 12345
  }
}
```

## 事件类型

### flow

连接和流量基础信息。

必要字段：

- src_ip
- dst_ip
- src_port
- dst_port
- proto
- direction
- bytes
- packets
- start
- end

### dns

DNS 查询和响应。

payload：

```json
{
  "query": "example.com",
  "qtype": "A",
  "rcode": "NOERROR",
  "answers": ["93.184.216.34"]
}
```

### tls

TLS ClientHello 和指纹。

payload：

```json
{
  "sni": "example.com",
  "ja3": "hash",
  "ja4": "hash",
  "version": "TLS 1.3",
  "alpn": ["h2", "http/1.1"]
}
```

### http

HTTP 明文请求信息。

payload：

```json
{
  "host": "example.com",
  "method": "GET",
  "url": "/index.html",
  "user_agent": "Mozilla/5.0 ..."
}
```

### quic

QUIC 可见握手信息。

payload：

```json
{
  "sni": "example.com",
  "alpn": ["h3"],
  "version": "1"
}
```

### device

设备侧信号，来自 DHCP、mDNS、NBNS、LLMNR、UA parser、MAC OUI 等。

payload：

```json
{
  "origin": "dhcp",
  "device_name": "iphone",
  "vendor": "Apple",
  "os": "iOS",
  "model": "iPhone",
  "ttl": 64,
  "hostname": "yuan-iphone",
  "vendor_class": "Apple iOS DHCP",
  "requested_options": "1,3,6,15,119,252",
  "client_mac": "aa:bb:cc:dd:ee:ff",
  "device_hint": "apple"
}
```

第一阶段 Zeek 设备指纹 PoC 只接入 `dhcp.log`，将 `host_name`、
`client_software`、`requested_options`、`mac`、`requested_addr` 和
`assigned_addr` 映射到 `device` 标准事件。`device_hint` 是本地轻量归类，
不依赖 Fingerbank 在线查询。

第二阶段开始接入 Zeek `software.log`，仍映射为 `device` 标准事件：

- `payload.origin = "software"`
- `source_event_type = "software"`
- `payload.software_type/software_name/software_version`
- 当 `software_type = DHCP::CLIENT` 时，将 `unparsed_version` 同步为
  `payload.vendor_class`，用于和 DHCP 设备画像合并。

`software.log` 只作为标准设备信号来源，不让风险层直接读取 Zeek 原始日志结构。

抓包侧的 TTL / Hop Limit 是按源 IP、方向、IP 版本和适用范围聚合的设备观测，
不能伪造为单条连接。`flow.src_ip` 为实际源地址，`flow.ip_version` 为 4 或 6，
`flow.traffic_scope` 为 `unicast`、`multicast`、`broadcast`、
`protocol_specific` 或 `unclassified`。聚合桶不声明具体目的地址、端口或协议，
并在 `payload.observed_count` 保留包数。相同 TTL 的单播与组播分别计数和生成事件 ID，
目的地址数量不会增加聚合桶数量。

IPv4 事件使用 `source_event_type = ttl`、`payload.origin = ttl` 和 `payload.ttl`；
IPv6 使用 `source_event_type = hop_limit`、`payload.origin = hop_limit` 和
`payload.hop_limit`，二者与 flow / payload 中的 IP 版本保持一致。
主机 IPv4 TTL 路径规则只使用单播适用范围，排除组播、广播、mDNS 等协议专用值，
原始观测仍保留。缺少范围的历史事件沿用兼容读取，按自然窗口过期；不为历史数据补造上下文。
示例见 `examples/device/ttl-scope/protocol-ttl.jsonl`。

### 协议自报归属事件

Zeek 无法给 `dns`/`http`/`ssl` 日志附加链路层地址，因此 HTTP `Server` 头、
页面标题和 TLS 证书字段虽然能识别设备，却无法直接落到物理终端。域名识别
worker 对这些事件按“同一传感器、园区、地址与事件时刻的唯一有效 DHCP 租约”
归属，并派生 `type = device` 的标准事件：

- `payload.origin = "http"` 或 `"tls"`，`payload.derived = "protocol-self-report"`
- `payload` 只保留白名单自报字段：`server`、`title`、`certificate_subject`、
  `certificate_issuer`、`certificate_san`、`ja3`、`ja4`
- `subject.mac` 来自唯一租约；缺失租约、租约冲突或非 `mac:` 归属一律跳过，
  不按地址猜测
- `event_id` 由原事件 ID 与类型稳定哈希得到，重复批次幂等
- `raw_ref.derived_from` 指向原始事件 ID

派生事件只写入 PostgreSQL 的终端画像与设备信号，不回写 ClickHouse 标准事件，
因此证据聚合、风险评分、共享判定与路由识别不受影响。

### identity

账号、终端、IP 和接入位置的身份关联事件，来自 RADIUS、Portal、802.1X、
DHCP、交换机 MAC 表、无线 AC、网关会话日志等控制面数据。

payload：

```json
{
  "origin": "radius",
  "action": "login",
  "auth_method": "802.1x",
  "vlan": "108",
  "ap": "Dorm-3F-AP08",
  "switch_id": "sw-dorm-03",
  "switch_port": "Gi1/0/8",
  "session_id": "radius-session-xxx",
  "auth_mac": "aa:bb:cc:dd:ee:ff",
  "observed_mac": "aa:bb:cc:dd:ee:ff"
}
```

`identity` 事件必须先进入标准事件层，风险层不得直接读取 RADIUS、
Portal 或交换机原始字段。缺少 MAC 或明确终端标识时，`entity_role`
默认只能是 `unknown`，不得直接计入普通终端并发。

## subject 归属

`subject.ip` 是风险聚合的主键。旁路场景下，归属规则为：

- 如果 src_ip 是在线用户，subject.ip = src_ip。
- 如果 dst_ip 是在线用户，subject.ip = dst_ip。
- 如果无法归属用户，但属于受管网段，subject.ip = 内网 IP。
- 如果无法确定，事件仍保留，但不进入处罚链路。

## 版本演进

- v1 字段只新增，不删除。
- 破坏性调整必须升级 schema_version。
- Adapter 必须保留未知字段到 raw_ref 或 raw_summary。

## IEEE 1905 关联事件的地址归属

`ieee1905_client_association` 的客户端和 BSSID 属于二层协议证据。采集器不得用相同 Ethernet 源 MAC 上转发的 IP 数据包补写网关地址。聚合层以事件时间、传感器、园区及设备 MAC 查找有效 DHCP ACK；过期、释放、被其他 MAC 接管、同时冲突或同一 MAC 的多个有效地址均不绑定共享出口 IP。IP 归属不足时保留 MAC 关联记录，不能据此将其他 IP 确认为共享设备。

关联表更新时清除已不成立的旧地址。发布共享窗口前再次检查租约，防止没有新关联报文时，释放或地址重分配后的旧绑定继续生效。静态地址设备尚无 DHCP 归属证明时，客户端关联仅保留为二层参考证据；后续可扩展独立、可回放的地址归属来源。

## IEEE 1905 客户端快照

`ieee1905_client_snapshot` 为 `device` 标准事件，保留 `subject.mac`、协议 origin、AL-MAC、以太网源 MAC、消息类型/ID，以及 `payload.bss_snapshots` 数组。每项包含 `bssid` 和 `client_macs`；空客户端数组是该 BSS 的明确空快照，空 BSS 数组没有清理范围。只有完整且无分片的 Topology Response 能生成快照，原有逐客户端关联事件继续输出。

聚合层只撤销同传感器、园区、接入域、设备 MAC 和所报告 BSSID 下，不在快照中、且时间不晚于快照的关联。其他 BSS、更新的加入记录及原始事件保留。同一时间桶无法证明先后时，离开优先于加入，等待下一时间桶的独立加入报文才能恢复。

设备身份优先使用协议 AL-MAC，以太网源 MAC 保留为来源审计字段，不把转发接口包装成关联客户端的所属设备。接口地址与 AL-MAC 可以不同，参见 [prplMesh 对 IEEE 1905.1 表 6-2 的说明](https://github.com/prplfoundation/prplMesh/issues/81)。BSSID、客户端数量及客户端 MAC 的结构参见 [Wireshark IEEE 1905 Associated Clients 解析器](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ieee1905.c)。

回放输入：`examples/router/ieee1905/client-snapshots.jsonl`。JSON Schema 为 IEEE 1905 的 MAC 主体及二层协议流提供条件分支，其他事件的 IP/流字段要求保留。

## 二层控制报文与转发流量的边界

LLDP/CDP 只根据控制报文本身提供设备信息。没有明确管理地址时保留 MAC 主体，不能把同 Ethernet 源 MAC 下转发的用户 IP 补成控制设备 IP；不保留这种推测映射缓存。LLDP 的明确管理地址及 VRRP/HSRP/SSDP 的 IP 协议来源继续保留。普通 IP 统计的方向筛选与控制协议发现分别处理，方向筛选不能丢掉已支持的控制报文。

标准事件 Schema 为 LLDP/CDP 与 IEEE 1905 提供 MAC 主体分支；VRRP/HSRP/SSDP 仍要求 IP 来源与完整流字段。packet-sidecar 控制事件的 `source_event_type` 必须与 `flow.proto` 一致，既有 Zeek 发现事件继续使用原有 IP 流格式，普通流的 IP/流字段要求继续保留。真实采集路径的帧回放会验证转发 IP 不污染 LLDP/CDP 归属，生成输入见 `examples/router/l2-controls/control-ownership.jsonl`。

客户端漫游后，旧 BSSID 的迟到退出只能撤销旧 BSSID 的关联；退出也必须匹配关联记录的园区和接入域，不能覆盖另一范围中的较新加入。回放输入 `examples/router/ieee1905/client-roaming.jsonl` 验证旧 BSS 退出、当前 BSS 退出及跨范围退出的处理。

TTL路径变化的标准事件回放样例为 `examples/device/ttl-scope/path-variation.jsonl`。
其中相同源IP的单播TTL64/63保留观测计数，风险层将其作为零分路径说明，
不把IP处理过程中的跳数变化解释为新增设备。聚合包数仍不能代替多个独立事件的重复共现。

`dhcpcd`、`udhcpc`、`dhclient` 等通用 DHCP 客户端原值继续保留在标准事件中，但不单凭客户端名称生成 Linux 系统提示。旧适配器根据这类客户端产生的 `device_hint=linux` 在系统家族推断时不作为独立依据；明确的 Android、Windows、Ubuntu 等其他线索仍可使用。本地归类属于推测，MAC 与名称观测不随之删除。[dhcpcd 上游](https://github.com/NetworkConfiguration/dhcpcd)说明其用途为 DHCP 客户端；[Android AOSP 的 dhcpcd 源码](https://android.googlesource.com/platform/external/dhcpcd/)也说明客户端名称不构成桌面系统专有身份。回放输入 `examples/device/portable-dhcp/client-aliases.jsonl` 保留旧提示和全部原值，验证通用软件不会增加操作系统或设备类型结论。

## 被动 mDNS 主机地址公告

现场采集默认使用兼容生产形状：`discovery-worker` 的 `--passive-dns-evidence-v2` 默认为 `false`，不输出下文主机地址事件及 SRV priority/weight 新字段；缓存索引、容量约束和已有服务发现继续工作。该开关只通过进程参数设置，集合配置文件不能隐式启用，`capture.stats.dns_record_evidence_version` 为 1/2。消费者和回放始终支持两种证据。先发布此兼容版本并验证，将它保留为应用回退入口后，才可另行授权启用 v2；启用时不改变固定源起点或丢弃待处理段。

`type=discovery`、`source_event_type=dns_sd` 沿用现有标准事件。没有可解析服务的本包 A/AAAA 公告可带可选 `payload.dns_record_kind=host_address`：`dns_name` 保留本包 owner 大小写与结尾点，`dns_record_type` 为 A/AAAA，`dns_record_class`、`dns_record_ttl`、`dns_record_address` 保留原记录值，`announcer_ip` 为本包 IP 来源，`dns_message_id` 与 `dns_message_sha256` 标识原始 DNS 消息。消息 SHA-256 按 UDP 内完整 DNS 字节计算，记录字段不能冒充完整原始包；当前采集链没有包存储引用时，不声明原包可回取。

这只是主机名与地址的弱线索：`subject.ip` 是被公告地址，`subject.mac` 为空，`address_binding=false`，不得生成服务实例、类型、目标或端口字段。以太网源 MAC 只留作 `ethernet_source_mac` 来源证据，不归属于被公告终端；主机名不进入产品、系统和整机类型推断，也不形成确定当前地址绑定。现有 `dns_sd` 配置同时控制这类公告，采集允许范围分别检查报文源和被公告地址。查询报文、非 IN 类地址、组播/未指定/回环地址不形成此线索。

事实键保留完整采集作用域，区分规范化 DNS owner、A/AAAA、被公告 IP 和真实报文公告者 IP；owner 比较忽略大小写与结尾点。不同 VLAN 不合并；同 IP 的多个名称分别保留事实。不同公告者的主机声明保留独立事实，另一公告者的 goodbye 不得撤销原声明；公告者仍只是证据来源，不因此建立地址绑定。仅本包 A/AAAA 可以创建或续租主机事实，跨包缓存不会把旧地址伪装成新公告；TTL 0 撤销对应事实，其他别名不被撤销，自然过期以原观测时间和 TTL 计算，最长有效期仍为七天。本包服务已经表达同地址时，避免重复生成正向主机事实；TTL 0 主机撤销仍保留。旧版设备事实消费者需支持该可选分支后再接入流量，本轮未改变 UI 或自动发布。

mDNS 关联缓存最多保留 10,000 条记录和 8 MiB 计费字节（键字节及展开 DNS 记录字节，不等于进程 RSS）；相同键满缓存仍可续租，撤销与过期释放容量。缓存拒绝新增记录时，本包内容继续参与当前消息解析。`capture.stats.dns_cache` 固定记录 `records`、`bytes`、累计 `records_not_retained`、累计 `messages_with_records_not_retained` 和最近受影响 `last_message_sha256`，即使纯 TXT/PTR 没有可生成的设备事件也保留统计。这些字段表示关联缓存保留缺口，记录数按同一消息合并重复项后的有效记录计数，不能解释为抓包丢包或当前报文未收到。

关联缓存的命名空间用无歧义结构编码 `source_id`、采集节点、站点、接入域、接口、完整 VLAN 标签串和本包 `announcer_ip`，仅使用解析层实际已有值，不推断 VRF。同一公告者的跨包 SRV、A/AAAA、TXT、PTR 仍可互补；不同公告者、接口或采集作用域不能互补服务。服务解析和关联缓存只使用 IN 类记录，记录身份区分类别而不把 cache-flush 位当成另一类别。本包主机公告仍从原消息记录生成，保留各自通过既有采集边界的标准事件；无地址的 SRV-only 输出仍可能被 CIDR 筛选过滤，不代表每条原始 DNS 消息均已保存。

缓存按 owner 建记录索引，并为 SRV target 和 PTR instance 建反向索引。每包只展开所触及服务及去重后的地址、TXT、PTR 依赖；A-only 包没有相关 SRV 时，不重建其他缓存记录。共享 target 只读取一次依赖。每个保留记录占一个 owner 索引项、一个过期堆节点，SRV/PTR 再占一个反向索引项；续租原位调整堆，撤销和过期同时移除索引及空桶，拒绝新增时不留下索引。索引元数据由 10,000 条记录上限约束，计费字节继续独立约束正文与键，不能等同为总内存上限。续租对原记录实际字节变化重新计费，超限时保留旧内容与旧截止时间。本包处理量取决于本包、相关依赖和实际过期记录，不随无关存活缓存量全量扫描；原文、确认及后续事实保留职责不变。

每 DNS 消息的服务和主机输出合计最多 250 个事件、512 KiB JSON 事件字节，按稳定次序显式截断。达到边界时输出 `dns_message_coverage`，精确记录 `candidate_events`、`emitted_events`、`omitted_events`、`omitted_fields`、限额与 `complete`，并附原消息 SHA-256。首个服务的超大缓存 TXT 超出预算时保留实际服务/地址/TTL，省去 TXT 并记录 `dns_fields_omitted`，不得把省去的产品字段用于识别。缓存拒绝时另附 `cache_records_not_retained`，不等同于当前输出不完整。输出截断的说明明确标记该消息未完整覆盖；正常消息不增加覆盖计数。消息 hash、ID、原 TTL 与覆盖计数是证据元数据，不参与事实语义 hash，不形成设备事实或强分类。纯关联缓存压力也不进入设备事实解释或可见版本；只有实际输出/字段截断保留完整性二态说明。同一消息的相同记录按最短 TTL 合并，TTL 0 撤销优先且不依赖记录排列顺序。

回放输入：[mDNS 主机地址公告](../examples/discovery/mdns-host-announcements.jsonl) 包含 A、AAAA、同 IP 别名与大小写不同的撤销。测试从每条记录重建单答案 DNS 消息核验 SHA-256，并验证采集范围、归属、撤销、过期、缓存与输出双界。这些是本地回放结果，不代表现场容量验收。

真实 SRV 记录另保留可选 `service_priority`、`service_weight`；服务生产者事件标识和事实标识都区分 instance、target、port、priority、weight，事实还包含被公告 IP 和既有采集作用域。priority/weight 缺失按零处理，TTL 变化不改变事实标识，同一 SRV 的续租和 goodbye 命中同一事实，不同实际 SRV 不相互覆盖。没有 target/port 的通用服务线索仍沿用原事实语义。该事实键升级不改写既存历史：旧键事实按原 TTL 自然过期，过渡期可能与新键事实并存，不将其包装成新设备或历史已重算。

回退存在语义边界：r32 消费器不识别主机公告专用事实键，也未按完整 SRV 字段区分事实，不能安全接手启用 v2 后的新语义待处理段。关闭开关或统计版本恢复为 1，不证明历史 v2 待处理段已消失。后续启用版本应回退到已验证的兼容读取版本，而非 r32。若确需回退 r32，必须先由支持本模型的新版本以 `--mode=stream-drain` 处理完这些待处理段，核验消费结果及失败/未完成缺口，并恢复旧生产参数；不能让旧二进制直接消费新段，也不能删除或跳过待处理证据。这里只说明回退条件，不自动执行发布、排空或历史清理。
