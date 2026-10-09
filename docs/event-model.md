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
