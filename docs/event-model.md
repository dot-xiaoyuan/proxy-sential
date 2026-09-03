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
