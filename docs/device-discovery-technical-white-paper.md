# Proxy Sentinel 网络设备发现实现

**从镜像报文到设备当前态的工程实现**

| 项目 | 内容 |
|---|---|
| 文档性质 | 技术白皮书，按实际实现顺序说明 |
| 代码基线 | 仓库提交 c3e1c600（2026-11-11） |
| 现场数据 | 204 节点 2026-11-06 至 11-10 只读记录 |
| 文档日期 | 2026-11-16 |

## 摘要

Proxy Sentinel 的设备发现由五段组成：采集、解析为标准事件、持久化、投影为事实与当前态、查询。当前 204 节点使用的主链路是：

镜像报文或 Zeek 日志 → ClickHouse 的 passive_discovery_events_v2 → passive-discovery-worker → PostgreSQL 的 discovery_observations 与 latest 读模型 → 查询接口。

系统不把“抓到的报文”直接当设备。每条报文先变成带作用域的标准发现事件；事件按设备键和事实键去重、比较版本、计算有效期；当前态由仍然有效的事实聚合；类型判定和终端画像识别再分别读取这些事实和结构化属性。

本文按处理顺序展开：先说明一次发现从报文到查询的完整路径，再说明采集、解析、批次处理、事实化、当前态、类型判定、终端识别、归属、主动发现和查询的实现方式。

## 1. 端到端流程

### 1.1 一次发现的完整链路

一次发现的处理顺序固定为六步：

1. 采集进程从镜像口、Zeek 日志、SNMP 或主动探测拿到原始输入。
2. 解析器把原始输入转换成标准发现事件，写入 ClickHouse。
3. passive-discovery-worker 按时间和事件 ID 读取一批事件。
4. 每条事件被转换成 Observation，计算设备键和事实键。
5. 事实写入 PostgreSQL，随后聚合成当前设备状态。
6. 查询接口读取当前状态、证据和历史。

### 1.2 模块与数据落点

| 阶段 | 输入 | 处理 | 输出 | 落点 |
|---|---|---|---|---|
| 采集 | 镜像报文、Zeek 日志、SNMP 响应、主动探测响应 | BPF 过滤、协议解码、作用域校验 | 标准发现事件 | ClickHouse |
| 批次读取 | ClickHouse 表 | 游标、租约、批大小控制 | 一批原始事件 | 内存 |
| 观察转换 | 标准事件 | 作用域、设备键、事实键、语义哈希 | Observation | 内存 |
| 事实写入 | Observation | 版本比较、TTL、撤销、重复判断 | 事实、变化、身份链接 | PostgreSQL |
| 当前态聚合 | 同一设备的事实 | 当前地址、MAC、类型、协议、能力、过期时间 | 当前状态文档 | PostgreSQL |
| 查询 | 当前状态、证据表 | 过滤、排序、游标分页 | 设备列表、详情、历史 | API |

### 1.3 一次 ARP 应答的走查

以一条 ARP 应答为例：

1. 采集端在镜像口看到 ARP 应答，源 MAC 为 aa:bb:cc:dd:ee:ff，发送方 IP 为 10.1.2.3，VLAN 100。
2. 解码器生成事件：type=discovery，source_event_type=arp，subject.ip=10.1.2.3，subject.mac=aa:bb:cc:dd:ee:ff，payload.address_binding=true，TTL 600 秒。
3. 事件写入 ClickHouse，event_id 由来源、报文内容、观测时间稳定生成；原始报文引用保留在 raw_ref。
4. worker 读到事件后，按 sensor、site、domain、VLAN、VRF、interface 和 IP 计算设备键；按来源、协议、MAC、IP 计算事实键。
5. 事实写入 discovery_observations；同一事实再次出现时只刷新最近观测时间，不新增设备。
6. 当前态聚合时，ARP 的 address_binding=true 可以作为当前 MAC 绑定；如果之后出现新的 DHCP 租约或 ARP 换绑，旧绑定会被替换或过期。
7. 查询接口返回该设备的当前地址、MAC、协议、最近观测和证据数；原始 ARP 事件可通过证据引用回查。

这条路径同样适用于 DHCP、NDP、mDNS、SSDP、LLDP、SNMP 等协议，差别只在解码字段和证据强度。

## 2. 采集与解析

### 2.1 采集入口

当前实现有四类入口：

| 入口 | 采集方式 | 主要协议 | 说明 |
|---|---|---|---|
| 镜像口被动采集 | 原始套接字 + BPF 过滤 | ARP、NDP、LLDP、CDP、mDNS、SSDP、WS-Discovery、SNMP、DHCPv6、NBNS、LLMNR、BACnet、CoAP | 需要 CAP_NET_RAW；按接口、站点、网络域、允许 CIDR 采集 |
| Zeek 日志 | 读取 Zeek 生成的日志文件 | DHCP、SIP、RTSP、HTTP 设备、TLS 设备、SSL/x509 | 适配器把日志行转成标准事件；适合应用层自报字段 |
| SNMP 只读轮询 | 定时读取交换机/AP 的 MIB 表 | FDB、邻居表、LLDP 邻居、sysDescr | 需要管理 IP、只读凭据和节点映射 |
| 主动探测 | 经授权的 ICMP/ARP/NDP/IPP/SSDP/ONVIF | 目标定向探测 | 默认不启用；需要允许网段、接口、维护窗口 |

204 节点的被动侧以镜像采集和 Zeek 日志为主。SADP 由 packet-sidecar 解析后进入同一套标准事件；IEEE 1905 的关联和拓扑也走标准事件。

### 2.2 抓包过滤与作用域

抓包过滤在数据链路层完成，不依赖 libpcap 的 VLAN 关键字，而是显式计算三层偏移，支持单层和双层 VLAN 标签。过滤条件包括：

- ARP、LLDP、CDP、IEEE 1905 的 EtherType；
- NDP 的 ICMPv6 类型；
- mDNS 5353、SSDP 1900、WS-Discovery 3702、SNMP 161/162、DHCPv6 546/547、NBNS 137、LLMNR 5355、CoAP 5683、BACnet 47808、SADP 37020；
- 只保留配置中启用的协议。

每条事件都带作用域：传感器、站点、网络域、VLAN、VRF、接口。采集范围由允许 CIDR 显式给出；空范围不会退化成全网抓包。IPv6 链路本地地址按传感器和接口隔离；全局地址不命中范围时直接跳过。

### 2.3 协议解码

解码器的输入是以太网帧，输出是标准发现事件。当前解码路径如下：

| 协议 | 解码内容 | 生成的关键字段 |
|---|---|---|
| ARP | 发送方/目标 IP、MAC、请求/应答 | address_binding（仅应答为 true）、TTL |
| NDP | 邻居通告/请求、目标链路层地址选项 | IPv6 地址、MAC、address_binding |
| DHCPv4 | ACK/REPLY/RELEASE/NAK、租约、主机名、vendor class、请求选项、选项顺序 | IP、MAC、租约时间、hostname、dhcp_vendor_class、dhcp_requested_options、dhcp_message_type |
| DHCPv6 | Reply 中的地址绑定、DUID、IAID | IPv6、DUID、IAID、有效期 |
| DNS-SD | PTR/SRV/TXT/A/AAAA、服务实例、端口、TTL | service_type、service_instance、service_target、service_port、txt、model |
| SSDP | 响应/NOTIFY、USN、ST/NT、Location、Server | usn、service_type、device_type、manufacturer、model |
| WS-Discovery | ProbeMatch、Types、XAddrs | types、endpoint_reference、厂商/型号 |
| LLDP/CDP | Chassis、Port、TTL、System Name/Description、Capabilities、管理地址 | chassis_id、remote_port、system_capabilities、system_description |
| SNMP | sysDescr、sysObjectID、sysName、FDB、邻居表、LLDP 表 | vendor、model、port、vlan、address_binding |
| SIP/RTSP | User-Agent、Server | sip_user_agent、sip_server、rtsp_user_agent、rtsp_server |
| HTTP/TLS | Server、Title、证书 Subject/Issuer/SAN、JA3/JA4 | http_server、http_title、tls_subject、tls_issuer、tls_san、ja3、ja4 |
| SADP | ProbeMatch、型号、claimed IP/MAC、二层源 MAC、摘要 | product_model、claimed_ip、claimed_mac、l2_source_mac、identity_status |
| IEEE 1905 | 关联/离开、BSSID 快照、AL-MAC | client_mac、bssid、association_state |

DNS-SD 的解码还维护一个关联缓存：最多 10,000 条记录、8 MiB；PTR、SRV、TXT、A/AAAA 可以跨报文互补，但只在同一来源、接口、VLAN、公告者作用域内关联。缓存满时，本包内容照常解析，但新记录不再进入缓存，并记录拒绝计数。

### 2.4 标准发现事件

标准事件的结构是固定的：

| 字段 | 内容 |
|---|---|
| event_id | 稳定事件 ID；由来源、报文内容和观测时间生成，重放不重新生成 |
| source / source_event_type | 采集来源和协议类型 |
| type | discovery |
| timestamp | 观测时间，RFC3339Nano |
| observer | 传感器、来源、接口、采集作用域、配置版本 |
| subject | 站点、网络域、VLAN、VRF、IP、MAC |
| payload | 协议字段、TTL、撤销、address_binding、型号等 |
| raw_ref | 原始报文或日志的引用、哈希 |

解析阶段只接受“响应/公告”作为设备证据。DNS-SD、SSDP、WS-Discovery、SNMP、IPP、ONVIF 要求响应标志；SIP/RTSP 只接受响应或注册方向的事件；查询报文不生成设备结论。地址校验拒绝组播、未指定、回环和非法地址。

### 2.5 原始事件落库

标准事件写入 ClickHouse 的 passive_discovery_events_v2。该表按时间组织，保留事件 ID、来源、协议、传感器、园区、subject、observer、payload、flow、raw_ref 和置信度。原始事件是证据的权威副本；后续所有事实、类型和识别结果都可以回放到这条事件。

写入按批次进行，批次有稳定 ID、记录数、校验值和状态。POSTGRES 只保存投影结果和任务状态，不保存每条事件的完整正文。

## 3. 发现处理主流程

### 3.1 批次读取

passive-discovery-worker 从 ClickHouse 读取事件，读取水位使用 (timestamp, event_id) 游标，而不是只按时间。这样同一时间戳下的事件不会因为顺序不稳定而漏读或重复。

| 参数 | 当前值/行为 |
|---|---|
| 读取保护窗口 | 默认 2 分钟，可配 30 秒至 30 分钟 |
| 批大小 | 1,500 条 / 6 MiB；慢批减半，最低 500 条 |
| 批大小恢复 | 连续三次满批成功后翻倍，最高 1,500 条 |
| 租约 | 90 秒；过期后其他 worker 可以接管 |
| 单批预算 | 45 秒；超时保留原游标重试 |
| 游标推进 | 只推进到已提交的最后一条事件 |

读取保护窗口的作用是等待晚到和乱序写入 ClickHouse 的事件。窗口内的事件不会被提前处理；窗口外的事件按游标继续读取。

### 3.2 作用域与设备键

设备键决定“什么算同一个发现设备”：

设备键 = SHA256(sensor, site, domain, vlan, vrf, interface, identity) 的前 32 位。

identity 的取值顺序是：

1. IP 存在时用 IP；
2. IP 为空、MAC 存在时用 mac:MAC；
3. 两者都为空但有服务实例时用服务实例或服务目标；
4. 最后用 event_id 兜底。

设备键始终包含传感器、站点、网络域、VLAN、VRF 和接口。同一 IP 出现在不同 VLAN 或不同传感器下，会得到两个设备键；同一 MAC 换 IP 也会得到新的设备键，旧键按 TTL 过期。当前实现选择“宁可分裂，不可错并”。

| 场景 | 结果 |
|---|---|
| 10.1.2.3 / VLAN 100 / 传感器 A | 设备键 A |
| 10.1.2.3 / VLAN 200 / 传感器 A | 设备键 B |
| MAC aa:bb:cc:dd:ee:ff 从 10.1.2.3 换到 10.1.2.4 | 两个设备键，旧键过期 |
| 服务公告没有 IP/MAC，只有服务实例 | 以服务实例形成独立键 |
| 只有 ARP/NDP，没有类型证据 | 设备键存在，类型为空 |

### 3.3 事实化

Observation 转换成事实时，使用事实键和语义哈希：

- 事实键由来源、协议、服务实例、IP、端口等业务字段组成；mDNS 的 SRV 事实还区分实例、目标、端口、优先级、权重；ARP 请求和应答分开；主机地址公告单独成键。
- 语义哈希去掉 event_id、观测时间、有效期、TTL 以及只属于证据元数据的字段。同一服务重复公告、同一 ARP 心跳重复出现，不会生成新事实。
- 版本比较按 (observed_at, revision, event_id) 决定新旧。
- TTL 以原始观测时间加租约/公告 TTL 计算，最长 7 天；TTL 为 0 表示撤销。
- 同一内容重复只刷新首末观测和计数；不同内容才进入可见变化。

每次事实比较会得到以下结果之一：

| 结果 | 含义 |
|---|---|
| applied | 新事实或新版本 |
| repeat_observation | 内容相同，只刷新观测 |
| corrected | 同键内容变化 |
| withdrawn | 显式撤销 |
| restored | 撤销后恢复 |
| late_history | 晚到旧事件，不覆盖当前事实 |

### 3.4 当前态聚合

当前态由同一设备键下仍然有效的事实聚合：

- 当前地址只来自 address_binding=true 的 DHCP/ARP/NDP 事实；
- 当前 MAC 只来自 DHCP/ARP/NDP 的绑定事实，不采用服务报文的传输层源 MAC；
- 如果绑定 MAC 发生变化，旧的非绑定事实会被撤销，避免旧服务证据挂到新设备；
- 设备类型由强类型事实聚合；协议类型、能力、厂商/型号只作为线索；
- 首末观测、证据数、传感器、网络域、VLAN、接口、过期时间写入当前状态文档。

当前态状态机：

candidate → identified → expired → candidate

candidate 在出现强类型证据时进入 identified；证据过期或撤销后进入 expired；支撑结论的证据全部被替换后回到 candidate；多个强类型冲突时进入 conflict。

### 3.5 过期与刷新

每条当前状态带 expires_at，取当前有效事实中最早的到期时间。后台任务按 expires_at 有界领取状态并重新聚合；没有新事件也会推进过期，不会把旧状态一直当成当前状态。未来生效的事实会另外设置唤醒点。

## 4. 发现类型判定

### 4.1 两层证据

发现类型判定分两层：

1. 协议自报线索：LLDP 的 system_capabilities、SSDP 的 InternetGatewayDevice、WS-Discovery 的 NetworkVideoTransmitter、SADP 的直接二层型号、SIP/RTSP 的 UA/Server、DHCP/TTL 的系统线索。
2. 强类型规则：只有类型化协议或产品型号规则成立时，才产生确定的 IoT 类型。

### 4.2 强类型规则

| 类型 | 强证据 |
|---|---|
| printer | IPP 返回 printer-make-and-model；或 mDNS 服务类型 + TXT 产品字段 + 型号规则 |
| scanner | 扫描服务 + 型号/产品字段；打印机优先于扫描仪 |
| camera | WS-Discovery 声明 NetworkVideoTransmitter；或 ONVIF 设备信息；或 RTSP 厂商型号 |
| recorder | WS-Discovery 声明 NetworkVideoStorage |
| voip_phone | SIP UA 命中话机厂商/型号 |
| voice_gateway | SIP Server 命中 PBX/网关型号 |
| building_device | BACnet I-Am 的 device 对象 |
| sensor / display / iot_gateway | CoAP 资源类型显式声明 |
| media_player | mDNS TXT 的 model=appletv、md=chromecast 等 |

### 4.3 冲突与撤回

- 通用设备类型先占位：手机、桌面、服务器、路由器、交换机、AP、防火墙不会再叠加一个 IoT 类型。
- 多个强类型同时成立，或通用类型与 IoT 类型同时成立，状态记为 conflict，不任选一个。
- 设备从 identified 变为 expired 时，只有支撑该结论的证据全部撤销或替换，才清空最后类型；一个无关服务的撤销不会抹掉另一条服务实例的结论。
- 没有类型是合法结果；只有 ARP/NDP 的设备停留在 candidate。

### 4.4 证据边界

- 服务类型只证明能力，不证明整机型号；打印机要 IPP 型号或 mDNS TXT 产品字段。
- 查询报文、广播、组播、未指定地址、回环地址不生成设备结论。
- OUI 只给厂商，主机名只给类别线索，TTL 只给系统线索；它们不能单独生成型号。
- SADP 只有在采集器核实直接二层来源、claimed IP/MAC 与帧源一致时，才把型号提升为强类型；非直接来源保留为线索。

## 5. 终端识别引擎

### 5.1 识别输出

终端画像识别以端点（通常是 MAC）为单位，输出多个独立维度：

| 维度 | 含义 | 来源 |
|---|---|---|
| Vendor | MAC 注册厂商或 SNMP 企业号厂商 | IEEE OUI、SNMP sysObjectID |
| Brand | 市场品牌 | 型号库、规则、自报型号、域名生态 |
| Model | 产品型号 | 型号库、mDNS/SSDP/SNMP/IPP/ONVIF/RTSP/SIP |
| ProductFamily | 产品系列 | 型号库、规则 |
| DeviceType | 手机、桌面、平板、打印机、摄像头、路由器、AP 等 | 规则、协议自报、主机名/UA 线索、厂商先验 |
| OSFamily | Windows、Android、Apple OS、iOS、iPadOS、HarmonyOS、Linux | DHCP、UA、TTL、协议规则 |
| Confidence | 每个维度独立分值 | 规则分、库命中分 |
| Conflict | 冲突标记与冲突维度 | 强候选不一致 |

整体 Confidence 是规则评分，不是统计概率。品牌、型号、类型、系统分别展示；型号为空不代表品牌为空。

### 5.2 输入闸门

识别只接受标准事件中的有界字段，每个字段必须满足方向、协议、关联和时效：

| 方向 | 允许字段 | 约束 |
|---|---|---|
| device | hostname、DHCP vendor class/requested options/message type、mDNS/SSDP/SNMP/LLDP/CDP 自报、service type、IPP/ONVIF/WSD 型号 | 必须是设备自身或协议声明 |
| server | HTTP Server/Title/Auth/Body/favicon、TLS Subject/Issuer/SAN、SSH Banner、SIP Server | 必须能证明服务器归属 |
| client | User-Agent、JA3、JA4、TCP 签名、SIP User-Agent | 只能描述客户端运行时 |

协议字段也必须匹配：DHCP 只接受 hostname、vendor class、requested options、options、message type；TLS 只接受 tls_*、ja3、ja4；HTTP 只接受 http_*、favicon、user_agent。

关联方式只接受 direct、mac、unique_lease、unique_stream_binding；其他关联丢弃。未来时间或已过期的证据不参与；空值和超过 512 字节的值不参与（http_body 允许 16 KiB）；单次最多 128 条证据，引用最多 16 条，维度证据最多 48 条，产品候选最多 16 条。

识别结果带 stage（model/device_type/brand/vendor/os_family/none）和 reason（conflict、unattributed、no_current_signal、insufficient_specificity），用于区分“没有当前信号”“信号无法归属”“信号不够具体”“强冲突”。

### 5.3 特征地图

| 特征 | 输入 | 能支持 | 不能支持 |
|---|---|---|---|
| MAC OUI | 归一化 MAC 前缀（9/7/6 位）；随机 MAC 跳过 | 厂商参考，0.9 厂商分 | 品牌、型号、设备类型 |
| DHCP 选项 | option 55、60、61、77、43；message type；option order | OS/类型候选；Fingerbank 精确组合 | 单凭 option 55 确认型号 |
| 主机名 | DESKTOP-、LAPTOP-、iPhone、iPad、iQOO-、LENOVO-PC、MacBook | 设备类别线索（0.70–0.78） | 品牌/型号；网络设备角色确认 |
| mDNS/DNS-SD | 服务类型、SRV 目标/端口、TXT 的 model/md/product/ty/usb_mdl | 服务能力、部分产品型号 | 服务公告直接确认整机类型 |
| SSDP/UPnP | Server、ST/NT、Location 描述中的厂商、modelName、modelNumber | 网关/媒体能力、型号线索 | 仅凭描述确认硬件 |
| LLDP/CDP | Chassis、Port、System Name/Description、Capabilities、管理地址 | 路由器/AP/交换机角色线索、端口路径 | 终端 MAC 绑定；转发接口当设备地址 |
| SNMP | sysObjectID、sysDescr、sysName | 厂商、型号、基础设施角色 | 无响应即离线；OID 单独确认型号 |
| HTTP 设备面 | Server、Title、WWW-Authenticate、Body、favicon MD5 | 服务器产品/固件线索、同型号聚类 | 客户端身份；证书主题即型号 |
| TLS | Subject、Issuer、SAN、JA3/JA4 | 厂商/型号线索、客户端栈指纹 | 服务端证书直接证明物理设备 |
| SIP/RTSP | User-Agent、Server | 话机、语音网关、摄像头、NVR 型号 | 无 MAC/租约时的终端归属 |
| 型号库 | iPhone15,2、SM-G991B、DS-2CD2143G0-I | 精确/最长前缀匹配品牌、型号、系列、类型 | 目录外型号 |
| 多源规则 | 22,008 条源规则中的 12,120 条可编译规则 | 745 条 self_report 参与结论；11,375 条 auxiliary 只展示 | 用多库重复同一结论当多票 |
| 厂商先验 | 厂商名与产品线 | 静默设备的类型线索（≤0.80） | 品牌、型号、确定类型 |
| TTL/OS 线索 | 初始 TTL 区间 | 仅填充空 OS（0.55） | 覆盖已有强 OS；网络设备 OS |
| 域名生态 | 厂商服务域名，7 天窗口 | 品牌推测（最多 0.70；需多服务或重复观察） | 单一域名；与高置信品牌冲突时覆盖 |

### 5.4 识别流水线

| 顺序 | 阶段 | 规则与分值 |
|---|---|---|
| 1 | MAC 归一化与 OUI | 随机 MAC 跳过 OUI；厂商分 0.9；只写 Vendor |
| 2 | SNMP sysObjectID | 企业 OID 映射厂商；只作为厂商候选 |
| 3 | 型号库 | 精确优先，其次最长前缀；型号代码边界成立；置信度上限 0.95；输出 Brand/Model/Family/Type |
| 4 | 设备正则规则 | 103 条规则，按 hostname、SIP UA、TLS Subject、HTTP Title/Server 匹配；先命中者优先；弱规则不补造缺失字段 |
| 5 | Fingerbank DHCP | 按归一化 requested options 精确匹配，vendor class 辅助；取最高置信度候选 |
| 6 | DHCP 系统线索 | Android DHCP class 给 Android（0.82）；Darwin + Mac 主机名给 macOS（0.65） |
| 7 | 主机名前缀 | 仅填空设备类型；0.70–0.78；网络设备角色上限 0.65 |
| 8 | 客户端 UA | 仅填空设备类型；0.70–0.78；不能覆盖协议自报 |
| 9 | 厂商先验 | 仅填空设备类型；≤0.80；不产生品牌/型号 |
| 10 | 多源规则目录 | 只让 self_report 规则参与结论（0.8）；auxiliary 只展示；同值多库算一个候选 |
| 11 | TTL/OS 线索 | 仅填空 OS（0.55）；网络设备不采用 DHCP/UA/TTL 确认 OS |
| 12 | 型号系列线索 | 仅填空设备类型（0.65–0.74）；不产生品牌/型号/OS |
| 13 | 虚拟化 OUI | 虚拟化平台厂商覆盖为 virtual_machine（0.75） |
| 14 | 网络设备歧义策略 | 只有主机名的 router/AP/switch/firewall 置信度压到 0.65；抑制弱 OS |
| 15 | 品牌归一化 | 品牌别名归一；不改变证据和维度分 |

路由器识别是独立规则集：78 条 regex 规则按 hostname、vendor class、software、LLDP、SSDP、HTTP、TLS 评分；likely 阈值 60、confirmed 阈值 80，confirmed 还要求至少 2 个独立来源；AP、交换机、防火墙保留真实角色，但不生成 confirmed_router；证据默认 24 小时过期，关联窗口 10 分钟。

### 5.5 置信与冲突

多个来源给出同一维度时，合并规则是保守的：

- 空值可以被候选填充；同值取较高分；更具体的值可以覆盖更宽的值（mobile → tablet；Apple OS → iOS/iPadOS/macOS；Android → HarmonyOS）。
- 两个都达到冲突阈值（常规 0.85，多源目录 0.8，Fingerbank 0.85）且值不同，标记该维度冲突。
- 弱线索不能覆盖已确认值；同一字段的第二种解释可以暴露冲突，但不能补造缺失字段。
- 多源目录中，多个库给出相同值只算一个候选；不同 self_report 值才进入冲突。
- auxiliary 规则只作为证据展示，不改变结论。

### 5.6 典型识别样例

| 输入 | 过程 | 结果 | 边界 |
|---|---|---|---|
| Apple OUI + DHCP vendor class + iPhone 主机名 + 型号代码 iPhone15,2 | OUI 厂商；型号库命中 iPhone15,2；主机名/UA 辅助 | Apple / iPhone 14 Pro / mobile；OS 另判 | 随机 MAC 时没有 OUI，但型号代码仍可命中 |
| mDNS _ipp._tcp + TXT ty=HP LaserJet + IPP printer-make-and-model | 服务类型给 printing；TXT 产品字段 + 型号库给 printer/HP/LaserJet | 打印机 / HP / LaserJet | 只有 _ipp._tcp 时只给打印能力 |
| SADP 直接二层一致 + WS-Discovery NetworkVideoTransmitter + ONVIF Model + RTSP UA | SADP 核实直接来源；WS-D/ONVIF 给 camera；RTSP 补型号 | 摄像头 / 厂商 / 型号 | 非直接二层 SADP 只作线索 |
| LLDP WLAN 能力 + SNMP sysDescr + 主机名 | LLDP 给 AP 角色；SNMP 给厂商/型号 | AP / 厂商 / 型号 | 只有主机名时类型上限 0.65 |
| DHCP MSFT 5.0 + DESKTOP- 主机名 + Windows NT UA | DHCP 给 Windows；主机名给桌面；UA 辅助 | 桌面 / Windows | 路由器/AP 场景抑制弱 OS |
| 只有 OUI + 无其他信号 | OUI 给厂商；厂商先验给类型线索 | 厂商 + 类型线索（≤0.80） | 不给品牌/型号 |
| 两个强类型规则分别给出 printer 与 camera | 两个维度都达到强阈值 | 冲突标记 | 不任选一个 |

### 5.7 特征库与版本

识别规则是数据，不是散落在代码里的 if/else。离线包携带版本、来源、许可、校验值和转换器版本；运行时不访问外部服务。

| 目录 | 规模 | 用途 |
|---|---|---|
| IEEE OUI | 现场安装包 54,390 条前缀 | 厂商参考 |
| 设备正则规则 | 103 条，confidence 0.70–0.96 | 主机名、UA、TLS、HTTP 等定向规则 |
| 型号库 | 89 条，最长前缀匹配 | 型号代码 → 品牌/型号/系列/类型 |
| 服务类型目录 | 20 条 | mDNS 服务 → 能力/产品线 |
| 厂商先验 | 87 条，≤0.80 | 静默设备类型线索 |
| 路由器规则 | 78 条，likely 60 / confirmed 80 | 路由器/AP/交换机角色 |
| 多源目录 | 22,008 条源规则；12,120 条 converted；745 条 self_report；11,375 条 auxiliary | 协议/型号/系统规则与证据 |

多源目录其余条目包括 3,974 条 unsupported_input、1,956 条 unsupported_syntax、901 条 duplicate、4 条 invalid_data。它们不会静默消失：状态、原因和来源都在目录里可见。

许可来源包括 Rapid7 Recog（BSD-2-Clause）、Satori（GPL-2.0）、LibreNMS（GPL-3.0）、WhatWeb（GPL-2.0）、OpenWrt Table of Hardware（CC-BY-SA-4.0）、p0f（LGPL-2.1）、Nmap（NPSL）和 Fingerbank（商业服务）。如果要把 GPL/NPSL 规则与闭源程序一起分发，需要先做法务审查，必要时用独立数据文件或独立进程隔离。

每次识别结果写入 fingerprint_version；规则升级先离线回放，比较类型/OS/冲突变化，再在影子环境验证，最后切换。回放命令 fingerprint-replay 支持基线包与 Fingerbank 刷新包的对比，只输出聚合变化。

## 6. 归属与资产关联

发现记录可以独立存在，也可以关联到终端画像。关联条件是可逐条核对的：

1. 管理员为采集源填写 identity_sensor、identity_campus、identity_vlan、identity_vrf，且观察的配置版本与当前源版本一致。
2. 观察的 MAC 是单播、非本地管理位（即非随机 MAC），且站点、网络域、VLAN、VRF 与映射完全一致。
3. 在事件时刻，身份传感器和园区内存在唯一有效的 DHCP ACK，IP 对应的租约属于同一 MAC。
4. 租约在事件时刻仍然有效；事件之后没有 stop、没有换绑到其他终端，也没有多个终端同时占用同一 IP。
5. 关联有效期取租约到期和观察有效期的较小值；后续换绑立即使旧关联失效。

不满足任一条，就留在独立发现区。系统不会写回 DHCP，不会修改租约，也不会用主机名/IP 做兜底匹配。IP 级的 SIP 话机如果没有 MAC/租约证据，就只停留在 IP 级。

## 7. 主动发现与 SNMP

### 7.1 主动扫描

主动扫描默认关闭，启用前需要允许探测的 CIDR、禁止探测的网段、探针接口、协议清单、维护窗口和授权。

| 约束 | 值/行为 |
|---|---|
| 目标上限 | 4,096 个地址 |
| IPv4 最小范围 | 前缀不短于 /20；网络地址和广播地址不作为目标 |
| 并发 | 每节点最多 16 个目标并发 |
| 速率 | 全任务每秒 10 个请求 |
| 超时/重试 | 单请求 2 秒；一次重试 |
| 扫描并发 | 每节点同一时间最多一个扫描任务 |
| 本地链路 | ARP/NDP 只允许指定接口直连网段 |
| 敏感网段 | 禁用 IPP/SSDP/ONVIF 等应用层探测 |
| 定时 | 手动试扫完成当前配置版本后才允许每日定时 |
| 结果语义 | 有响应才生成事件，TTL 300 秒，置信度 0.5 |

主动探测的网络安全边界：XML 禁止 DTD、响应限制 1 MiB、2 秒超时、禁止重定向和代理；IPP 只发 Get-Printer-Attributes，不发 Print-Job；IPPS 使用系统信任链；ONVIF 只发标准 Probe/GetDeviceInformation。

当前 204 和 184 的只读记录均为 discovery_sources=0、discovery_scan_profiles=0，主动发现未启用。

### 7.2 SNMP 基础设施采集

SNMP 是独立入口，适合交换机和 AP 的 FDB、邻居表、LLDP 邻居和系统描述：

- 只读 v2c 必须显式选择；v3 使用 authPriv（SHA-256/AES），口令长度至少 8 位。
- 默认轮询 300 秒，可配置 60 至 86,400 秒；单表最多 100,000 条。
- 表读取失败标记为不完整，不因为空表断言设备离线或不支持。
- FDB 的端口是路径线索，不是终端直连证明；Q-BRIDGE 的 FDB ID 通过 dot1qVlanFdbId 映射，多个 VLAN 共用同一 FDB 时 VLAN 留空。
- 邻居表提供 IP-MAC 绑定，但仍需作用域和租约校验才能用于终端归属。
- LLDP 邻居的 chassis/port/capabilities 用于基础设施角色和拓扑线索；没有明确管理地址时保留 MAC 主体，不用同源转发的用户 IP 补写管理地址。

## 8. 查询与运行

### 8.1 查询

设备列表只读已生成的当前状态和检索索引，不在请求内重建全网状态：

- 列表按筛选、排序和末行键生成不透明游标；统计独立接口，带统计时间。
- IP、MAC、账号走精确索引；名称和综合文本走专用检索字段；少于三个字符走前缀，三个及以上支持包含匹配。
- 详情首包返回当前摘要；证据、历史、关联各自限定范围分页。
- 当前状态返回处理时间、结果版本、状态；处理中、失败、延迟、空结果分别表达。

### 8.2 可靠性

- 原始事件先写 ClickHouse，再进入投影；投影失败不回滚原始事件。
- 批次有稳定 ID、记录数和校验值；消费进度只在持久确认后推进。
- 事实按事件键、语义哈希和版本幂等；同键不同内容记为冲突，不静默覆盖。
- worker 使用租约；过期租约不能推进游标；失败保留原游标重试，不跳过任务。
- 队列满或积压超限时显式报错或停止，不静默丢弃。

### 8.3 现场状态

2026-11-10 的 204 记录：

| 指标 | 数值 |
|---|---:|
| 终端画像 | 8,698 |
| 明确类型 | 约 6,781 |
| 无明确类型 | 1,917 |
| 手机 | 4,222 |
| 无线接入点 | 925 |
| 平板 | 651 |
| 桌面终端 | 623 |

2026-11-06 的发现列表 24 小时窗口为 3,795 个作用域身份（明确类型 1,919、待核实 390、冲突 0、过期 1,486）；同日 17:59 为 3,912。这些是滚动窗口内的可见身份，不是固定盘点。

被动来源的最新观测计数（2026-11-09）：ARP 6,981、DHCP 5,489、NDP 5,148、TTL 2,309、DNS-SD 465、SNMP 155、HTTP 设备 138、WS-Discovery 131、SSDP 55、TLS 设备 38。

## 9. 当前实现边界与下一步

| 项目 | 当前状态 | 下一步 |
|---|---|---|
| 被动发现 | ARP/NDP/DHCP/DNS-SD/SSDP/WS-Discovery/SNMP/HTTP/TLS/SIP 已入库；RTSP 已接入待流量 | 补 SMB/NTLM、IPv6 扩展头/分片、工控/楼控 |
| 主动发现 | 代码具备，204/184 均未启用 | 现场提供只读 SNMP、允许网段、探针接口和授权后试扫 |
| 设备身份 | 以作用域 + IP/MAC 为键，IP 优先 | 研究稳定的端点身份层，用租约链、802.1X、AP 关联做受控合并 |
| 覆盖率 | 没有镜像覆盖率分母 | 建立人工标注集和 capture-coverage 度量 |
| 处理路径 | 204 批处理主链路；184 流式路径并行 | 先在影子环境比较，再逐步收敛 |
| 容量 | 204 PostgreSQL 2 vCPU / 6 GB、HDD；高峰期游标滞后 | 按真实负载扩资源、换 SSD、调批大小和索引 |

下一步按优先级：

1. 建立按品类、按镜像位置分层的人工标注集，先量出覆盖率和类型/型号准确率。
2. 接入只读 SNMP 和 AP 关联，补齐端口路径和稳定身份证据。
3. 统一 204 批处理与流式路径的类型/置信度语义，先影子比较再切读。
4. 按现场真实负载验证查询延迟、游标延迟和归档容量。

## 附录 A：关键实现位置

| 主题 | 代码/文档 |
|---|---|
| 观察模型、设备键、TTL、类型线索 | model.go |
| 标准事件适配、DHCP/ARP/NDP 语义 | standard_event.go |
| 被动抓包解码、mDNS/SSDP/LLDP | passive.go、frame_decoder.go |
| 发现类型规则、产品规则 | iot_classification.go、product_rules.go |
| 终端归属与租约校验 | identity.go |
| 主动扫描与安全边界 | active.go、active_repository.go |
| SNMP 表采集 | snmp.go |
| 204 被动物化器 | passive_discovery_materializer.go |
| 流式投影与当前态 | stream_projection.go、stream_state.go |
| 段日志与 lane 确认 | journal.go、stream_writer.go |
| 识别输入、方向/协议白名单、证据引用 | evidence.go |
| 识别流水线、OUI/规则/先验/多源合并 | library.go |
| 维度置信、覆盖与冲突 | adjudication.go、network_clue.go |
| 多源规则目录与来源许可 | multisource.go |
| 型号库、服务类型、厂商先验 | model_catalog.go、service_types.go、prior.go |
| 路由器独立规则集 | router.go |
| 识别物化与摘要 | recognition_materializer.go、identity.go |
| 识别离线回放 | cmd/fingerprint-replay/main.go |

## 附录 B：术语

| 术语 | 含义 |
|---|---|
| 作用域 | 传感器、站点、网络域、VLAN、VRF、接口的组合 |
| 观测 | 某个时刻的一条协议证据 |
| 事实 | 同一业务键下可更新、可撤销的语义 |
| 当前设备 | 作用域内由当前有效事实聚合出的展示单元 |
| 强类型 | 经类型化协议或产品规则匹配得到的设备类别 |
| 线索 | 自报、OUI、主机名、TTL 等辅助信息，不单独定论 |
| 过期 | 有效期已过，但历史证据仍保留 |
| 撤销 | TTL 0 或显式 goodbye，表示事实不再当前有效 |
| holdback | 读取水位落后当前时间的保护窗口 |
| 识别维度 | 品牌、型号、系列、设备类型、操作系统等独立输出 |
| 方向白名单 | 字段只允许在 device/server/client 某一方向参与结论 |
| self_report | 设备/协议自报规则，可参与识别结论 |
| auxiliary | 辅助规则，只作证据展示，不改变结论 |
| 型号库 | 型号代码到品牌/型号/系列/类型的精确或最长前缀映射 |
| 厂商先验 | 厂商产品线对设备类型的弱先验，≤0.80 |

## 附录 C：数据口径

- 文中设备数均指当前作用域内的可见设备单元，不是物理台数。
- 终端画像数、发现列表身份数、最新观测数是三个不同口径，不能相互加减。
- 现场数字引用自 docs/current-work.md 的只读记录；本文没有重新执行现场查询。
- 代码行为引用仓库 c3e1c600；204 部署版本与仓库 HEAD 可能不同。
- 识别目录规模按仓库 internal/fingerprint/data 的 status 统计；安装包筛选后的可执行数量可能不同。
- 42 条设备标签样本是回归样本，不是现场人工标注集。
