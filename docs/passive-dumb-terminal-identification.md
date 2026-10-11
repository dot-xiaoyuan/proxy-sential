# 镜像流量被动识别哑终端：能力边界与落地路径

本文回答一个问题：不装探针、不做主动探测，只用镜像流量，能把哑终端识别并记录到哪一步。结论用于选型与排期，不是验收记录；所有覆盖率数字都是待现场标定的估计值。

## 一、结论摘要

按"能作为台账事实"的标准分四级：

| 级别 | 能确定的内容 | 需要的信号 | 纯被动可行性 |
| --- | --- | --- | --- |
| A 事实 | MAC、厂商、IP 历史、接入传感器/VLAN、首次与最近观测、通信对端与端口、在网时长形态、是否出现过认证流量 | DHCP 租约、ARP、LLDP/FDB、conn | 可达。已具备大部分采集通道 |
| B 大类 | 打印机/复印、摄像头与 NVR、VoIP 话机、无线 AP、瘦客户机、门禁一卡通、工控与楼控、UPS/PDU、路由或 NAT | 自报协议 + 协议栈指纹，至少两个独立来源 | 大部分可达，覆盖率取决于镜像位置 |
| C 型号与固件 | 打印机型号、摄像头型号、话机型号与固件、AP 型号、部分 IoT 型号 | mDNS TXT、UPnP 描述、LLDP、HTTP Server 头、RTSP/SIP/ONVIF UA、SNMP sysObjectID | 集中可达，但只覆盖"愿意自报"的品类 |
| D 做不到 | 精确 OS 版本、序列号（除自报）、NAT 后物理台数、静默固定 IP 设备、加密后的应用内容 | — | 纯被动不可达，需人工台账或一次性主动确认 |

一句话判断：**哑终端比手机和电脑更容易被动识别，因为它们的协议栈常年不变、不做 MAC 随机化、而且大量使用自报协议；难点不在算法，在于镜像位置和归属链路。**

覆盖率的量级预期（必须用现场人工标注集校准，不得直接引用）：

| 镜像位置 | 设备大类覆盖率 | 型号覆盖率 |
| --- | --- | --- |
| 接入交换机上联（带 VLAN tag） | 60%–85% | 25%–50% |
| 汇聚/BRAS 侧 | 40%–60% | 10%–25% |
| 仅出口镜像 | 20%–40% | 低于 15% |

差距几乎全部来自链路本地多播（mDNS、SSDP、LLDP/CDP、NBNS、DHCP 广播）是否在镜像范围内，而不是来自规则数量。

上表是工程估计，没有权威公开数字可以直接引用：公开研究里没有真实校园或企业网"可分类设备占比"的直接百分比。已有的实测都偏悲观——校园骨干流量上 p0f 召回 49.1%、精确率 64.1%（见 L1 一节），复现评测显示文献平均 F1 超过 96% 的结果在加入非 IoT 设备后平均下降约 27%，**未知设备的检测 F1 会从 0.949 断崖式跌到 0.081**（[Gupta et al., ACSAC 2025](https://doi.org/10.1109/ACSAC67867.2025.00071)）。所以对外不能承诺"识别率 95%"；真问题是覆盖率与漂移，而不是已识别样本的准确率。

## 二、本仓库现状盘点

已经具备、不需要重建的资产：

| 能力 | 位置 | 状态 |
| --- | --- | --- |
| 标准事件与适配层 | `internal/normalized`、`internal/adapter/zeek`、`internal/adapter/suricata` | conn/dns/http/ssl/x509/lldp/ssdp/snmp/dhcp/software 已解析；Suricata 补 ja3/ja4、证书 subject/issuer/SAN |
| 设备信号模型 | `internal/store/device.go` | 已有 kind：mac、oui_vendor、device_name、os_family、model、brand、device_type、dhcp_vendor_class、dhcp_requested_options、software_name/version、user_agent、ja3、ja4、ttl、ipid、domain；带 strength/confidence/weight/event 引用 |
| 原始抓包通道 | `internal/devicesignal` | AF_PACKET + 内核 BPF，已过滤 ARP、LLDP、CDP、IEEE 1905、DHCP、NBNS、mDNS、LLMNR、SSDP、SNMP、VRRP/HSRP；另一路只取 SYN 前 128 字节 |
| 指纹库 | `internal/fingerprint` + bundle v4/v5 | IEEE OUI、uap-core、Fingerbank、设备域名与品牌推测、路由规则 |
| 服务能力标签 | `internal/discovery/model.go` | mDNS 服务类型 → printing/scanning/casting，SSDP → media_rendering/routing，LLDP → 类型线索；SSDP 描述已解析 manufacturer/model_name/model_number |
| 名称与租约 | DHCP hostname/FQDN、mDNS 响应，经唯一有效租约归属 | 已有证据表、有效期与换绑规则 |
| 多播与自报采集 | `assets/zeek/*.zeek` | DHCP option 55/60 + 租期、mDNS A/AAAA/SRV、NBNS、LLMNR、SNMP sysDescr |
| 共享多样性信号 | `internal/sharedaccess` | ua_os、ttl_path（含推测初始 TTL 与跳数）、tls_stack(ja4)、dhcp_stack，带来源族去重 |

三个断点，按影响排序：

1. **归属断点**：2026-09-08 基线显示近七天 4,599,445 条 DNS/TLS/HTTP/QUIC 事件里，直接携带终端 ID 的为 0。信号都在库里，但没有一条落到设备上。这是最大的单点问题，其它工作在此之上才有意义。
2. **规则断点**：`internal/fingerprint/data/device_rules.json` 只有 9 条规则，`inferDeviceFromDHCP` 是硬编码分支，覆盖 iPhone/iPad/Apple/Android/Windows/ChromeOS/Linux。哑终端所在品类（打印、视频、话机、AP、门禁、工控）基本没有规则。现场 127 个终端里整机型号识别为 0。
3. **集成断点**：`internal/devicesignal` 的原始抓包只喂路由识别，`internal/discovery` 的能力标签只进独立发现读模型，两者都没有汇入终端画像。采集通道已经抓到了本文需要的那批报文，只是消费端只取路由相关字段。

现场已有的两条正面事实，说明上限不是"看不到"：

- 2026-09-20 部署后，Zeek 在镜像口收到了真实 DHCP 与 mDNS 响应。链路本地多播可见，意味着当前镜像位置在接入侧或能看到接入网段的多播，L2 自报信号可用。这是覆盖率估计取乐观区间的前提，仍需 Phase 0 用完整 24 小时数据确认比例。
- 同时存在 210 条主机名证据未归属（188 条 IPv6、22 条 IPv4）与 16 条服务名证据未归属。信号采到了，卡在归属，尤其是 IPv6。这与断点 1 是同一个问题。

## 三、被动信号地图

### L0 链路与地址

| 信号 | 取值来源 | 能确定 | 开源实现 | 本项目落点 |
| --- | --- | --- | --- | --- |
| MAC OUI | IEEE MA-L/MA-M/MA-S | 厂商（不是品牌、不是型号） | Wireshark manuf、IEEE 公开清单、macaddress.io | 已有，bundle v4 |
| 本地管理位置位 | MAC 第一字节 bit1 | 是否随机化 MAC，用于排除手机与新 Windows，反向支持"哑终端"判断 | 通用判据 | 已有 `IsRandomizedMAC` |
| 被动 ARP 学习 | ARP 广播/请求 | IP↔MAC 表，不依赖 SNMP 与 DHCP | arpwatch 思路、Zeek arp 日志 | 报文已进 BPF，未产出信号 |
| IPv6 EUI-64 IID | fe80::/10 与全局地址低 64 位 | 无 L2 也能反推 MAC | 通用算法 | 缺 |
| DHCPv6 DUID-LL/LLT | DHCPv6 SOLICIT/REQUEST | 无 L2 也能拿到 MAC，且跨 VLAN 稳定 | Zeek 自带 `base/protocols/dhcpv6`（Spicy 实现） | 分析器可用，适配器与信号未接，高性价比 |

### L1 协议栈指纹

| 信号 | 取值来源 | 能确定 | 开源实现 | 本项目落点 |
| --- | --- | --- | --- | --- |
| TCP SYN 选项序列、MSS、窗口、窗口缩放、DF、TTL、IPID | 首个 SYN / SYN-ACK | OS 家族与栈实现，嵌入式精简栈（LwIP、uIP、嵌入式 Linux）区分度高 | p0f v3（LGPL-2.1，3.09b/2014 后停更）、Satori（GPL-2.0，活跃）、Recog（BSD-2，自身不抓包） | 只采了 TTL 与 IPID 两个标量；SYN 前 128 字节的通道已存在 |
| TCP timestamp | SYN 与后续包 | 开机时长、时钟偏移，区分虚拟机与物理设备 | p0f uptime 模块、Kohno 时钟偏移法 | 缺 |
| SSH host key 指纹 | SSH KEX 明文段 | 单设备稳定标识，可跨 IP 追踪 | HASSH（BSD-3）、Zeek ssh.log | 未接 |

协议栈指纹要按真实准确率预期来用，不能按宣传值。2023 年在校园骨干真实流量上的实测：p0f v3 的 OS 名准确率 92.8%，但**精确率 64.1%、召回 49.1%、F1 55.6%，小版本 F1 只有 7.5%**（[Laštovička et al., Computer Networks 2023](https://doi.org/10.1016/j.comnet.2023.109782)）。也就是说 p0f 系只能作为辅助证据，不能作为品类认定的独立来源。

哑终端多用精简协议栈，同一型号的一致性高于 PC，但**指纹会随时间漂移**：同一批设备在无重训情况下设备级 F1 每天衰减 0.01–0.023，第 14 天降到约 0.5（[Kolcun et al. 2020](https://arxiv.org/abs/2011.08605)）。因此"人工确认一次即可长期复用"不成立，必须把标注集复验排进常规运维。

### L2 自报身份（哑终端主战场）

| 信号 | 能确定 | 开源实现 | 本项目落点 |
| --- | --- | --- | --- |
| DHCP option 55/60/61/77/43/93 | 客户端实现、厂商、终端角色；option 43 常用于话机与 AP 的厂商私有字段；option 93 与 TFTP 引导文件名指向瘦客户机与无盘终端 | Fingerbank（无自由再分发的完整离线库）；公开 opt 55/60 库基本不存在 | Zeek 的 `dhcp-options.pac` 已解析 55/60/61/77/43，但**只在脚本层 `DHCP::Options` 可见，默认 dhcp.log 不落**；**option 93 完全未解析**，需要自解析。项目已有 55/60 脚本，扩 43/61/77 是改脚本，93 要在原始通道解 |
| mDNS/DNS-SD 服务类型与 TXT | 品类与服务能力，TXT 里的 `model=`/`fw=`/`md=` 直接给型号与固件 | **Zeek 无原生 mDNS/DNS-SD 分析器**（多播 DNS 走 DNS analyzer，且 9.1 起不再配对 query/response），社区包 `zeek-plugins/mdns`（BSD-3）2022 年后停滞 | 项目已自写 `local-device-signals.zeek` 补上 A/AAAA/SRV，**缺 TXT 与服务类型语义库**；现有映射只有 ipp/ipps/printer/uscan/airplay/raop/googlecast 七项。服务类型表必须自建 |
| SSDP/UPnP 描述 | deviceType 给品类，description XML 给 manufacturer、modelName、modelNumber、serialNumber、UDN | Zeek 无原生；社区包 `nttcom/zeek-parser-SSDP-COM`（BSD-2，2023 后停滞）；项目已自实现 | 已实现被动 SSDP 与描述读取；UDN 未作为稳定标识使用。SSDP 的 `SERVER` 头含 OS 与版本，是摄像头与 AP 的强信号 |
| LLDP/CDP | 邻居自报的型号、固件、序列号、管理地址、端口、能力（bridge/WLAN AP/telephone/router） | **Zeek 无原生 LLDP/CDP 分析器**；lldpd（ISC，活跃）可被动收 LLDP/CDP/EDP/FDP/SONMP；tshark 有原生 `lldp.*`/`lldp.med.*`/`cdp.*` dissector，最适合离线跑镜像；cdpr 仅 CDP 且 2011 年后停更 | 项目已在 `internal/devicesignal/control.go` 自解析 LLDP 帧，另有 `zeek-lldp` 输入通道。**Phase 0 需核对该日志的实际生产者**：若来自社区包，按停更组件处理 |
| WS-Discovery（3702） | ONVIF 摄像头、WSD 打印机 | **未找到成熟的开源被动解析器** | 需自建。报文本身是明文 XML，成本可控 |
| NBNS/LLMNR | 主机名与工作组，Windows 系终端 | Zeek 自带 DNS analyzer 覆盖 137/5355；项目已有脚本 | 已采查询名；响应中的名称未全部利用 |
| SMB1 SessionSetup 的 NativeOS/NativeLANManager、SMB2/NTLMSSP CHALLENGE 的 AV_PAIR | Windows 版本、计算机名、域名，对 POS、瘦客户机、自助机很关键 | Zeek `ntlm.log` 有 username、hostname、domainname、server_nb_computer_name、server_dns_computer_name | 未接。**脚本层不落 OS 版本**，NTLM AV_PAIR 与 SMB1 NativeOS 需自解析；**只保留元数据，不落 challenge/response 等凭据材料** |
| SNMP 响应 sysDescr/sysObjectID/sysName | sysObjectID 是企业 OID，可精确定位型号 | librenms、Zabbix 模板、公开 OID 库 | 已排除 community 并保留 display_string；sysObjectID 未提取 |
| HTTP Server/Title/favicon hash/Realm | 打印机与摄像头常在 Server 头里直接写型号与固件；favicon hash 可聚类同型号 | Shodan favicon 算法（mmh3）、FingerprintHub（MIT，活跃）、fav-up（MIT） | 已采 server/title；favicon hash 缺。注意 favicon 随固件变化，CDN 共享会误报 |
| TLS 证书 subject/issuer/SAN | 自签证书的 CN/O/OU 常含厂商与型号，DER 指纹可聚类同固件 | Suricata 已提取；JA3/JA3S（BSD-3）与 JA4 client（BSD-3）可商用 | 已有 ja3/ja4（来自 Suricata，不是 Zeek）。**没有公开的"指纹→设备型号"权威库**，需自建，且同芯片方案会互相污染 |
| RTSP、SIP、ONVIF UA、IPP/LPD | UA 字符串常带完整型号与版本（话机、摄像头） | Zeek 原生 SIP analyzer（`sip.log` 有 user_agent）；**RTSP 无 Zeek 原生解析**，且没有公开的被动 RTSP UA 库（cameradar/CamSniff 等均为主动扫描） | 未接；SIP 是话机品类最可靠的单条规则来源，RTSP/ONVIF 字符串需自建规则 |
| EtherNet/IP ListIdentity、BACnet、Modbus、PROFINET DCP | 明文的厂商、设备类型、产品名、固件版本、序列号 | ICSNPP（CISA/INL，**BSD-3，活跃**）：`cip_identity.log` 被动给出 vendor_name、device_type_name、product_code、revision、serial_number、product_name；BACnet `bacnet_property.log` 可给 model-name 与 firmware-revision | 未接。**唯一能做到"厂商+型号+固件"级别的纯被动路径**。PROFINET DCP 与 Modbus MEI 覆盖有限，DCP 无成熟被动实现 |
| DICOM A-ASSOCIATE | AE title 与实现 UID，医疗影像设备 | 需自建 | 缺，按现场是否需要决定 |

### L3 行为与身份判据

| 判据 | 说明 |
| --- | --- |
| 是否出现过认证流量 | EAPOL、Portal 跳转、认证客户端心跳。从不认证是判定哑终端最有力的缺席证据 |
| 是否出现过浏览器与门户探测 | `captive.apple.com`、`connectivitycheck.gstatic.com`、`msftconnecttest.com` 等 DNS 请求意味着设备带完整 OS 与浏览器。这类域名一出现即可排除哑终端 |
| 通信对端形态 | 只与一台 NVR 单向上传即摄像头；只做 NTP/SNMP 周期心跳即基础设施类；对端分散且有人工交互特征则更接近 PC |
| 周期与带宽形态 | 打印偶发突发、视频恒定码率、IoT 低速率长连接。用于佐证品类，不作为唯一依据 |
| 与 DHCP 租约时间线结合 | 产出"设备的一生"：IP 变更、VLAN 变更、接入点变更。这是所有其它信号的归属锚点 |

### L4 融合与置信

沿用路由识别已经验证过的原则，不另造一套：

- 来源家族去重：Zeek 与 Suricata 对同一协议的镜像只算一个来源。
- OUI 单来源只能给"厂商参考"，不得推导品类或型号。
- 品类认定要求至少两个独立来源，其中至少一个是自报协议（mDNS/SSDP/LLDP/SIP/RTSP/HTTP Server/SNMP）。
- 冲突保留并展示，不合并。例如 OUI 为通用网卡厂但 mDNS 自报 Apple 服务，按冲突处理。
- 每条结论带证据引用、规则版本、时间窗口和解释文本，默认窗口 24 小时，超期失效。

### 典型品类逐项判定

"重点是哑终端"落到具体品类时，主判据和能到的粒度差别很大：

| 品类 | 主判据（按可靠性从高到低） | 能到型号 | 难点 |
| --- | --- | --- | --- |
| 网络打印机/复合机 | DHCP option 60、mDNS `_ipp`/`_printer` + TXT、SSDP 描述、HTTP Server 头（多数厂商直接写型号与固件）、LPD 队列名、SNMP sysObjectID、9100 端口 | 可以，且最可靠 | 休眠期流量稀疏，需要长窗口与负证据处理 |
| IP 摄像头/NVR | ONVIF/WS-Discovery（需自建解析）、RTSP UA 与 Server 头（需自建规则）、HTTP Title、TLS 自签证书 CN、UPnP deviceType、554 端口 | 品牌稳，型号依赖自报 | 大量私有协议设备只剩端口与厂商 OUI |
| VoIP 话机 | SIP UA（常含完整型号与固件）、LLDP-MED、CDP、DHCP option 60/43、TFTP 配置文件名 | 可以，粒度最好 | 要求镜像能看到 SIP 与 LLDP |
| 无线 AP 与 AC | LLDP/CDP、CAPWAP、SNMP sysObjectID 与 sysDescr、DHCP option 60、管理面指纹 | 可以 | 属基础设施角色，项目已有规则禁止其进入普通终端统计 |
| 门禁/一卡通/考勤 | 与固定服务器的长连接与私有端口、SNMP、NBNS 主机名 | 基本到不了 | 靠服务器网段与端口聚类，只能给"同类终端"结论 |
| 瘦客户机/无盘终端 | DHCP option 93 + TFTP 引导文件名、PXE、SMB/NTLM、RDP/PCoIP 行为 | 型号较难，OS 家族可以 | 行为最接近 PC，是否算哑终端需要业务口径 |
| 信息发布屏/投影/中控 | mDNS、SSDP、HTTP 管理面、私有协议 | 品牌可以，型号弱 | 厂商私有协议为主 |
| 实验室仪器/工控/楼控 | EtherNet/IP CIP Identity、BACnet、Modbus MEI、周期轮询 | 可以，协议自带厂商、产品名与固件版本 | 需要 ICSNPP（BSD-3）；一旦可见准确率最高。PROFINET DCP 无成熟被动实现 |
| UPS/PDU/环境监控 | SNMP sysObjectID 与 sysDescr、周期心跳 | 可以 | 依赖 SNMP 响应在镜像内可见 |
| 宿舍消费 IoT（电视、音箱、扫地机） | mDNS TXT、SSDP、域名生态（已有品牌推测能力）、QUIC/TLS 指纹 | 品牌可以，型号部分 | 以云连接为主，本地自报少 |

判定"是不是哑终端"必须正反结合：正面证据（自报协议、固定协议栈、MAC 不随机）只能说明它是什么品类；反面证据（从不出现认证流量、从不出现浏览器与门户探测域名）才能说明它不是有人值守的 PC 或手机。

## 四、四条优先级高于"加规则"的前置条件

1. **镜像位置与覆盖度量**。链路本地多播不会离开接入网段，镜像点太靠上就看不到。需要把现有 `capture-coverage/v1` 事实契约从"共享窗口是否完整"扩展为"识别覆盖率的分母"：本网段应有多少终端、其中多少报文进了镜像。没有这个分母，任何覆盖率数字都是假的。
2. **MAC 归属回填**。这是最大的单点杠杆，且成本很低：
   - Zeek 加载 `policy/protocols/conn/mac-logging.zeek`，conn 日志即带 `orig_l2_addr`/`resp_l2_addr`，而适配器已经在读 `orig_l2_addr`，无需改代码；
   - 用已建成的 DHCP 租约时间线，把只有 IP 的事件按"传感器 + 园区 + IP + VLAN + 事件时刻唯一租约"回填 `subject.mac`；
   - 补 DHCPv6（Zeek 自带分析器）的 DUID 与 IPv6 EUI-64，覆盖双栈哑终端。
3. **哑终端品类词表与信号 kind 扩展**。现有 device_type 词表是 mobile/tablet/desktop/laptop/printer，需要按现场真实品类扩展（camera、nvr、voip_phone、access_ap、thin_client、access_control、industrial、ups、display、printer、server、router），并新增 kind：`service_type`、`upnp_device_type`、`lldp_capability`、`sip_ua`、`rtsp_ua`、`smb_native_os`、`snmp_sysoid`、`tcp_options`。
4. **静默设备的人工核查队列**。固定 IP、不发 DHCP、不响应多播、只有单向业务流的设备，纯被动只能拿到厂商和 IP。这类必须显式呈现为"证据不足待人工确认"，不能靠规则补造结论。项目已有的"缺失字段留空、推测不升级为结论"规则在这里同样是硬约束。

## 五、落地路线

Phase 0（度量，不做功能）
- 在接入侧镜像上跑一次 24 小时采样，统计 DHCP、mDNS、SSDP、LLDP、NBNS、SNMP 的可观测比例。
- 产出人工标注集：每个品类至少 10 台真实设备，记录 MAC、来源、人工确认的品类与型号，作为唯一准确率基线。
- 扩展 capture-coverage 事实，得到识别覆盖率的分母。

Phase 1（零新增采集通道，只扩解析与规则）
- Zeek 侧：加载 `policy/protocols/conn/mac-logging.zeek`；扩 DHCP 脚本到 option 43/61/77（Zeek 已解码，只是默认不落日志），option 93 与 mDNS TXT 需在脚本层或原始通道自解析；接 Zeek 自带的 smb/ntlm、ssh、sip 分析器。**Zeek 没有原生 mDNS/DNS-SD、LLDP/CDP、RTSP、WS-Discovery 解析**，这几项走项目已有的自写脚本或 `internal/devicesignal` 原始通道；若继续依赖 `zeek-lldp` 输入，先核对它的实际生产者。
- 有工控与楼控终端时并行接入 ICSNPP（BSD-3，活跃）：`cip_identity.log` 被动给出厂商、设备类型、产品名、固件版本、序列号，是唯一能到"厂商+型号+固件"的路径。
- 适配器侧：把新增字段映射进标准事件 payload，保持风险引擎不接触采集器原始对象。
- 指纹库 v6：p0f 签名子集（仅作辅助证据）、mDNS 服务类型与 TXT 键表、DHCP option 60/43 厂商表、HTTP Server 头表、SIP/RTSP UA 表、SNMP sysObjectID 前缀表。全部走现有离线包导入、校验、版本切换与回滚流程。opt 55/60 与 mDNS 服务类型没有可用的公开离线库，必须自建并纳入版本管理。
- 把 `internal/discovery` 的服务能力标签改为消费标准事件，汇入设备信号，而不是维护两套映射。

Phase 2（归属与画像）
- MAC 归属回填与租约时间线关联。
- 终端画像增加品类、能力、型号、固件字段与独立置信度；缺字段留空。
- 冲突与来源族去重复用路由识别的实现。

Phase 3（原始抓包指纹）
- 在已有的 `internal/devicesignal` 内核 BPF 通道上增加 p0f 式 SYN 指纹与 TCP timestamp 解析，产出 `type=device` 标准事件。不新建采集框架，不把解析放进热路径。

Phase 4（运营闭环，只读优先）
- 哑终端台账页面：品类列表、证据链、待人工确认队列、批量人工确认。
- 与准入联动保持只读：识别结果可供人工核查与白名单参考，不自动加白、不自动处罚、不影响风险分与设备数量统计。

## 六、验收指标与红线

必须区分并分别报告的指标：

- 品类覆盖率 = 得到品类的设备数 / 应识别设备总数（分母来自 Phase 0 的覆盖度量）。
- 品类准确率 = 人工标注集中判定正确的比例，按品类分别报告，不给单一总体数字。
- 型号覆盖率与型号准确率分开；型号只在自报品类上统计。
- 误标率与冲突率；`OUI-only 误定类`必须为 0。
- 静默设备比例，即只有厂商与 IP 的设备占比，这是能力的真实缺口而不是失败。
- 漂移复验：用同一标注集按季度复测品类与型号准确率。指纹会衰减，没有复验机制的准确率数字只能代表发布当天。

红线：

- 不把 MAC 厂商当作品牌或型号；不把服务公告当作整机型号确认。
- OUI-only、单来源、关联歧义、强冲突均不得升级为品类或型号。
- 证据不足留空，不显示占位文案；推测与确定信息分开展示并保留依据。
- 哑终端识别是资产事实，与防代理风险解耦，不进入风险分、设备数量、处罚动作。
- 不在哑终端上做主动探测；被动采集不改变现场网络行为。
- 安全边界沿用现有实现：SNMP community 在日志层排除、UPnP XML 禁 DTD 且不跟随重定向、SMB 只保留 AV_PAIR 元数据不留凭据材料。

## 七、开源方法对照与许可证

许可证与维护状态经源码或官方页核对，结论随本文维护。

| 组件 | 许可 | 维护 | 用途与结论 |
| --- | --- | --- | --- |
| Zeek | BSD-3 | 活跃 | 事件抽取底座。注意它没有 mDNS/DNS-SD、LLDP/CDP、RTSP、WS-Discovery 的原生解析 |
| ICSNPP（cisagov/icsnpp） | BSD-3 | 活跃 | 工控与楼控被动解析，唯一能到"厂商+型号+固件"的纯被动路径 |
| zeek-plugins/mdns | BSD-3 | 2022 年后停滞 | 可参考实现，服务类型语义库仍要自建 |
| nttcom zeek-parser-SSDP | BSD-2 | 2023 年后停滞 | 项目已有自实现，不必引入 |
| lldpd | ISC | 活跃 | 被动收 LLDP/CDP/EDP/FDP/SONMP，可取 chassis、port、system description、LLDP-MED 类型 |
| tshark | GPL-2 | 活跃 | 离线镜像上 `-T fields -e lldp.*` 直接出结构化字段，用独立进程调用 |
| p0f v3 | LGPL-2.1 | 3.09b（2014）后停更 | 指纹库已停更 12 年，仅作辅助证据 |
| Satori | GPL-2.0 | 活跃 | 复刻 p0f v3 指纹库；GPL 有传染性 |
| Recog（Rapid7） | BSD-2 | 活跃 | 指纹归一化编排，自身不抓包 |
| nmap 指纹库 | NPSL 0.95 | 活跃 | **不要引入**，见下方红线 |
| JA3 / JA3S（Salesforce） | BSD-3 | — | 可商用，可随包分发 |
| JA4（仅 TLS 客户端） | BSD-3 | — | 可商用，项目当前使用的正是这一项 |
| JA4S/JA4L/JA4H/JA4X/JA4SSH 等 JA4+ | FoxIO License 1.1 | — | **非 OSI 许可，禁止 monetization，专利 pending** |
| HASSH（Salesforce） | BSD-3 | — | SSH 客户端与服务端指纹 |
| FingerprintHub | MIT | 活跃 | Web 指纹与 favicon 规则 |
| fav-up | MIT | — | favicon 哈希提取 |
| Hfinger | GPL-3.0 | 活跃 | HTTP 请求指纹，许可坑 |
| Arkime | Apache-2.0 | 活跃 | 全量 PCAP 索引与会话检索，适合做证据底座 |
| NetBox | Apache-2.0 | 活跃 | IPAM/DCIM，是台账的落地目标 |
| NetworkMiner | GPLv2 | — | 被动主机的现成参考；其 OS 指纹库来自 Satori 与 p0f |
| Kismet | GPL-2 | 活跃 | 无线导向，接不了有线镜像 |
| Nzyme | SSPL | 活跃 | 架构可参考，代码不要内嵌 |
| nPrint | Apache-2.0 | 活跃 | 统一流表示 |
| nPrintML | Apache-2.0 | 2024 年后停滞，仅支持 Python 3.6–3.8 | 论文里的设备指纹是**主动** Nmap 式探测，被动侧只有 OS 识别 |
| FlowPrint | MIT | 2022 年后停滞，原仓库已 404 | 指纹对象是移动应用而不是设备，平均 recall 约 54%，且要求训练与测试同网 |
| 数据集 | — | — | YourThings 是设备数据集（约 45 台/6 类，许可未标注）；IoT-23、CICIoT2023、UNSW-NB15 都是**攻击分类**数据集，不能当设备数据集用 |

许可证红线：

1. **JA4+ 不是开源**。只有 JA4 client 是 BSD-3；JA4S/JA4X 等全部是 FoxIO License 1.1，禁止 monetization。把它当"开源组件"打进对外交付物是最容易踩的雷。
2. **NPSL §3** 明确把"读取或包含 nmap-os-db/nmap-service-probes"的软件定义为 derivative work，分发物须整体 NPSL+GPL。不要把 nmap 指纹库打进发行包。
3. **SSPL（Nzyme）** 非 OSI 认可，作为对外服务提供会触发整栈开源义务。
4. **GPL 传染**：Satori、Hfinger、cdpr、NetworkMiner 若内嵌或链接进闭源采集器有传染性，用独立进程加文件或管道（arm's length）隔离。
5. **Fingerbank** 当前形态有 API 配额与商业条款，没有可自由再分发的完整离线库。项目 bundle 用的是公开历史快照，**不能据此假定新版本具有同样条款**。
6. 安全区：Zeek、ICSNPP、zeek-plugins、lldpd、Recog、JA3/JA3S、JA4(client)、HASSH、Arkime、NetBox、FingerprintHub 均为 BSD/Apache/MIT/ISC。

证据不足时必须承认的边界：

- 没有真实校园或企业网"可分类设备占比"的公开权威数字，只能用 p0f 召回 49.1% 与未知设备 F1 崩塌作间接证据。
- 固件级识别没有通用方案，只有工控自报协议（CIP Identity revision、BACnet firmware-revision）或 HTTP banner 能到。
- 公开的 DHCP option 55/60 离线指纹库、WS-Discovery 与 PROFINET DCP 的成熟被动解析器均未找到，需要自建。
- 结果会漂移，必须定期用标注集复验，不能按"一次调好长期有效"运营。

## 八、不建议做的事

- 不建议第一版上机器学习。现成的两条路线都不成立：nPrintML 事实停更且只支持 Python 3.6–3.8，其论文中的设备指纹是主动探测；FlowPrint 的指纹对象是移动应用而不是设备，平均 recall 约 54%，且要求训练与测试来自同一网络。跨数据集迁移时设备识别 macro-F1 会从 0.68 掉到 0.11–0.14。现场没有标注集、无法解释误判，与"证据化判断"的架构要求也冲突。等 Phase 0 的标注集成型后再评估。
- 不建议把识别结果直接接到白名单或处罚。哑终端识别错误的代价是把一台共享上网设备放行，或把一台打印机下线。
- 不建议为提升覆盖率而放宽来源要求。OUI + 单一服务线索给出的品类，在运营上比空值更危险。

## 九、第一增量实现状态（2026-10-11）

本轮只做归属链路与度量，不加识别规则、不改风险分与共享判定。

已完成：

- **Zeek**：`policy/protocols/conn/mac-logging.zeek` 加入安装器生成的 Zeek 单元与插件预检脚本两处，`conn.log` 开始携带 `orig_l2_addr`。适配器原本就读取 `orig_l2_addr`，Go 侧无需改动，`internal/adapter/zeek/adapter_test.go` 已有该映射断言。
- **归属回填**：`internal/store/protocol_attribution.go` 对 `http`/`tls` 事件按“同传感器、园区、地址与事件时刻的唯一有效 DHCP 租约”归属，派生 `type=device`、`payload.origin=http|tls` 的事件；缺失或冲突租约一律跳过。派生事件只写 PostgreSQL 终端画像与设备信号，不回写 ClickHouse（见 `docs/event-model.md` 的“协议自报归属事件”）。
- **信号与属性闸门**：新增信号 kind `http_server`、`http_title`、`tls_subject`、`tls_issuer`；`identityAttributes` 白名单与 `fingerprint.Signals.Hints` 已放行 `server` 与 `certificate_subject`，其余字段不进入识别输入。
- **度量**：`/api/v1/device-recognition/summary` 新增 `mac_attributed_event_count`、`mac_attribution_rate` 与 `observability`（按 `source_event_type` 统计事件数与带 MAC 数）；OpenAPI 与生成的 TypeScript 类型已同步。
- **现场度量命令**：`proxy-sentinel device-census --postgres-dsn <dsn> --clickhouse-dsn <dsn> [--sensor-id office-30] [--window 24h] [--json]`，只读输出镜像可见 MAC/地址数、持租约设备数、画像覆盖率与按来源可见性。
- **前端展示**：终端页面“识别质量与接入诊断”新增“链路层归属（近 24 小时）X / Y 事件带 MAC · Z%”与按来源可见性条目；当带 MAC 事件为零时给出提示，说明 Zeek 需要加载 mac-logging。样式集中在 `frontend/src/index.css`，数字 `nowrap`、来源名 `overflow-wrap:anywhere`、卡片圆角 8px。三视口（390×844 / 1280×800 / 1440×900）测试与 DOM 探针见 `frontend/tests/e2e/device-attribution-diagnostics.spec.ts`，产物在 `artifacts/passive-attribution-ui/`。
- **测试**：`examples/replay/device-mac-attribution.jsonl` 回放样本；`go test ./...` 通过；隔离 PostgreSQL 集成测试覆盖唯一租约归属、无租约跳过、冲突租约阻止归属、重复批次幂等；前端 `npx tsc --noEmit`、`pnpm build`、25 文件 86 用例与 3 个三视口 e2e 全部通过。

尚未完成（需后续增量或另行授权）：

- Phase 0 的现场 24 小时采样、人工标注集与基线报告需要现场只读访问授权。
- 现场发布与验收未执行；按 AGENTS.md，普通代码修改不自动授权部署，184 才是现场目标。
- Phase 1 解析与规则（DHCP option 43/61/77、mDNS TXT 与服务类型库、SIP/RTSP、ICSNPP）未开始。

已知边界：若现场 Zeek 单元是站点自行维护而非安装器生成，则本轮对 Zeek 脚本列表的改动不会自动生效，需要在站点侧同步同一脚本；`device-census` 的目录计数依赖镜像可见 `subject_mac`，未开启 mac-logging 时该值保持为零，这正是它要暴露的事实。

## 十、30 节点验证记录（2026-10-11）

在开发节点 `192.168.0.30` 上按只读核对 → 预检 → 改动 → 验证的顺序执行，未替换任何二进制、未发布。

采集侧结果：

- Zeek 生效命令行已包含 `policy/protocols/conn/mac-logging.zeek`，服务 active，其他来源不受影响。
- `conn.log` 由 0 行带 `orig_l2_addr` 变为 42/42 行携带，样例 `"orig_l2_addr":"68:1d:ef:54:18:a3"`。
- 用节点上现成的 r105 二进制把同一份 `conn.log` 转标准事件：`read=42 emitted=42 malformed=0`，42/42 条带 `subject.mac`，证明 Zeek → 适配器 → `subject.mac` 在真实流量上贯通。

改动过程中发现的两个现场事实，对后续发布有直接影响：

1. **主 unit 的 `ExecStart` 是死配置**。`/etc/systemd/system/proxy-sentinel-zeek.service` 里的 `ExecStart` 被 drop-in `proxy-sentinel-zeek.service.d/proxy-transactions.conf` 用 `ExecStart=` 清空后整体替换，实际运行参数还包含 `proxy-transactions.zeek` 与 `LogAscii::use_json=T`。只改主 unit 不会生效，必须改 drop-in。
2. **该 unit 不是安装器生成的**（没有 `# Managed by proxy-sentinel install-openeuler.sh` 标记）。安装器会保留站点自维护单元，因此本轮对 `install-openeuler.sh` 的改动在 30 这类节点上不会自动落地。对任何目标节点发布前都应先用 `systemctl cat` 核对生效配置，而不是只看主 unit 或假定安装器已覆盖。

回退方式：还原 drop-in 备份后 `systemctl daemon-reload && systemctl restart proxy-sentinel-zeek.service`。备份路径在当次执行记录中给出，主 unit 已还原为改动前内容。

存储侧结论：30 的 ingest 原先只订阅 `dhcp/software/mdns/nbns/llmnr` 与 device-signals，`conn.log` 不在其中，所以采集侧改动不会自动反映到数据库；`mdns` 是项目自写的自定义日志流，记录结构不含 L2 字段，mac-logging 也不影响它。经确认后已把 `conn.log` 接入 ingest 并观察流量与证据增量变化。

接入 `--zeek-conn` 后的实测对比（改动前后不同长度的窗口，已折算为每分钟速率）：

| 来源 | 接入前（30 分钟） | 接入后（8 分钟） |
| --- | --- | --- |
| conn（Zeek，本次新增） | 未采集 | 7.3 条/分，**带 MAC 100%** |
| flow（Suricata EVE） | 15.7 条/分，带 MAC 0 | 12.9 条/分，带 MAC 0 |
| mdns | 15.5 条/分，带 MAC 0 | 12.0 条/分，带 MAC 0 |
| ssdp | 11.6 条/分，带 MAC 100% | 11.4 条/分，带 MAC 100% |
| ttl | 6.8 条/分 | 6.4 条/分 |

PostgreSQL 增量：`evidence` 由 2.03 条/分变为 1.88 条/分，基本持平；`shared_behavior_observations` 两端均为 0；`risk_snapshots` 由 12 条/30 分变为 7 条/8 分，绝对值太小（按窗口重算，`updated_at` 计数噪声大），**不足以判定无影响**。ingest 与 Zeek 均 active，无错误或畸形日志，`conn` 源持续写入。

因此：flow 类事件量实际增加约 57%（conn 约 1.0 万条/天，Suricata flow 约 1.85 万条/天），是否长期保留 `conn` 订阅需要更长的观察窗口；本次观察不足以宣称对风险与共享判定没有影响。

回退方式：还原 ingest 单元备份后 `systemctl daemon-reload && systemctl restart proxy-sentinel-ingest.service`。
