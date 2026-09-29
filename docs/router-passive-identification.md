# Huawei/H3C 路由器被动识别

## 目标与边界

本能力只在标准事件之上生成独立的路由观察、证据和置信度历史，用于离线回放、新机器影子验证和控制面查询。`confirmed_router` 是派生观察证据，不进入代理风险分、case、policy、action 或任何处置 connector。

不进行主动扫描、SNMP/HTTP 登录或设备配置读取，不依赖旧 dpi-analyze、MongoDB 或 Redis。OUI 只能确认厂商参考，不能确认路由器角色。

## 现状审计

| 链路 | 实施前 | 当前标准事件字段 |
| --- | --- | --- |
| Zeek | DHCP、software、mDNS、NBNS、LLMNR、TTL | 继续支持上述日志，并增加 `conn/dns/http/ssl/x509/lldp/ssdp` 的 JSON/TSV；输出既有 `flow/dns/http/tls/discovery/device` 类型 |
| Suricata | flow、dns、tls、http、quic、alert | 增加 `subject.mac`、`payload.vlan`、HTTP Server/Title、TLS subject/issuer/SAN/serial/fingerprint，保留 alert signature/category/metadata |
| 标准事件 | 已有 hostname、vendor class、requested options、software、TTL 和部分 HTTP/TLS 字段 | 路由规则统一读取 `subject.mac`、`subject.ip`、`payload.vlan` 及规范化 payload，不读取采集器原始对象 |
| 设备归属 | endpoint/MAC、身份租约和 IP 观测 | 显式 endpoint/MAC 优先；无 MAC 时使用事件时唯一租约，再按 sensor+campus+IP+VLAN+10 分钟窗口关联；歧义会降权并阻止确认 |
| 存储 | PostgreSQL 保存设备读模型，ClickHouse 保存标准事件 JSON | PostgreSQL `059` 保存路由证据、当前评估、状态历史和规则版本；ClickHouse 不新增路由专表 |
| 前端 | Discovery 展示基础设施发现，Devices 展示终端画像 | Discovery 增加路由识别列表/详情，Devices 只显示关联摘要和跳转，不改变 endpoint 主模型 |
| Shadow | 按 EVE、DHCP、software 固定 offset 增量读取 | `sources` map 按来源路径保存 offset，并兼容旧固定字段；输出路由证据、评估及来源统计 |

## 规则与置信度

规则位于 `internal/fingerprint/data/router_rules.json`，随 fingerprint bundle v5 发布；v1-v4 离线包没有该文件时回退到内置规则。每条规则保存 ID、版本、输入、原始值、匹配表达式、品牌、系列、型号、角色、强度、分值、排除标记和解释。

- Huawei 路由系列：AR、NE、ME、WS、AX、BE、HG、EG；AP/AirEngine 和 USG 分别归为 AP、防火墙。
- H3C 路由系列：MSR、ER、GR、Magic；WA/WX、S/Comware、SecPath 分别归为 AP、交换机、防火墙。
- 通用 Huawei/H3C 文本和 OUI 只生成 `brand_reference_only`。
- 排除规则优先于正向规则。AP、交换机、防火墙和基础设施角色保留真实分类与证据，但不得生成 `confirmed_router`。

默认阈值为 candidate `< 60`、likely `60..79`、confirmed `>= 80`。confirmed 还要求至少两个独立来源，其中至少一个是型号或角色强证据。来源家族按 OUI、DHCP、software、LLDP、SSDP、HTTP 管理面、TLS 管理面和 weak stack 去重，Zeek/Suricata 对同一协议的镜像不构成两个来源。单一 DHCP/software、OUI-only、关联歧义及强冲突均不能 confirmed。

证据默认 24 小时过期。聚合器使用稳定 evidence ID 合并重复镜像，按事件时间处理乱序，保留贡献事件、首次/最近观测、过期时间、关联质量、冲突和规则版本。MAC/endpoint 身份可跨窗口更新；IP-only 身份按窗口隔离，不同 VLAN 或不同 MAC 分开归属。

## 查询与回放

控制面提供只读接口：

```text
GET /api/v1/router-observations
GET /api/v1/router-observations/{assessment_id}
```

列表支持 `keyword/ip/mac/vlan/brand/model/role/status/source/confidence_min/confidence_max/first_seen_from/first_seen_to/last_seen_from/last_seen_to/infrastructure/limit/cursor`。详情包含证据时间线、原值、强度、分值、规则 ID/版本、分数构成、状态变化、过期和冲突。

运行 golden JSONL 评估：

```bash
go run ./cmd/proxy-sentinel evaluate routers \
  --manifest examples/router/golden/manifest.json \
  --output /tmp/router-evaluation.json
```

manifest 输入支持 normalized JSONL、Suricata EVE、Zeek 日志目录和 PCAP。PCAP 模式会在临时目录离线执行 Zeek、Suricata；缺少任一外部程序时明确失败，不会退化为不完整评估。报告包含样本数、三种状态数量、Huawei/H3C 精确率和召回率、排除角色误报率、OUI-only 误确认、来源分布、无法关联和过期证据数。

## 只采样不入库

在新机器的独立镜像网卡上运行：

```bash
proxy-sentinel router sample \
  --interface ens1f1 \
  --duration 5m \
  --work-dir /var/tmp/proxy-sentinel-router-sample
```

命令临时启动 Zeek，将日志写到指定目录，结束后通过标准事件适配器生成路由候选、证据和来源统计并自动退出。该模式固定使用文件存储，不读取数据库 DSN、不安装或修改 systemd 服务，也不触发处置。

## 验收原则

- `OUI-only misconfirmed` 必须为 0。
- AP、交换机、防火墙和基础设施样本不得 confirmed。
- 所有 confirmed 必须满足双来源和强证据要求。
- 回放、shadow 与新机器采样默认只读；生产 connector 保持禁用。
