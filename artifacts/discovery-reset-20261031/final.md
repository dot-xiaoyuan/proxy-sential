# 发现数据重置两小时验收摘要

- 采集窗口：2026-10-31 17:28:16–19:28 CST
- 验收采样：2026-10-31 19:32 CST
- 历史清理：已清空业务历史；数据边界严格从 09:28:16Z 开始
- 登录会话已清空，账号和密码保留

## 当前数据

| 指标 | 数值 |
|---|---:|
| current 文档 | 49,166 |
| stream facts | 52,849 |
| 发现页 passive total | 51,467（修正后） |
| 哑终端线索过滤 total | 368（修正后） |
| current=false | 0 |
| 空文档 | 0 |
| no_facts | 62 |

## 协议分布

| 协议 | 当前文档数 |
|---|---:|
| ARP | 24,587 |
| DHCP | 12,542 |
| DNS-SD | 657 |
| SSDP | 156 |
| IEEE1905 client association | 2 |

## 哑终端能力线索

| capability | 设备数 |
|---|---:|
| casting | 302 |
| media_rendering | 58 |
| routing | 37 |
| printing | 9 |
| scanning | 5 |
| file_sharing | 4 |

## ClickHouse

| 表 | 行数 |
|---|---:|
| normalized_events | 2,861,487 |
| passive_discovery_events_v2 | 1,128,744 |
| eventbus_discovery_receipts | 2,861,209 |

## 积压与健康

- Kafka 状态：Stable
- discovery TOTAL-LAG：约 500（ARP 突发，未持续增长）
- producer published：440,481
- producer failed / dropped：0 / 0
- producer queue_depth：0
- control plane readyz：200
- failed services：0
- 页面接口：200，无 console/page error

## 已知缺口

- 62 个当前文档没有直接事件 facts；
- LLDP 现场 0 包；
- IEEE1905 未启用；
- 27 条旧 closed 切流元数据因外键引用保留，不是采集业务数据；
- PostgreSQL 逻辑数据已清空，物理文件不会立即缩小；
- 登录会话为空，验收前需要重新登录。
