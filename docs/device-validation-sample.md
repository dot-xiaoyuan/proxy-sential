# 人工已知设备验证集

这份验证集用于给设备发现、防共享和翻墙监测提供“标准答案”。没有它，系统只能说明生成了多少风险和设备画像，无法判断漏发现、误合并、重复创建和基础设施污染是否真实改善。

## 验证范围

第一版保持 30-50 台人工已知设备，覆盖：

- Windows 笔记本、macOS 笔记本、手机、平板、办公台式机。
- 个人路由器或 NAT 共享设备，至少 1 台。
- 打印机、服务器、网关、DNS、DHCP、无线 AC 等非普通终端。
- 无线 AP 接入、有线交换机端口接入、动态 IP 变化。
- 已登记和未登记设备都要包含。

## 模板

模板文件：`examples/known-devices-template.csv`

校验命令：

```bash
go run ./cmd/proxy-sentinel validate known-devices \
  --input examples/known-devices-template.csv \
  --output -
```

如果已经有一段身份标准事件回放结果，可以同时做发现结果比对：

```bash
go run ./cmd/proxy-sentinel validate known-devices \
  --input examples/known-devices-template.csv \
  --events data/shadow/runs/<run-id>/normalized.jsonl \
  --output -
```

正式验收使用严格模式：

```bash
go run ./cmd/proxy-sentinel validate known-devices \
  --input known-devices.csv \
  --events normalized-identity.jsonl \
  --strict \
  --output known-devices-acceptance.json
```

`acceptance_ready=true` 需要 30-50 台样本覆盖告警全部消失，并且身份事件比对通过。报告会额外统计发现率、误合并、重复创建和基础设施污染；只有结构合法而没有身份事件对照时，不会进入正式验收通过状态。

模板自带少量示例行，目的是说明填法。正式验收前需要扩展到 30-50 台现场设备。

## 字段说明

| 字段 | 说明 |
| --- | --- |
| `sample_id` | 人工样本编号，必须唯一 |
| `expected_endpoint_id` | 系统预期终端 ID；有 MAC 时建议使用 `mac:<mac>` |
| `primary_mac` | 人工确认的主 MAC；基础设施可为空 |
| `expected_account_id` | 预期账号；基础设施必须为空 |
| `expected_owner_name` | 责任人或人工登记名称 |
| `expected_owner_department` | 部门、宿舍区或管理单位 |
| `expected_device_type` | 设备类型，例如 `windows_laptop`、`phone`、`personal_router` |
| `expected_os_family` | 操作系统族，例如 `windows`、`ios`、`android`、`linux` |
| `expected_vendor` | 厂商或 OUI 归属 |
| `expected_ip` | 验证窗口内预期 IP |
| `expected_access_id` | 接入位置主键，例如 AP、交换机端口或机柜 |
| `expected_vlan` | VLAN |
| `expected_ap` | 无线 AP；有线设备可为空 |
| `expected_switch_id` | 交换机 ID；无线设备可为空 |
| `expected_switch_port` | 交换机端口；无线设备可为空 |
| `expected_role` | `endpoint`、`gateway`、`server`、`network_device`、`nat`、`infrastructure`、`unknown` |
| `registration_status` | `registered`、`unregistered`、`exempt`、`unknown` |
| `is_infrastructure` | 是否基础设施；为 `true` 时不得计入普通终端并发 |
| `is_nat_or_router` | 是否个人路由/NAT 或网关类设备 |
| `expected_hidden_downstream_count` | 人工确认的 NAT 后隐藏设备数；没有则填 0 |
| `first_seen` / `last_seen` | 验证窗口，RFC3339 格式 |
| `notes` | 人工备注 |

## 验收问题

每次拿系统输出和验证集比对时，只回答这些问题：

- 样本设备是否被发现。
- 同一台设备动态 IP 变化后是否仍是同一个 endpoint。
- 两台不同设备是否被错误合并。
- 同一设备是否被重复创建。
- 网关、DNS、DHCP、服务器、无线 AC 是否被排除在普通终端并发之外。
- 个人路由器是否作为 endpoint 记录，同时只输出“疑似 NAT 后多设备”证据。
- 账号、IP、MAC、AP、交换机端口是否能按时间窗口正确关联。

## 状态边界

当前项目已经完成模板、严格覆盖校验和发现质量报告；现场 API 已从 DHCP 标准事件回填 82 个 endpoint 候选，可直接从中挑选 30-50 台建立人工标准答案。样本的责任人、真实设备类型和基础设施属性必须由现场人员确认，不能用系统自身推断替代人工真值。
