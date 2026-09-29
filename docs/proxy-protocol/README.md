# HTTP CONNECT / SOCKS5 代理事务识别

首版识别成功代理连接，并关联事件发生时的认证账号。协议识别与是否违规分开；只支持仅观测与人工确认，不开放自动处罚，不涉及 VPN 检测规则或应用统计 ClickHouse 改造。

## 数据流及判定

1. Suricata 保留原 HTTP 标准事件，同时为 CONNECT 生成 `type=proxy_transaction` 的派生标准事件。使用同一 EVE 事务内的 method、status、tx_id，2xx 为成功，最终非2xx为失败。缺少连接或事务 ID、不存在最终响应时为不完整。
2. Zeek `assets/zeek/proxy-transactions.zeek` 使用解析器 HTTP 和 SOCKS 事件输出 `proxy_transactions.log`。HTTP 使用解析器事务深度关联，SOCKS5 只确认 CONNECT 命令（1）的成功应答（0）。认证协商、SOCKS4、BIND 和 UDP 不算此类成功证据。同连接出现重复 SOCKS 请求时不冒险关联响应。
3. 请求先输出不完整记录，响应到来后输出完整记录。消费侧按传感器、来源、采集实例、连接、事务、协议组成稳定证据 ID；只替换整个完整事务，不拼接两条残缺记录的字段。相互矛盾的可信记录变成冲突，禁止用于处置。
4. 异步处理器每批最多读取 1000 条代理事务，独立保存结果。数据库模式下，结果与扫描游标在 PostgreSQL 同一事务提交；开发文件模式结果原子写入后推进游标，失败批次可重复处理。定期重新扫描最近七天以接收迟到记录。
5. 按请求时间、园区、接入域及 IP 重新查询身份；过期或冲突保持未知。Suricata 普通 EVE HTTP 记录没有可靠的请求时间，因此可确认协议成功，但不会凭日志时间归责账号；需要账号处置时使用 Zeek 事务记录提供准确请求时间。

结果包含 `success`、`failed`、`incomplete`、`unsupported`、`conflict` 五种状态；`trusted` 与结果分开。未通过来源校验的成功记录只是线索。证据不进入原有风险评分，返回的通用 evidence `score` 为 0，避免间接触发原有自动处罚。

## 受控来源配置

样例：`examples/proxy-protocol/producers.example.json`。样例密钥仅用于回放，实际使用必须替换随机密钥，并限制配置文件读取权限。采集适配进程与控制面使用对应登记配置。

登记项固定绑定 `sensor_id`、`source`、`instance_id`、`parser_id`、`parser_version`、`campus_id`、`access_domain` 和不少于32字节的密钥。`instance_id` 必须在采集器重启后变化；需要识别旧记录时保留旧实例登记。配置变更产生新的配置指纹并触发重新校验，旧配置结果不会继续用于处罚。

适配器用配置中的密钥对规范化代理事件签名，控制面验证签名、来源与版本。原始数据里的 `verified` 不参与判断，事件不能自行授予可信身份。日志文件目录也必须由受控采集器写入；签名证明经过登记适配器，不证明人为导入的原始日志真实。

命令示例（本地离线回放）：

```bash
zeek -C -r capture.pcap assets/zeek/proxy-transactions.zeek LogAscii::use_json=T

go run ./cmd/proxy-sentinel adapter zeek \
  --log-kind proxy --sensor-id replay --collector-instance-id replay-boot \
  --proxy-protocol-config examples/proxy-protocol/producers.example.json \
  --input proxy_transactions.log --output normalized-proxy.jsonl
```

Suricata 适配命令同样新增 `--proxy-protocol-config`，HTTP 需要开启 EVE extended logging。实时 ingest 新增 `--zeek-proxy <日志路径>`，与 `--collector-instance-id`、`--proxy-protocol-config` 一起使用；控制面 serve 增加同名配置文件参数。未配置控制面来源登记时不启动代理证据物化。

生产数据库需要按项目既有流程应用 `019_proxy_protocol.sql`，本任务没有执行生产迁移或部署。部署包的现有 assets/zeek 复制流程会包含新脚本。

## 标准事件与接口

新增标准事件类型 `proxy_transaction`，复用 Event 的 observer、subject、flow 和 raw_ref。payload 包含：

- 公共：protocol、transaction_id、request_at、response_at；时间缺失就不填写。
- HTTP CONNECT：method、status。
- SOCKS：version、command、reply。
- `flow.connection_id` 使用现有标准连接 ID；`observer` 包含 sensor_id、collector_instance_id、parser_id、parser_version、proxy_signature。

不采集 SOCKS 用户名、密码或认证内容。派生事件不会修改已存储的原始标准事件。

沿用现有 API：

- `/events/{id}` 返回原始事件字段并附加独立的 `proxy_protocol` 识别结果。
- `/ips/{ip}/evidence` 混合返回代理事务证据和已有证据，代理证据包含 `proxy_protocol` 字段。
- `/policies/{id}/simulate` 的明确代理评估附加 `proxy_evidence`。
- `/policy-executions` 为执行记录附加可查看的协议依据；`approve` 使用 `policies:authorize`，撤销沿用 `actions:revoke`。

配置 `explicit_proxy` 策略时，自动模式在后端验证中被拒绝。即使绕过配置校验导入了自动策略，策略输入和动作执行端仍阻止执行。人工确认记录当前证据 ID 集合；发送前再次检查证据时效、事件时刻归责、当前账号会话、策略优先级和豁免。证据集合变化要求重新确认，不能把审批复用到新证据。既有影子准入、全局停止、控制器能力声明、重试和撤销保持生效。

## 验证与限制

执行 `scripts/proxy-protocol/replay.sh` 可本地生成 TCP PCAP、通过真实 Zeek 解析，再运行适配和策略沙箱测试；不会向外部网络发送数据包。需要 Python3、Zeek、Go。

本次验证：

- Zeek 8.2.0 解析实际生成的 PCAP：14条日志合并为8个事务，2成功、3失败、2不完整、1不支持；普通 HTTP 与仅认证协商未算作成功事务。
- Go 测试包含伪造签名、内容篡改、事务边界、迟到补正、身份换绑/冲突、证据过期、文件结果重启恢复、FileStore/ClickHouse HTTP 模拟源一致性、手工确认及自动模式阻止。
- 内置 HTTP 控制器沙箱验证人工确认后发送及重复执行去重；现有账号动作测试覆盖部分失败与解除。
- `go test ./...`、相关包 `go test -race`、前端类型检查和生产构建通过。
- Playwright 完成390×844、1280×800、1440×900的事件证据、执行记录及表单检查，6项用例通过；截图和 DOM 探针位于 `frontend/test-results/proxy-protocol/`。

没有执行真实流量观测、真实控制器或实际 PostgreSQL/ClickHouse 服务器的联合验收；数据库源测试使用 HTTP 沙箱，不能替代真实数据库部署验证。源配置假定同一登记传感器的流量属于其登记园区/接入域，不能将跨园区镜像任意归入一个园区。一次策略评估最多处理一万条近七天证据，超出时返回不可用并停止据此判断，不能静默截断后继续处罚。

五分钟以上未关联响应的 Zeek 请求保持不完整；加密代理握手、SOCKS4、UDP ASSOCIATE、WireGuard/OpenVPN 不属于本次成功识别范围。
