# 被动硬件识别 v2 兼容契约

`PROXY_SENTINEL_HARDWARE_V2=true` 启用新读取，默认关闭；`PROXY_SENTINEL_HARDWARE_SHADOW=true` 仅生成投影。184 的既有风险读模型不读取本投影。迁移 241 只新增表，不回填、不改写既有事件或已应用迁移。

标准事件新增响应输入 `snmp`、`bacnet`、`modbus`，字段见 `internal/normalized/hardware_contract.go`。`snmp_varbinds` 最多 64 个白名单 OID，每值最多 4096 字节。SNMP 连接聚合不是响应证明。设备侧 IP 必须与响应源一致，并有同传感器、校区、接入域、VLAN、VRF 的事件时间二层归属；无归属的输入仅保留线索。

身份为 JSON 数组 `["identity",sensor,campus,domain,vlan,vrf,"mac",mac]`；未知 VLAN/VRF 保留空维度，不与已知维度合并。精确型号或产品级证据可以形成持久硬件结论；OUI、名称、端口、通用系统/服务线索不能单独确认类型。服务/地址过期只改变活动状态，撤销、归属纠正、规则撤回和真实矛盾证据触发重算。

新增返回字段：`hardware_type`、`hardware_type_status`（identified/candidate/conflict/revoked）、`hardware_model`、`hardware_model_status`、`type_evidence_at`、`type_rule_version`、`type_sources`、`activity_status`（active/stale）、`classification_version=passive-hardware/v2`。来源包含 source/rule_id/rule_version/evidence_id/observed_at。类型和型号分别判定冲突。旧字段在 v2 开启时映射同一当前投影；统计按窗口内可信身份观测与持久类型交集计数，`metric_version=passive-census/v2`。规则结果不产生人工核实数。

事实仅存有界结构化匹配输入和原文引用。重复观测合并首次/末次时间，撤销保留墓碑；晚到不能覆盖更新或撤销。事实写入与 dirty outbox 同事务，按受影响身份有界重算；失败保留错误、次数和首次入队时间。规则变更按依赖键分批入队，无需等待设备重新发报文。列表、统计、导出只读当前投影，不请求内扫历史。

新表无自动 TTL：支撑现行结论的紧凑事实与原文引用随当前态保留。原文仍由原有事件归档负责。清理被撤回事实/变更历史必须先满足归档核验和引用保护，不由本迁移擅自删除。常规写成本与受影响身份及独立证据条目数相关，重复未变化结果不递增结果版本。上限溢出明确失败并展示积压，不能截断后声称完成。

指纹包新增 `device-fingerprint-bundle/v8`，在 V7 基包上增加 `hardware-catalog.json` 与 `hardware-provenance.json`，保留已有载荷字节及 V1–V7 加载路径。旧 `IdentifyEvidence` 语义不变；新硬件入口只为 204 独立投影提供判断。规则包必须固定来源版本、原始来源引用与哈希，发生规则变更时更新目录版本并有界重算受影响当前身份。

PG 242 补充声明级撤销及规则版本索引；PG 243 记录固定起点的保留窗回填游标和缺少原文引用的缺口。`PROXY_SENTINEL_HARDWARE_BACKFILL=true` 单独启用每批 100 条的回填，无原文引用的条目跳过并计缺口，不补造历史。回填完成后分析派生表统计信息，再比较影子与现有读取；新读取仍由独立 gate 决定。可用起点为实际可引用数据的最早时间，不能用请求的 30 天边界代替。

回填游标使用 latest 表真实主键五元组 `(device_key,source_id,origin,service_type,port)`，不是可重复的事件 ID。PG 244 记录固定起点后被更新的行；`backfill_complete` 仅表示当前投影遍历完成，`coverage=retained_latest_only` 明确其不等于完整 30 天历史。实时输入和独立规则重算继续分别处理，不把回填遍历结束描述为全校覆盖完成。
