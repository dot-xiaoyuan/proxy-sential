# 设备/路由器识别：识别链路实施记录（2026-10-27）

## 目标

把识别从"规则跑在拼接串上、首个匹配即生效、OUI 可被任意规则覆盖"改为
"结构化字段 → 查表 → 规则兜底 → 冲突显式化"，并使结果与规则文件顺序无关。

成功标准：字段定向可验证、OUI 不得单独确认品牌、型号代码可解析为商品名、
SSDP/SNMP 自报字段进入识别输入、既有回放与单测不回归。

## 已实施变更

| 工作包 | 文件 | 内容 |
|---|---|---|
| A-WP1 | `internal/fingerprint/library.go` | `matchRules` 收集全部命中并按「字段特异性 > 置信度 > 文件序」排序；`applyRuleMatch` 只让主匹配写维度；`ruleInputValues` 支持按字段取值 |
| A-WP1 | `internal/fingerprint/library.go` | 新增 `applyRuleExtras`：型号库已确认品牌/型号时，规则只补 OS 与空类型 |
| A-WP1 | `internal/fingerprint/library.go` | `ruleMatchConflicts`：次级高置信规则与主结论冲突时置 `Result.Conflict`，但不覆盖字段 |
| A-WP2 | `internal/store/device.go` | `ssdp` 来源写入 `ssdp_manufacturer`/`ssdp_model`；`snmp` 来源写入 `snmp_sysdescr`/`snmp_sysoid`/`snmp_model` |
| A-WP2 | `internal/store/identity.go` | `endpointRecognitionSignals` 增加 `ssdp_model`/`ssdp_manufacturer`/`snmp_model` 三个输入字段 |
| A-WP2 | `internal/fingerprint/multisource.go` | `supportedCatalogFields` 增加 `ssdp_model`/`ssdp_manufacturer`/`dns_sd_model`/`snmp_model` |
| A-WP3 | `internal/fingerprint/library.go` | `sysObjectID` 解析厂商（置信度 0.85），仅在 OUI 未给出厂商时使用；厂商类型先验作为最后兜底 |
| A-WP4 | `internal/discovery/product_rules.go` + `data/product-rules.json` | 8 条硬编码产品规则迁为数据文件，代码保留 `parseProductRules` 校验 |
| A-WP4 | `internal/discovery/model.go` | dns_sd 能力映射优先读 `service-type-catalog.json`，缺失时回退原 switch |

## 语义变化

1. **结果与规则顺序无关**：同分时按文件序稳定排序，主匹配由置信度决定。
2. **OUI 不再覆盖规则结论**：删除 `|| result.Source == "ieee_oui"` 分支。OUI 仍写
   `Vendor`/`VendorConfidence=0.9`（既有测试与界面约定），但不再参与品牌/型号判定。
3. **次级规则只用于冲突报告**，不再填补维度。首版实现曾让次级规则填补空维度，
   导致 `HP LaserJet` 被写入 model、`Embedded Linux` 被写入 os，被
   `TestCampusSelfReportedDeviceRules` 拦下后改为当前策略。
4. **型号代码解析为商品名**：`ALN-AL00` 现在返回 `Mate 60 Pro`，
   `campus_device_rules_test.go` 的对应期望已同步更新并注明原因。

## 与计划的偏差

| 计划 | 实际 | 原因 |
|---|---|---|
| OUI 置信度降至 0.50 | 保持 0.9，仅禁止确认品牌/型号 | `library_test.go` 锁定 `VendorConfidence == .9`，且该字段是厂商置信度而非整机置信度 |
| UA→型号通道 | 仅在 OUI 厂商与型号品牌一致时启用 | 避免 UA 单独决定物理型号；随机 MAC 设备因此不启用 |
| 统一两条识别路径 | 未做，只做数据化 | 合并会改动 discovery 的观察模型，超出本轮范围 |
| bundle 携带新表 | 仅嵌入，未进 payload | 旧 reader 会拒绝未知条目（`TestV6BuilderPreservesLegacyBundleReaders`），需 V7 schema |

## 遗留

- 厂商类型先验仅覆盖哑终端族群（打印/摄像/存储/IoT），网络设备仍依赖型号规则；这是刻意取舍，避免把交换机/AP 误判为路由器。
- v2 discovery 的 enrichment（SSDP 描述、SNMP 产品信息）落在 `stream_discovery_facts`，尚未桥接到终端识别；桥接需要先确定 epoch 权威性和 MAC 索引方案。
- ClickHouse `passive_discovery_events_v2` 视图不含 snmp，SNMP 观察依赖主动采集或旧版持久化路径进入 `discovery_observations`。
- `endpointRecognitionSignals` 里的 ssdp/snmp 属性键保留，供未来 device 事件直接携带同名属性；当前这些值由被动发现提示层供给。

## 补记：端到端接线（2026-10-27 续）

复核发现 A-WP2 只把字段写进了 device signal 与 attribute 键，`PassiveDiscoveryRecognitionHints`
仍只读取 `data->>'name'`，字段并未真正进入终端识别输入。本轮按下列改动补齐。

| 工作包 | 文件 | 内容 |
|---|---|---|
| C-WP1 | `internal/store/identity.go` | `DiscoveryRecognitionHint` 增加 `Field`；`BuildEndpointDeviceInventory` 复制基础信号后按字段写入 `ProtocolFields`，主机名提示仍走 `Hints`；`passiveRecognitionChanged` 比较 `Vendor` |
| C-WP1 | `internal/store/passive_recognition_postgres.go` | 单条有界查询返回 dns_sd/dhcp 名称、ssdp 型号/厂商、snmp 型号/sysObjectID/sysDescr、dns_sd 型号；单 endpoint 上限 40，值去空、去控制字符并限制长度 |
| C-WP2 | `internal/store/passive_discovery_materializer.go` | 被动 SSDP 从描述自报厂商/型号；被动 DNS-SD 从 TXT 写入 `ModelName` |
| C-WP2 | `internal/discovery/product_rules.go` | 新增 `DNSSDModelFromTXT`，解析 model/md/usb_mdl/product/ty，并与位置规则共用 |
| C-WP3 | `internal/fingerprint/model_catalog.go` | `modelCandidates` 增加 `snmp_model`，并把协议型号字段排在主机名前 |
| C-WP4 | `internal/discovery/iot_classification.go` | dns_sd 产品品类改由 `service-type-catalog.json` 的 `product_kind` 决定，未知品类仍不分类 |

语义补充：

1. `dns_sd_model` 与 `mdns_model` 是同一值的两个输入别名：前者供字段定向规则，后者供既有 195 条
   multisource catalog 规则；当前 catalog 没有 `dns_sd_model` 规则，因此不产生重复匹配。
2. 提示仍是只读增强：显式终端属性优先，`Source` 记为 `passive_discovery`，证据带 origin 与字段名。
3. 提示上限 40，超长型号/厂商直接丢弃而不是截断；sysDescr 允许 512 字符，但证据只保留 80 字符。
4. 随机 MAC 设备在存在 mDNS/SSDP 型号观察时已有型号主路径；UA 仍不单独确认物理型号。

新增用例：`TestTypedDiscoveryModelHintResolvesMarketingName`、`TestSNMPSelfReportHintResolvesVendor`、
`TestTypedDiscoveryHintRoutesToFieldScopedRule`、`TestUsableRecognitionFieldValueBounds`、
`TestProtocolModelFieldsReachModelCatalog`、`TestDNSSDModelFromTXT`、`TestFromEventDNSDCarriesModelName`、
`TestIOTClassificationUsesServiceCatalog`、`TestPassiveSelfReportReadsUPnPDescription`。

验证（2026-10-27，当前工作区）：

```bash
gofmt -l internal/store internal/fingerprint internal/discovery   # 本任务改动文件无输出；另有两个属其他任务的既有差异
go build ./...
go vet ./internal/fingerprint ./internal/discovery ./internal/store
go test ./internal/fingerprint ./internal/discovery ./internal/store -count=1
go test ./internal/... ./cmd/...
```

构建、静态检查和定向/全量测试均通过。`TestPassiveDiscoveryRecognitionHintsPostgres` 需要
`PROXY_SENTINEL_TEST_POSTGRES_DSN`；按本地约定未启动数据库栈，该用例跳过，SQL 只做了静态核对，
尚未在真实 PostgreSQL 上执行。

验收结果见 [链路验收计划](device-identification-pipeline-acceptance-20261027.md) §6。

