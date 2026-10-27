# 验收计划：设备识别链路（2026-10-27）

执行者：验收方（Claude）。实施方已完成代码与文档，本文件只描述可复现的判定方法。

## 0. 前置

- 仓库：`proxy-sentinel`，工作区即当前目录；不要清理既有未提交改动
  （`frontend/*`、`internal/netscan/`、`internal/controlplane/internal_scan*`、
  `migrations/postgres/170_*` 属于其他任务）。
- 不需要数据库、不需要网络、不需要部署。
- 已知基线失败：`artifacts/shared-detail-deploy-184-20261023` 包编译失败（未跟踪目录，
  与本次无关）。所有命令都限定 `./internal/... ./cmd/...`。

## 1. 命令清单

```bash
go build ./...
go vet ./internal/fingerprint ./internal/discovery ./internal/store
go test ./internal/... ./cmd/...
go test ./internal/fingerprint/ -run 'TestRule|TestOUI|TestSNMP|TestModel|TestVendor|TestDeviceLabel|TestProtocolModelFields|TestUserAgent|TestCampus|TestRouter' -v
go test ./internal/discovery/ -run 'TestService|TestProduct|TestDNSSD|TestFromEventDNSD|TestIOTClassificationUsesServiceCatalog' -v
go test ./internal/store/ -run 'TestPassive|TestTyped|TestSNMP|TestUsable|TestEmptyMaterialized' -v
go test ./internal/store/ -run TestPassiveDiscoveryRecognitionHintsPostgres -v   # 有 PROXY_SENTINEL_TEST_POSTGRES_DSN 时
```

## 2. 断言

| # | 断言 | 方法 | 通过标准 |
|---|---|---|---|
| A1 | 全仓可构建 | `go build ./...` | 退出码 0 |
| A2 | 三个受影响包静态检查通过 | `go vet ...` | 退出码 0 |
| A3 | 全量单测通过 | `go test ./internal/... ./cmd/...` | 无 FAIL |
| A4 | 规则按字段定向 | `TestRuleInputRoutingScopesMatches` | 同一规则在 `ssdp_model` 命中、在 hostname 不命中，且 `Source=="device_rule:ssdp_model"` |
| A5 | 结果与规则顺序无关 | `TestRuleOrderDoesNotChangeOutcome` | 正反序加载同一组规则，品牌/型号/类型一致，且高置信规则胜出 |
| A6 | OUI 不得确认品牌/型号 | `TestOUICannotConfirmBrandOrModel` | Vendor 非空、`VendorConfidence==0.9`，Brand/Model/DeviceType 全空 |
| A7 | 冲突被标记但不覆盖 | `TestRuleConflictIsReportedNotApplied` | `Conflict==true` 且 Brand 为主匹配值 |
| A8 | sysObjectID 解析厂商 | `TestSNMPOIDResolvesVendor` | Vendor 非空、置信度 0.85、Brand/Model 为空 |
| A9 | 型号代码解析商品名 | `TestModelCatalogResolvesMarketingName` | `ADY-AL00 → Huawei/Pura 70/mobile/0.95`；`SM-G991B/DS` 前缀命中 |
| A10 | 厂商先验仅兜底 | `TestVendorPriorIsFallbackOnly` | 先验命中且置信度 ≤0.80；已有明确类型时不被覆盖 |
| A11 | 夹具结果稳定 | `TestDeviceLabelFixtureSnapshot` | 42 行与 `testdata/device-label-baseline.json` 完全一致 |
| A12 | UA 仍不得确认品牌 | `TestUserAgentCannotPopulatePhysicalDeviceProfile` | 仅 UA 时品牌/型号/类型/OS/置信度全空 |
| A13 | 校园自报规则未回归 | `TestCampusSelfReportedDeviceRules` | 全部用例通过（含 `ALN-AL00 → Mate 60 Pro` 的更新期望） |
| A14 | 路由器网卡不被误判 | `TestRouterRulesRejectTPLinkAdapters` | 全部适配器不匹配 router 规则 |
| A15 | 协议字段进入终端识别 | `TestTypedDiscoveryModelHintResolvesMarketingName` | `ssdp_model=ADY-AL00` 经型号库得到 Huawei/Pura 70/mobile，`Source=="passive_discovery"`，证据含 SSDP 与字段名 |
| A16 | sysObjectID 提示不被丢弃 | `TestSNMPSelfReportHintResolvesVendor` | 随机 MAC 下 `snmp_sysoid` 提示使 Vendor 非空，且结果仍归属 `passive_discovery` |
| A17 | 提示按字段路由 | `TestTypedDiscoveryHintRoutesToFieldScopedRule` | 同一值作为 `ssdp_manufacturer` 命中字段规则，作为普通 hostname 提示不命中 |
| A18 | 提示值有界 | `TestUsableRecognitionFieldValueBounds` | 型号/厂商 >128 rune、sysDescr >512 rune、含控制字符或空值被拒绝 |
| A19 | 型号字段覆盖完整 | `TestProtocolModelFieldsReachModelCatalog` | `ssdp_model`/`snmp_model`/`dns_sd_model`/`mdns_model` 均解析 `ADY-AL00`，仅 UA 仍为空 |
| A20 | DNS-SD TXT 型号可解析 | `TestDNSSDModelFromTXT` / `TestFromEventDNSDCarriesModelName` | `ty`/`product`/`model`/`md`/`usb_mdl` 命中并清理括号/控制字符/超长；`FromEvent` 写入 `ModelName` |
| A21 | 产品品类由服务目录驱动 | `TestIOTClassificationUsesServiceCatalog` | 打印/扫描/投屏在带产品声明时分类正确；无声明、未知服务、非 IoT 品类不分类 |

## 3. 人工复核点

验收方需自行判断以下"预期变化"是否合理，而非视为失败：

1. `TestCampusSelfReportedDeviceRules` 中 `huawei harmony phone` 的 model 期望由
   `ALN-AL00` 改为 `Mate 60 Pro`（型号库解析）。源文件已注明原因。
2. `Result.Source` 新增取值：`device_rule:<字段>`、`model_catalog`、`snmp_sysoid`。
   下游若按 `"device_rule"` 精确匹配，需要改为前缀匹配。
3. `Result.Evidence` 新增三类文本：`SNMP sysObjectID: … → …`、`型号库: <code> → <name>`、
   `厂商类型先验: <vendor> → <type>`。
4. 被动提示新增带字段的证据文本 `被动发现 <ORIGIN> <field>: <value>`；`dns_sd_model` 与
   `mdns_model` 是同一值的两个输入别名，属预期设计。
5. 识别结果只在提示确实改变品牌/型号/类型/系统/厂商/冲突时替换原结果；仅增加证据而值未变的提示不会覆盖基础识别。

## 4. 不通过判定

出现以下任一情况即判不通过：

- A1–A3 任一失败。
- A4–A21 任一失败且不属于第 3 节列出的预期变化。
- `git diff` 中 `internal/fingerprint/data/router_rules.json` 条目数不等于 78，
  或 `device_rules.json` 不等于 75（本会话既定基线）。
- 出现对 `frontend/`、`migrations/` 的改动。

## 5. 交付物核对

- [x] `internal/fingerprint/library.go` 的 `matchRules`/`ruleInputValues`/`applyRuleMatch`
- [x] `internal/store/device.go` 的 ssdp/snmp 属性搬运
- [x] `internal/store/identity.go` 的三个新输入字段
- [x] `internal/discovery/product_rules.go` 改为数据驱动
- [x] `internal/store/identity.go` 的 `DiscoveryRecognitionHint.Field` 与按字段注入
- [x] `internal/store/passive_recognition_postgres.go` 的字段化提示查询与长度上限
- [x] `internal/store/passive_discovery_materializer.go` 的 SSDP 描述自报与 DNS-SD TXT 型号
- [x] `internal/fingerprint/model_catalog.go` 的 `snmp_model` 候选
- [x] `internal/discovery/iot_classification.go` 的 `product_kind` 数据化
- [x] 本文与 `docs/device-identification-pipeline-plan-20261027.md` 的补记一致
- [x] `docs/device-identification-pipeline-plan-20261027.md`

## 6. 执行记录（2026-10-27）

环境：分支 `codex/stream-storage-handoff-20261026`，工作区含未提交改动；Go 1.24.0 darwin/arm64；
无数据库、无网络、无部署。按 §0 排除 `artifacts/shared-detail-deploy-184-20261023`。

| 断言 | 命令/用例 | 结果 |
|---|---|---|
| A1 | `go build ./...` | 通过 |
| A2 | `go vet ./internal/fingerprint ./internal/discovery ./internal/store` | 通过 |
| A3 | `go test ./internal/... ./cmd/...` | 通过（无 FAIL） |
| A4 | `TestRuleInputRoutingScopesMatches` | 通过 |
| A5 | `TestRuleOrderDoesNotChangeOutcome` | 通过 |
| A6 | `TestOUICannotConfirmBrandOrModel` | 通过 |
| A7 | `TestRuleConflictIsReportedNotApplied` | 通过 |
| A8 | `TestSNMPOIDResolvesVendor` | 通过（0.85） |
| A9 | `TestModelCatalogResolvesMarketingName` | 通过（精确 + 前缀） |
| A10 | `TestVendorPriorIsFallbackOnly` | 通过（≤0.80） |
| A11 | `TestDeviceLabelFixtureSnapshot` | 通过（42 行一致） |
| A12 | `TestUserAgentCannotPopulatePhysicalDeviceProfile` | 通过 |
| A13 | `TestCampusSelfReportedDeviceRules` | 通过 |
| A14 | `TestRouterRulesRejectTPLinkAdapters` | 通过 |
| A15 | `TestTypedDiscoveryModelHintResolvesMarketingName` | 通过 |
| A16 | `TestSNMPSelfReportHintResolvesVendor` | 通过 |
| A17 | `TestTypedDiscoveryHintRoutesToFieldScopedRule` | 通过 |
| A18 | `TestUsableRecognitionFieldValueBounds` | 通过 |
| A19 | `TestProtocolModelFieldsReachModelCatalog` | 通过 |
| A20 | `TestDNSSDModelFromTXT`、`TestFromEventDNSDCarriesModelName` | 通过 |
| A21 | `TestIOTClassificationUsesServiceCatalog` | 通过 |
| 基线 | `router_rules.json`=78、`device_rules.json`=75 | 与既定基线一致 |
| 数据 | `internal/*/data/*.json` | 全部合法 JSON |
| 集成 | `TestPassiveDiscoveryRecognitionHintsPostgres` | 跳过（未设置 `PROXY_SENTINEL_TEST_POSTGRES_DSN`） |

格式与静态检查：

```bash
gofmt -l <上述改动文件>                            # 无输出
go vet $(go list ./... | grep -v '/artifacts/')   # 通过
```

未覆盖项与边界：

- 按本地验证约定未启动 PostgreSQL/ClickHouse 栈，字段化提示 SQL 未在真实数据库执行，
  仅做了静态核对；`TestPassiveDiscoveryRecognitionHintsPostgres` 在有隔离 DSN 时才会运行。
- v2 `stream_discovery_facts` 桥接与 ClickHouse `passive_discovery_events_v2` 不含 snmp
  仍是遗留项，见链路实施记录「遗留」，不在本轮验收范围。
- 本任务未新增 `frontend/` 或 `migrations/` 改动；工作区既有前端改动属于其他任务（见 §0），
  因此未执行 `pnpm test`/`typecheck`/`build` 与三视口审查。
- `internal/discovery/capture_linux.go`、`internal/fingerprint/consumer_router_rules_test.go`
  的 gofmt 差异属其他任务，本轮未处理。

本任务改动文件：

- `internal/store/{identity.go,passive_recognition_postgres.go,passive_recognition_test.go,passive_recognition_integration_test.go,passive_discovery_materializer.go,passive_discovery_materializer_test.go}`
- `internal/discovery/{describe.go,product_rules.go,iot_classification.go,iot_classification_test.go,dns_sd_model_test.go}`
- `internal/fingerprint/{model_catalog.go,signature_tables_test.go}`
- `docs/device-identification-pipeline-{plan,acceptance}-20261027.md`
