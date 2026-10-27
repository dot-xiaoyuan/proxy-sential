# 验收计划：特征数据表（2026-10-27）

执行者：验收方（Claude）。本文件只描述可复现的判定方法，不需要网络与数据库。

## 0. 前置

- 与链路验收相同的仓库与工作区状态要求。
- 已知基线失败包 `artifacts/shared-detail-deploy-184-20261023` 不计入。

## 1. 命令清单

```bash
python3 -c "import json,glob;[json.load(open(f)) for f in glob.glob('internal/fingerprint/data/*.json')+glob.glob('internal/discovery/data/*.json')]"
shasum -a 256 internal/fingerprint/data/snmp-enterprise-oid.json
bash scripts/device-fingerprint/build-signature-tables.sh
bash scripts/device-fingerprint/build-signature-tables.sh
shasum -a 256 internal/fingerprint/data/snmp-enterprise-oid.json   # 与第一条哈希一致
go test ./internal/fingerprint/ -run 'TestParseSignatureTablesRejectInvalid|TestSignatureTablesCarryProvenance|TestSNMPOIDResolvesVendor|TestModelCatalogResolvesMarketingName|TestVendorPriorIsFallbackOnly|TestV6BundleRejectsSignatureTablePayload' -v
go test ./internal/discovery/ -run 'TestService|TestProduct' -v
go test ./internal/fingerprint/ -run TestV6BuilderPreservesLegacyBundleReaders -v
```

## 2. 断言

| # | 断言 | 方法 | 通过标准 |
|---|---|---|---|
| B1 | 所有数据文件是合法 JSON | 第一条命令 | 无异常 |
| B2 | SNMP 表完整且有出处 | `TestSignatureTablesCarryProvenance` | `version/source/source_url` 非空，条目 ≥ 60000 |
| B3 | 非法表被拒绝 | `TestParseSignatureTablesRejectInvalid` | 空版本、空条目、先验置信度 >0.80、型号码 <5 字符、空型号名，全部报错 |
| B4 | OID 解析正确 | `TestSNMPOIDResolvesVendor` | `1.3.6.1.4.1.2011.2.23` 命中厂商，置信度 0.85 |
| B5 | 型号目录可用 | `TestModelCatalogResolvesMarketingName` | 精确与前缀两种命中，未知码不命中 |
| B6 | 先验只做兜底 | `TestVendorPriorIsFallbackOnly` | 命中的置信度 ≤0.80，且不覆盖已有类型 |
| B7 | 服务类型目录可用 | `TestServiceTypeCatalogCoversPrinterAndMedia` | `_ipp._tcp→printing`、`_googlecast._tcp→media_player` |
| B8 | 服务目录校验严格 | `TestParseServiceTypeCatalogRejectsInvalid` | 无下划线前缀的服务名被拒绝 |
| B9 | 产品规则等价迁移 | `TestProductRulesAreDataDriven`、`TestProductRuleTableCarriesProvenance` | 仍为 8 条，4 个样例的 kind/manufacturer 不变，且 `version`/`source`/`source_url`/`license` 非空 |
| B10 | 生成脚本幂等 | 连续两次运行脚本并比对 sha256 | 两次退出码 0，产物哈希相同且与既有快照一致 |
| B11 | 旧 bundle 仍可加载 | `TestV6BuilderPreservesLegacyBundleReaders` | 通过（新表未进入 payload） |

## 3. 人工复核点

1. `snmp-enterprise-oid.json` 体积约 2.0 MB。若仓库对单文件体积有上限，需确认是否接受；
   文件为压缩性较差的 JSON 映射，未做额外编码。
2. `device-type-prior.json` 只覆盖打印/摄像/存储/IoT/部分网络厂商，**不覆盖手机与 PC**，
   这是刻意设计：Apple、Samsung 等厂商同时生产多类设备，先验会造成误判。
3. `model-catalog.json` 首版 33 条，少于计划中的 200 条。实施方选择不编造型号码映射，
   验收时应确认这是可接受的取舍，而不是遗漏。
4. `service-type-catalog.json` 位于 `internal/fingerprint/data/`，`product-rules.json` 位于 `internal/discovery/data/`，
   不属于 fingerprint bundle 的载荷，因此 bundle 白名单未包含它们。

## 4. 不通过判定

- B1–B9、B11 任一失败。
- 生成脚本对同一上游快照连续两次运行产生不同字节（脚本非幂等或版本号不稳定）。
- 任何数据文件缺少 `version` 或 `source`。

## 5. 交付物核对

- [x] `internal/fingerprint/data/{snmp-enterprise-oid,device-type-prior,model-catalog}.json`
- [x] `internal/discovery/data/{service-type-catalog,product-rules}.json`
- [x] `internal/fingerprint/{snmp_oid.go,prior.go,model_catalog.go}`
- [x] `internal/discovery/service_types.go`
- [x] `scripts/device-fingerprint/build-signature-tables.sh`
- [x] `docs/device-identification-signature-plan-20261027.md`

## 6. 执行记录（2026-10-27）

环境：分支 `codex/stream-storage-handoff-20261026`，工作区含未提交改动；Go 1.24.0 darwin/arm64；
无数据库、无部署。基线排除 `artifacts/shared-detail-deploy-184-20261023`（见 §0）。

| 断言 | 命令 | 结果 |
|---|---|---|
| B1 | §1 的 JSON 校验 | 通过（5 个文件全部合法） |
| B2 | `TestSignatureTablesCarryProvenance` | 通过（67,377 条，`iana-pen-2026-10-26`） |
| B3 | `TestParseSignatureTablesRejectInvalid` | 通过 |
| B4 | `TestSNMPOIDResolvesVendor` | 通过（置信度 0.85） |
| B5 | `TestModelCatalogResolvesMarketingName` | 通过（精确 + 前缀，未知码不命中） |
| B6 | `TestVendorPriorIsFallbackOnly` | 通过（≤0.80，不覆盖显式证据） |
| B7 | `TestServiceTypeCatalogCoversPrinterAndMedia` | 通过 |
| B8 | `TestParseServiceTypeCatalogRejectsInvalid` | 通过 |
| B9 | `TestProductRulesAreDataDriven`、`TestProductRuleTableCarriesProvenance`、`TestParseProductRulesRejectInvalid` | 通过（8 条，kind/manufacturer 不变，provenance 齐全） |
| B10 | `bash scripts/device-fingerprint/build-signature-tables.sh` 连续两次 | 通过：两次产物 sha256 均为 `ea0fc8549ccfe68226e1f4f251631fc981c40ef3f165841892cd1bba426f89dd`，与既有快照一致，无需回滚 |
| B11 | `TestV6BuilderPreservesLegacyBundleReaders` | 通过（v1–v5 兼容） |
| 补充 | `TestV6BundleRejectsSignatureTablePayload` | 通过（三张新表不得混入 v6 包） |
| 补充 | `TestDeviceLabelFixtureSnapshot` | 通过（42 台夹具快照无变化） |

构建与静态检查：

```bash
go build ./...                                  # 通过
go test ./internal/...                          # 通过
go vet $(go list ./... | grep -v '/artifacts/')  # 通过
gofmt -l <本任务改动文件>                        # 无输出
```

未覆盖项：
- `go vet ./...` 全量仍被基线包的 `undefined: NewServer` 打断，与 §0 排除口径一致。
- `internal/discovery/capture_linux.go`、`internal/fingerprint/consumer_router_rules_test.go`
  的 gofmt 差异属其他任务，本轮未处理。
- 前端未改动，未执行 `pnpm test`/`typecheck`/`build` 与三视口审查。

本任务改动文件：

- `internal/discovery/{product_rules.go,product_rules_test.go,service_types_test.go}`
- `internal/discovery/data/product-rules.json`
- `internal/fingerprint/{bundle.go,bundle_test.go,signature_tables_test.go}`
- `docs/device-identification-signature-{plan,acceptance}-20261027.md`
