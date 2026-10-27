# 设备/路由器识别：特征数据实施记录（2026-10-27）

## 目标

在既有 OUI / Fingerbank / uap-core / multisource catalog 之上，补齐四类缺失特征，
全部以数据文件形式落地、带 provenance、可离线校验、可独立度量。

## 已落地数据表

| 表 | 文件 | 规模 | 来源 | 用途 |
|---|---|---|---|---|
| SNMP 企业号 | `internal/fingerprint/data/snmp-enterprise-oid.json` | 67,377 条 / 2.01 MB | IANA Private Enterprise Numbers（2026-10-26） | `sysObjectID` → 厂商 |
| 厂商类型先验 | `internal/fingerprint/data/device-type-prior.json` | 51 条 | 人工按产品线整理 | 哑终端兜底类型 |
| 型号目录 | `internal/fingerprint/data/model-catalog.json` | 33 条 | 厂商型号码公开资料（经验证子集） | 型号码 → 商品名 |
| 服务类型目录 | `internal/fingerprint/data/service-type-catalog.json` | 20 条 | IANA 服务名注册表 | mDNS 服务 → 能力/品类 |
| 产品规则 | `internal/discovery/data/product-rules.json` | 8 条 | 由代码迁出 | SSDP/SNMP 型号 → 产品族 |

## 新增 Go API

```go
// internal/fingerprint
func LookupSNMPVendor(oid string) (vendor string, confidence float64, ok bool)  // 0.85
func LookupVendorPrior(vendor string) (deviceType string, confidence float64, ok bool) // ≤0.80
func LookupModel(code string) (brand, model, deviceType string, confidence float64, ok bool) // ≤0.95
func ParseSNMPOIDTable([]byte) (*SNMPOIDTable, error)
func ParseVendorPriorTable([]byte) (*VendorPriorTable, error)
func ParseModelCatalog([]byte) (*ModelCatalog, error)
// 均有对应 Set* 用于测试与后续 bundle 注入

// internal/discovery
func ServiceCapabilities(serviceType string) ([]string, bool)
func ServiceProductKind(serviceType string) (string, bool)
```

## 查找与兜底规则

- **SNMP**：只接受 `1.3.6.1.4.1.<n>` 形式（或裸数字），前缀不匹配一律拒绝，
  避免任意 sysObjectID 解析出无关厂商。仅在 OUI 未给出厂商时使用。
- **型号**：精确 → 最长前缀（如 `SM-G991B/DS`）。型号命中优先级高于正则规则，
  规则仅补 OS 与空类型。
- **厂商先验**：精确优先，否则最长 `contains`；仅在设备类型为空且已知厂商时使用，
  置信度上限 0.80，永不确认品牌。
- **服务类型**：命中即写能力；表中缺该服务名时回退代码内 switch。表本身非法时与其他内嵌表一致，
  在启动阶段快速失败，不做静默降级。

## provenance 与许可

所有表带 `version`/`source`/`source_url`/`license`：
- IANA 企业号与服务名注册表：公开注册表，文件头标注来源 URL 与快照日期。
- 人工整理表：`internal-rule`，版本号随内容递增。

产品规则表在收口时改为 `{version, source, source_url, license, entries}` 信封；此前是裸数组，
四项 provenance 全缺，与验收 §4「任何数据文件缺少 version 或 source 即不通过」冲突。

## 生成与校验

```bash
# 重新生成 SNMP 企业号表（幂等；低于 4 万条会拒绝写入）
bash scripts/device-fingerprint/build-signature-tables.sh

# 校验
go test ./internal/fingerprint/ -run 'TestSNMP|TestModelCatalog|TestVendorPrior'
go test ./internal/discovery/
```

脚本只下载 IANA 公开注册表；型号目录与厂商先验为人工维护，不联网生成。

## 与计划的偏差

| 计划 | 实际 | 原因 |
|---|---|---|
| 型号目录首版 200 条 | 33 条 | 只收录可核实的型号码；不编造型号码—商品名映射，后续靠采集闭环增长 |
| 新表进入 bundle | 仅嵌入；bundle 白名单不预埋 | 预埋时三张表既不在 manifest 校验和内、也无加载路径：新 reader 会接受并静默丢弃，旧 reader 会拒绝同一个包。随 V7 schema 一并加入 |
| 覆盖 42 台夹具并设覆盖率阈值 | 改为快照回归 | 夹具以虚拟机与 `Unknown` 厂商为主，无法度量覆盖率；快照可防回归 |

## 已知缺口

- DHCP option 55 指纹仍依赖 Fingerbank 公共快照，中国设备覆盖弱，未自建。
- 型号目录规模小，主要价值在链路打通与 schema 定型。
- OUI 全量仍由 bundle 构建时合并 IEEE 注册表；内嵌 `oui.csv` 保持最小种子。

## 收口变更（2026-10-27）

- `product-rules.json` 加 provenance 信封；`parseProductRules` 校验 `version`/`source`，
  新增 `TestProductRuleTableCarriesProvenance`、`TestParseProductRulesRejectInvalid`。
- `VerifyBundleBytes` 白名单移除三张新表，新增 `TestV6BundleRejectsSignatureTablePayload`
  锁定「未升 schema 不得随包携带」。
- 清理测试遗留：删除未使用的 `countNonEmptyModel` 与快照测试中先算后丢的 `encoded`。
- 验收结果见 [特征数据验收计划](device-identification-signature-acceptance-20261027.md) §6。

