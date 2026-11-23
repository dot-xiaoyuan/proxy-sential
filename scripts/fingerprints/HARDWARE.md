V8 被动硬件识别
================

`fingerprint.EvaluateHardware` 只接收同一完整网络作用域、已确认身份归属的字段。调用方负责地址租约、撤销及硬件事实的持久化；型号事实不随服务 TTL 自动消失。`Incomplete` 表示输入或结果超过限额，投影任务必须保留失败状态，不能把空结果当作完成。错误方向、未来时间、缺少原文引用和不可信归属分别计入 `RejectedReasons`。

新入口与旧 `IdentifyEvidence` 分离。V8 读取器兼容 V1–V7，旧识别路径不变。V8 在经验证的 V7 包上增加 `hardware-catalog.json`、`hardware-provenance.json`，保留旧文件原字节和校验值；规则更新也可用已验证的 V8 包为基底，替换硬件目录和来源，使用新的不可变版本。184 风险规则不调用硬件入口。

`SourceStatus=verified_bundle` 才表示实际安装的 V8 已加载，同时返回 `BundleVersion`、`BundleSchema` 和独立硬件规则 `Version`。已安装 V7 或无版本的旧库返回 `unavailable` 和 `Incomplete/Error`，不能暗中回退到内嵌硬件规则。未安装运行库的本地调用标为 `embedded_replay`，直接加载目录回放标为 `explicit_replay`；两者都不是现场启用状态。真实投影 worker 必须先检查 `verified_bundle`。SNMP 描述保留真实 CRLF；Zeek TSV 的转义只在协议适配器解码一次，匹配器不二次解释字面 `\x0d\x0a`。

可重复生成和验证：

```sh
python3 -m venv /tmp/hardware-rules-python
/tmp/hardware-rules-python/bin/pip install PyYAML==6.0.3
/tmp/hardware-rules-python/bin/python -m unittest discover -s scripts/fingerprints -p 'test_*.py'
/tmp/hardware-rules-python/bin/python scripts/fingerprints/build_hardware_catalog.py --output /tmp/hardware-catalog.json
go test ./internal/fingerprint ./scripts/fingerprints/hardware-report
go run ./scripts/fingerprints/hardware-report --input /path/to/attributed-fields.jsonl --output /tmp/hardware-report.json
go run ./scripts/fingerprints/hardware-report --build-v8-base /path/to/verified-v7-or-v8.tar.gz --bundle-output /tmp/fingerprint-v8.tar.gz --version NEW_IMMUTABLE_VERSION
```

CLI 不访问现场，不发送探测，不导入运行中的规则包。默认回放时间为当前 UTC；历史可重复回放使用 `--as-of RFC3339`。显式输入格式为 `{"id":"...","identity_trusted":true,"evidence":[{"protocol":"sadp","field":"sadp_model","value":"DS-K1T6QT-F72M","direction":"device","association":"direct","event_id":"original-reference","observed_at":"2026-11-11T00:00:00Z"}]}`。完整作用域必须由调用方分组，不能将不同传感器、VLAN/VRF 的同 MAC 合并。兼容现场导出的型号摘要时，仅 `direct_l2/direct/mac` 归属可参与判断；缺少归属或型号会明确跳过。

`Sources` 统计导入规则数、可执行数、具备输入的规则事件组合、实际命中和形成硬件类型的命中。它们不是设备数量、准确率或召回率。规则事件按来源族、协议、原文引用和规则去重；不同原文引用仍是不同观测。OpenWrt 的导入数是原字典行数，只有审定的精确型号可执行。`librenms_hardware` 单列硬件抽取阶段。报告输出 `Unsupported` 原因，不能将导入数宣传为可执行能力。

来源边界：

- 原生 `recog-go` 固定到 `v0.1.1-0.20230801014443-aa6fe9074750`；使用原先固定到 `1714aaed118861b4567bb6754920b4b929f59380` 的 Recog XML。保留原参数名、捕获、样例；编译或上游样例验证失败的条目不执行。SADP 不伪装为 SNMP 或 mDNS 输入，通用海康 Web 标记不确定硬件类型。客户端/TLS 线索不确定硬件类型或型号。
- LibreNMS 固定到 `4d34094b03c4846e3325a375ca6a94b43f1b1eda`。同一响应内才组合 AND 条件；分支及列表保持 OR，排除条件缺输入时不会满足。额外 OID 仅消费被动响应，没有查询动作。符号 OID、PHP、复杂转换、缺失的 `os_discovery` 原文等列出缺口，整项不降级为宽泛匹配。新增的 Comware/NetBotz/Vertiv 原文和 Vertiv MIB 保留在补充 provenance；不能根据 `network` 类或 H3C 厂商认定交换机。
- 统一型号规则有原文引用、SHA256、版本、依据及正反例。OpenWrt 只审定四个 WiFi Router 型号族，其余字典项不升级类型；路由器身份不产生共享违规结论。Canon MF260 保留系列粒度，不能推断具体 MF264/MF267/MF269 子型号。
- DHCPv4 明确型号只从有归属的有效 ACK 提取。V8 保留 ACK 的采集 VLAN 和租约时效。指定 `field: dhcp_product_model` 的规则按精确产品码核对，通用 Option 55、系统线索与客户端请求继续作为辅助证据。
- 正反例和人工构造协议测试是代码回放；现场导出字段的回放也不是原始 pcap 验收。报告必须保留真实样本、归属与协议覆盖的缺口。

### SNMP 响应字段保留与 IP 产品线索

`latest_partition` 是派生索引内部键，按已验证 SNMP 响应的字段/OID 集合哈希，不包含值，不改变原始标准事件或作用域身份。迁移 248 仅替换 latest 触发器，新旧观测可共存，不自动扫描历史回填；原文与紧凑历史沿用既有保留规则。读取仍只读维护后的索引，每种现场实际响应集合增加一行，重复响应更新同一行；分区没有独立缓存，无额外失效任务。统计仍以身份去重，不以字段分区计设备。

`IPProductClue` 只表示响应地址的产品自报，不构造 MAC 或硬件事实。产品注释最多 16 KiB，修复清单单行仍遵守 64 KiB 限额；匹配失败显式记录，不丢原观测。`reviewed-snmp-products.json` 保留限定的产品描述语法、厂商资料链接和正反例；企业 OID 的厂商识别不能替代产品类型判断。`scripts/fingerprints/ip-product-report` 可对固定作用域观测离线逐条输出结果及输入哈希，输出始终标记为 IP 产品回放而非物理设备确认。

### RTSP 角色与投屏兼容声明

`field: rtsp_user_agent` 仅接受经原文哈希校验的 RTSP 请求端自报。现场两条 `HIKVISION player NVR V...` 原文支撑显式录像设备角色；新 `type_only` 规则保留品牌、类型及原文依据，不把固件版本当型号。反向响应、普通播放器和仅厂商名不命中。204 的硬件门控开启时，RTSP 与 SNMP/SIP 一样生成 IP 级产品线索；缺同作用域 MAC 时不创建硬件身份。184 风险与旧分类入口未接入这项硬件规则，相关回归单独执行。

`_leboremote._tcp` 的 `packagename=com.tcl.MultiScreenInteraction_TV` 作为接收端软件证据保留，不映射 TCL 硬件品牌。同一可信作用域身份中，AppleTV 型号声明处于该公告有效窗口时，暂不作为苹果硬件型号确认。允许五分钟记录先后差；缺 TTL 的旧记录仅采用五分钟窗口。撤销的标记不参与判断，后续超出公告窗口的型号可重新评估，跨身份输入直接拒绝。原 TXT 和各服务证据不删除。

原文恢复器新增 `snapshot-original --original-kind rtsp-device` / `apply-original`，复用 DHCP 的行哈希、文件身份、固定 30 天窗口、2 MiB/5,000 条分页、1 MiB/50 条事务、背压与检查点流程。新 schema 为 `protocol-original-file-replay/v1`；旧 DHCP 清单和检查点保持原 schema/哈希语义。仅受控 RTSP 原文可进入新增入口，不改实时消费游标。

### DNS-SD 打印机原文归属与同批对照

`dns_sd_referenced_model` 规则从已有同作用域硬件事实读取精确型号、原始日志文件引用和记录摘要，并要求设备 MAC 命中该型号已审核的前缀。各条件同时满足才形成硬件类型。转发的广告可保留在原有观测中。此字段在旧应用的 V8 校验中会显式报错。

`passive-hardware-audit --input snapshot.jsonl --baseline-bundle old.tar.gz --candidate-bundle new.tar.gz --output comparison.json` 使用本地冻结文件比较类型、型号、冲突和证据。输入首行包含 `kind=meta`、`from`、`as_of` 和 `cohort`，后续每行包含 `kind=device`、`key`、`split`、`state`、`facts` 和 `overflow`。身份 SHA-256 首字节小于 179 的记录进入开发集，`--development-only` 只评估该组。导出保存截止前的支持事实、撤销记录及实际投影状态，并记录来源水位。回放输出保留输入哈希、超限和现场状态与截止回放的差异。

### DHCP 产品自报及 SSDP 原文复核

204 的 DHCP 租约同时保留 Zeek 的原有厂商提示和实际 Option 60 产品字段。交换机规则要求同一次 REQUEST/ACK 的地址、MAC 与采集 VLAN 一致，有文件和行摘要，Option 60 为 `CloudSwitch_1`，主机名中的型号和 MAC 末四位符合已审定的 H3C 前缀。另外四项审定型号覆盖华为 AirEngine 5762-10、TP-Link YLS220-24G2F 和 TL-SG2008D，以及 H3C NX30。AP 的主机名还必须含同一 MAC 的全长字符串。海康 DS-IPC-B12-I 规则要求有可信归属的 SADP 产品响应及载荷摘要。

华为手机和平板的完整产品码可以给出品类线索。类型取自官方清单，厂商字段与主机名必须在同一条有原文引用的租约记录中完全相符。租约中的 `dhcp_candidate_type` 用于候选筛选，硬件事实中的 `dhcp_reported_model` 保留自报码。客户端 HTTP 型号适合独立复核，核对时使用请求方 IP、原文时间和完整作用域，并排除歧义绑定。[华为设备型号清单](https://developer.huawei.com/consumer/cn/doc/harmonyos-releases/support-device/)

新采集的 SSDP 观测保留原始 sidecar JSONL 行摘要。普通入库保留文件身份、批次范围和批次摘要，流式入库保留文件身份与源偏移。该摘要校验采集器的输出记录。核对历史采集记录需实际匹配原有事件、时间、作用域和产品字段。
