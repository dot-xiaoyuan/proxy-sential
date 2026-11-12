V8 被动硬件识别
================

`fingerprint.EvaluateHardware` 只接收同一完整网络作用域、已确认身份归属的字段。调用方负责地址租约、撤销及硬件事实的持久化；型号事实不随服务 TTL 自动消失。`Incomplete` 表示输入或结果超过限额，投影任务必须保留失败状态，不能把空结果当作完成。错误方向、未来时间、缺少原文引用和不可信归属分别计入 `RejectedReasons`。

新入口与旧 `IdentifyEvidence` 分离。V8 读取器兼容 V1–V7，旧识别路径不变。V8 在经验证的 V7 包上增加 `hardware-catalog.json`、`hardware-provenance.json`，保留旧文件原字节和校验值；规则更新需要新的不可变版本。184 风险规则不调用硬件入口。

`SourceStatus=verified_bundle` 才表示实际安装的 V8 已加载，同时返回 `BundleVersion`、`BundleSchema` 和独立硬件规则 `Version`。已安装 V7 或无版本的旧库返回 `unavailable` 和 `Incomplete/Error`，不能暗中回退到内嵌硬件规则。未安装运行库的本地调用标为 `embedded_replay`，直接加载目录回放标为 `explicit_replay`；两者都不是现场启用状态。真实投影 worker 必须先检查 `verified_bundle`。SNMP 描述保留真实 CRLF；Zeek TSV 的转义只在协议适配器解码一次，匹配器不二次解释字面 `\x0d\x0a`。

可重复生成和验证：

```sh
python3 -m venv /tmp/hardware-rules-python
/tmp/hardware-rules-python/bin/pip install PyYAML==6.0.3
/tmp/hardware-rules-python/bin/python -m unittest discover -s scripts/fingerprints -p 'test_*.py'
/tmp/hardware-rules-python/bin/python scripts/fingerprints/build_hardware_catalog.py --output /tmp/hardware-catalog.json
go test ./internal/fingerprint ./scripts/fingerprints/hardware-report
go run ./scripts/fingerprints/hardware-report --input /path/to/attributed-fields.jsonl --output /tmp/hardware-report.json
go run ./scripts/fingerprints/hardware-report --build-v8-base /path/to/verified-v7.tar.gz --bundle-output /tmp/fingerprint-v8.tar.gz --version NEW_IMMUTABLE_VERSION
```

CLI 不访问现场，不发送探测，不导入运行中的规则包。默认回放时间为当前 UTC；历史可重复回放使用 `--as-of RFC3339`。显式输入格式为 `{"id":"...","identity_trusted":true,"evidence":[{"protocol":"sadp","field":"sadp_model","value":"DS-K1T6QT-F72M","direction":"device","association":"direct","event_id":"original-reference","observed_at":"2026-11-11T00:00:00Z"}]}`。完整作用域必须由调用方分组，不能将不同传感器、VLAN/VRF 的同 MAC 合并。兼容现场导出的型号摘要时，仅 `direct_l2/direct/mac` 归属可参与判断；缺少归属或型号会明确跳过。

`Sources` 统计导入规则数、可执行数、具备输入的规则事件组合、实际命中和形成硬件类型的命中。它们不是设备数量、准确率或召回率。规则事件按来源族、协议、原文引用和规则去重；不同原文引用仍是不同观测。OpenWrt 的导入数是原字典行数，只有审定的精确型号可执行。`librenms_hardware` 单列硬件抽取阶段。报告输出 `Unsupported` 原因，不能将导入数宣传为可执行能力。

来源边界：

- 原生 `recog-go` 固定到 `v0.1.1-0.20230801014443-aa6fe9074750`；使用原先固定到 `1714aaed118861b4567bb6754920b4b929f59380` 的 Recog XML。保留原参数名、捕获、样例；编译或上游样例验证失败的条目不执行。SADP 不伪装为 SNMP 或 mDNS 输入，通用海康 Web 标记不确定硬件类型。客户端/TLS 线索不确定硬件类型或型号。
- LibreNMS 固定到 `4d34094b03c4846e3325a375ca6a94b43f1b1eda`。同一响应内才组合 AND 条件；分支及列表保持 OR，排除条件缺输入时不会满足。额外 OID 仅消费被动响应，没有查询动作。符号 OID、PHP、复杂转换、缺失的 `os_discovery` 原文等列出缺口，整项不降级为宽泛匹配。新增的 Comware/NetBotz/Vertiv 原文和 Vertiv MIB 保留在补充 provenance；不能根据 `network` 类或 H3C 厂商认定交换机。
- 统一型号规则有原文引用、SHA256、版本、依据及正反例。OpenWrt 只审定四个 WiFi Router 型号族，其余字典项不升级类型；路由器身份不产生共享违规结论。Canon MF260 保留系列粒度，不能推断具体 MF264/MF267/MF269 子型号。
- 正反例和人工构造协议测试是代码回放；现场导出字段的回放也不是原始 pcap 验收。报告必须保留真实样本、归属与协议覆盖的缺口。
