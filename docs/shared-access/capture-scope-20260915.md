# 实际采集范围与共享证据验证（2026-09-15）

## 本地实现

新增 `capture-scope/v1` 受控范围配置。配置包含传感器、采集实例、园区、接入域及 `[valid_from, valid_until)` 有效区间，最大 64 KiB，未知字段、尾随 JSON 和无效区间拒绝加载。

Suricata、Zeek 适配器和增量采集支持 `--capture-scope-config`。实时 TTL 采集同时支持 `--collector-instance-id` 与同一配置。实例必须对应实际采集进程；不同采集进程应分别维护有效配置，不应为省事共用虚假的实例标识。

范围只在符合配置的采集事件上附加，不修改传入对象。旧时间、实例重启、身份范围冲突会保留事件并写入 `capture_scope_issue`，共享窗口把它视为不完整/冲突。TTL 事件身份纳入实例、接口和 MAC，防止重启或不同观测合并为相同事件 ID。

缺省配置保持旧采集行为，但缺少接入范围的事件无法满足共享归责。正常原始事件、旧风险规则和其他流量统计继续保留。

## 隔离实采结果

- 四组既有 NAT 实验抓包转换出 79,806 条标准事件，通过明确的实验范围映射校验。此项是受控实验回放，不是给生产历史流量补写当前归属。
- 新建一次异构 NAT 实验，在路由容器内运行实际 Linux AF_PACKET TTL 采集器。输出 17 条 TTL 标准事件；出口观察到 63 和 127，两者均带受控范围、实例和配置摘要。
- 合并本次 Suricata 及 TTL 共 19,973 条标准事件，构造共享窗口后检测到 UA、TTL、TLS 三组独立信号。
- 无认证会话输入时，结果为证据不足、账号未知。加入显式实验身份 fixture 后，结果为 `basis_present`、设备下界为 1，不虚构两台已确认终端。
- 原始依据保留 Suricata 和 packet-sidecar 双来源引用及实例。实采容器和网络已清理。

这证明隔离环境中的“真实流量 → 实际采集/解析 → 标准事件 → 共享评估”链路，不证明真实认证归属、账号处罚、校园准确率或数据库端到端性能。实验身份不是 190 的认证数据。

## 验证与复现

全量 Go 测试通过；normalized、采集适配、TTL、实时处理、证据包竞态测试通过；Linux ARM64 构建通过。实采回放 `TestSharedLiveCaptureReplay` 竞态测试通过。

```sh
GOOS=linux GOARCH=arm64 go build -o /tmp/sentinel-capture-scope-linux ./cmd/proxy-sentinel
SENTINEL_CAPTURE_BINARY=/tmp/sentinel-capture-scope-linux scripts/testbed/campus/run-nat.sh heterogeneous
SENTINEL_SHARED_CAPTURE_DIR=<上一步目录> go test -race ./internal/evidence -run '^TestSharedLiveCaptureReplay$' -count=1 -v
```

本轮记录在 `artifacts/shared-access-capture/`。本次实采目录见 `live-ttl-report.json`。软件配置和采集范围文件随实验结果保存。

## 剩余事项

- 190 真实权威身份清单接入、测试账号认证与当前会话验证。
- 共享证据的案件/执行历史展示、人工确认、控制器动作及对应恢复。
- 生产来源范围部署、实例生命周期管理、系统级压力与故障恢复验收。
- 影子准入及人工标注通过前，不开放共享自动处置。

本轮没有生产部署或账号动作。
