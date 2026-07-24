# 192.168.0.30 Suricata 镜像流量测试

## 目标

在测试机 `192.168.0.30` 上采集镜像口流量，产出可回放的 Suricata EVE JSONL 样本，为 Sprint 1 的 `suricata-adapter` 提供真实 fixture。

本阶段只做影子模式采样，不接风险引擎，不执行降速、踢线、封禁等处罚动作。

## 测试机准备

把仓库同步到 `192.168.0.30` 后执行：

```bash
sudo scripts/suricata/prepare-testbed.sh
```

脚本支持 Debian/Ubuntu 和 openEuler。openEuler 使用 DNF，`iproute2`
对应的包名为 `iproute`。openEuler 22.03 官方仓库不提供 Suricata；如果当前
配置的软件源也不包含该包，脚本会安装其余基础工具并提示先从可信软件源或
[Suricata 官方源码安装文档](https://docs.suricata.io/en/latest/install.html)
完成 Suricata 安装，再重新运行准备脚本。

openEuler 22.03 测试机可以直接使用仓库内的源码安装辅助脚本：

```bash
sudo scripts/suricata/install-suricata-source-openeuler.sh
sudo scripts/suricata/prepare-testbed.sh
```

该脚本默认从 Suricata 官方源码包安装 `6.0.20`，安装到 `/usr`，配置文件放在
`/etc/suricata/suricata.yaml`，与采样脚本默认路径一致。

确认镜像口：

```bash
scripts/suricata/select-mirror-if.sh
```

选择规则：

- 优先使用 `eth1`。
- 如果没有 `eth1`，选择非默认路由且 RX 字节持续增长的网卡。
- 管理网口和镜像流量网口应分离。

## 采样流程

运行 30 分钟采样：

```bash
sudo scripts/suricata/capture-mirror-sample.sh --interface auto --duration 1800
```

脚本会执行：

- `tcpdump` 抓取 100 个包，验证镜像口有流量。
- `suricata -T` 验证配置。
- 使用 Suricata 前台采集镜像口流量。
- 将本次运行日志写到 `/tmp/proxy-sentinel/mirror-YYYYMMDD-HHMMSS/`。
- 导出原始 EVE 样本到 `/tmp/proxy-sentinel/eve-mirror-YYYYMMDD-HHMMSS.jsonl`。

脚本默认使用隔离日志目录，不覆盖系统已有的 `/var/log/suricata/eve.json`。

## 验收

检查事件覆盖：

```bash
scripts/suricata/validate-eve-sample.sh /tmp/proxy-sentinel/mirror-YYYYMMDD-HHMMSS/eve.json
```

验收标准：

- `flow`、`dns`、`tls`、`http` 中至少覆盖 3 类。
- 覆盖到的核心事件类型每类至少 10 条。
- DNS 样本能看到查询域名。
- TLS 样本能看到 SNI、JA3 或 JA4。
- HTTP 样本能看到 Host 或 User-Agent。

如果 10 分钟内无法看到 DNS/TLS/HTTP 关键字段，先调整镜像口、交换机镜像策略或测试流量源，不进入 adapter 开发。

## 脱敏 fixture

从原始 EVE 样本生成 200-1000 行脱敏样本：

```bash
scripts/suricata/anonymize-eve-sample.py \
  --input /tmp/proxy-sentinel/eve-mirror-YYYYMMDD-HHMMSS.jsonl \
  --output /tmp/proxy-sentinel/eve-mirror-redacted.jsonl \
  --limit 1000 \
  --min-lines 200
```

脱敏样本用于后续 adapter fixture。原始大文件保留在测试机或 `.gitignore` 覆盖的目录下，不进入版本管理。

脱敏规则：

- IP 使用固定映射替换，保留同一原始 IP 的关联关系。
- 域名替换为 `domain-N.example.test`。
- MAC 和用户标识替换为稳定假值。
- User-Agent 替换为稳定摘要值。

## Adapter 开发前置条件

进入 Sprint 1 adapter 开发前，必须具备：

- 一份通过校验的原始 EVE JSONL 样本。
- 一份 200-1000 行脱敏 EVE JSONL 样本。
- 样本覆盖正常行、多事件类型、缺字段和 malformed line 测试场景。
- 后续 CLI 边界保持为：

```bash
proxy-sentinel adapter suricata --input eve.json --output events.jsonl
```
