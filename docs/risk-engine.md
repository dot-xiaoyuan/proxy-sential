# 证据与风险评分

## 设计目标

旧版系统容易把单个特征阈值当成代理结论。新版风险引擎必须区分：

- Signal：原始事件。
- Evidence：可解释证据。
- Risk：多证据评分结果。
- Decision：策略动作。

## Evidence 结构

```json
{
  "evidence_id": "01J...",
  "ip": "10.1.2.3",
  "type": "multi_user_agent",
  "window": "10m",
  "score": 25,
  "confidence": 0.8,
  "severity": "medium",
  "reason": "10 分钟内出现 4 个差异明显的 User-Agent",
  "samples": [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"
  ],
  "created_at": "2026-07-22T10:00:00Z"
}
```

## RiskSnapshot 结构

```json
{
  "ip": "10.1.2.3",
  "score": 72,
  "level": "high",
  "confidence": 0.86,
  "window": "10m",
  "evidence_ids": ["01J..."],
  "summary": "多 UA、多 JA3 和 TTL 多簇共同指向共享上网",
  "recommended_action": "shadow_slowdown",
  "updated_at": "2026-07-22T10:00:00Z"
}
```

当前 CLI：

```bash
proxy-sentinel risk inspect --input evidence.json --ip 10.1.2.3
proxy-sentinel risk batch --input evidence.json --output risk-snapshots.json
proxy-sentinel risk list --input risk-snapshots.json --min-level suspicious --limit 50
```

风险层只读取 evidence 输出，不读取标准事件或采集后端原始字段。当前
`recommended_action` 只输出影子建议：`record`、`shadow_watch`、
`shadow_manual_review`、`shadow_confirm_review`，不触发处罚动作。

## 风险等级

| 分数 | 等级 | 含义 | 默认动作 |
| --- | --- | --- | --- |
| 0-29 | normal | 正常 | 记录 |
| 30-59 | suspicious | 可疑 | 观察或通知 |
| 60-79 | high | 高风险 | 影子降速或人工复核 |
| 80-100 | confirmed | 基本确认代理 | 按策略处罚 |

## 第一批证据规则

当前 CLI：

```bash
proxy-sentinel evidence --input events.jsonl --output evidence.json --window 10m
```

证据层只读取标准事件，不读取 Suricata 原始字段。所有证据输出都必须包含
`evidence_id`、`ip`、`type`、`window`、`score`、`confidence`、`severity`、
`reason`、`samples`、`created_at`。

### multi_user_agent

同一 IP 在窗口内出现多个差异明显的 User-Agent。

基础分：20-35。

加权：

- UA 对应不同 OS，加 10。
- UA 同时出现移动端和 PC，加 10。
- UA 出现明显模拟器或脚本特征，加 5。

降权：

- 仅浏览器版本差异，降 15。
- 命中已知系统组件，降 10。

### multi_ja3_ja4

同一 IP 在窗口内出现多个 TLS 指纹。

基础分：15-30。

加权：

- JA3/JA4 与 UA OS 不一致，加 15。
- JA3/JA4 数量和 UA 数量同时异常，加 15。

降权：

- 只有常见浏览器和系统服务组合，降 10。

### ttl_clusters

同一 IP 出现多个稳定 TTL 簇。

基础分：20-40。

加权：

- TTL 簇对应不同 UA/设备指纹，加 20。
- TTL 簇长期稳定，加 10。

降权：

- 只有少量样本，降 15。
- 路径变化明显，降 10。

### domain_diversity

DNS/SNI/HTTP Host 多样性异常。

基础分：10-25。

注意：该规则不能单独确认代理，只能作为辅助证据。

### port_distribution

目的端口分布或连接模式异常。

基础分：10-25。

注意：下载器、游戏、加速器可能误报，需要负证据修正。

### vpn_proxy_rule_match

Suricata `alert` 标准事件命中代理、VPN、隧道或翻墙规避相关规则。

基础分：68-78。

这是翻墙监测高置信证据，样本必须保留 `signature_id`、`signature`、
`category`、`severity` 等可复核字段。单条命中只进入 high 影子复核；
需要多个非弱证据互相印证才进入 confirmed。

### vpn_proxy_domain_hint

DNS、TLS、HTTP 或 QUIC 的可见域名/SNI/Host 中出现代理、VPN 或隧道关键词。

基础分：30-48。

这是中置信线索，不能替代规则命中。常见远程办公、企业 VPN、测试域名和
安全服务需要通过 labels 与负证据降权。

### encrypted_tunnel_behavior

窗口内出现 QUIC 或 UDP/443 加密传输行为。

基础分：14-25。

这是低置信评分特征，不能单独定性为翻墙、代理或共享上网。视频会议、网盘、
游戏、浏览器 QUIC 和 CDN 流量都可能产生该信号。

### multi_device_fingerprint

DHCP、mDNS、NBNS、LLMNR、UA parser、MAC OUI 等来源指向多个设备。

基础分：35-60。

这是强证据，但必须保留来源和样本。

### dhcp_device_fingerprint

同一 IP 在窗口内出现 Zeek DHCP 设备画像。

基础分：28-40。

样本由 hostname、vendor_class、requested_options、client_mac 等字段组成。该信号
来自局域网协议栈，可信度高于 User-Agent。第一阶段不调用 Fingerbank 在线查询，
只做本地轻量归类。

### device_fingerprint_conflict

同一 IP 在窗口内出现互斥 DHCP 设备画像，或 DHCP 画像与多个 TLS 客户端指纹
同时出现。

基础分：34-58。

Apple/iOS、Windows、Android、ChromeOS、Linux 等设备族混杂时，疑似共享上网
或代理出口。该规则可以参与 `confirmed`，但仍只输出影子复核动作。

## 账号级强证据

身份关联事件进入标准事件后，证据层可以输出 `subject_type=account` 的账号级
证据。该类证据不再依赖单个 IP 是否稳定，主要服务于校园账号共享上网复核。

### account_concurrent_macs

同一账号在窗口内关联两个及以上 endpoint MAC。该证据来自 RADIUS、Portal、
802.1X、DHCP、交换机或无线 AC 等身份数据，属于高置信复核证据。

### account_concurrent_endpoints

同一账号在窗口内关联两个及以上终端实体。仅当 MAC 不足以判定时作为补充，
需要结合换机、重认证和漫游情况复核。

### account_concurrent_access

同一账号短时间内出现在多个接入位置，例如不同 AP 或交换机端口。需要排除
无线漫游切换和认证日志延迟。

### auth_observed_mac_mismatch

认证 MAC 与实际观测 MAC 不一致。该证据属于强复核信号，应保留认证来源、
观测来源、窗口和样本。

基础设施、网关、NAT、服务器和网络设备角色不得进入普通终端并发和账号共享
设备数统计。缺少明确终端身份时，`entity_role=unknown` 只能作为保留事件，
不能直接升级为 endpoint。

## 负证据

以下情况不能直接放过，但要降权或进入特殊分类：

- 加速器。
- 模拟器。
- 下载器。
- 校园网认证组件。
- 系统更新服务。
- 白名单用户、白名单 MAC、白名单 IP。
- 测试网段。

## 决策原则

- 单个弱证据不能处罚。
- 单个强证据可以高风险，但建议先影子模式。
- 多个中强证据互相印证才进入 confirmed。
- 所有处罚必须可回放、可解释、可撤销。

当前实现约束：

- `domain_diversity`、`port_distribution` 和 `encrypted_tunnel_behavior` 被视为弱证据。
- 只有弱证据时，风险最多进入 `suspicious`。
- `confirmed` 需要总分达到阈值，并且至少包含两类非弱证据。

## 翻墙复核聚合

`GET /api/v1/proxy-reviews?window=7d` 在标准事件层之上聚合 TLS、QUIC 和明确
代理规则 alert。聚合维度为账号、endpoint 与 IP，输出接入位置、目的 IP/SNI、
协议分布、规则命中、首次/末次时间、持续时长以及关联风险与人工复核状态。

该聚合只服务于影子复核展示：高置信来自明确规则命中，中置信来自代理/VPN
域名线索，普通 QUIC、视频会议和 UDP/443 长连接保持低置信。页面复核动作仍须
携带标准 `evidence_ids`，没有证据时禁止写 label，聚合结果本身不直接触发处罚。
