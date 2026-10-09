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

### multi_user_agent（历史兼容，停止生成）

原始 UA 多样性只表示客户端软件、浏览器或运行时变化，不能推导物理设备数量。新版本不再生成该证据；历史快照仍可读取，以保持审计可追溯。

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

### ai_relay_domain_usage

DNS、TLS、HTTP 或 QUIC 的可见域名/SNI/Host 命中 `internal/airelay` 中登记的 AI API 中转站域名。

基础分：26-42。

这是弱证据，只证明访问了中转站域名，不证明发生了模型调用。域名会更换、会重用，也可能与其他站点共享 CDN；必须结合账号与人工复核。指标资产、来源与局限见 `docs/ai-relay-detection.md`。

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
代理规则 alert。详情地址按 IP 保持稳定，只有所有参与聚合的事件归属一致时才展示账号和 endpoint，输出接入位置、目的 IP/SNI、
协议分布、规则命中、首次/末次时间、持续时长以及关联风险与人工复核状态。

该聚合只服务于影子复核展示：规则命中须沿用标准事件中明确声明的置信度，缺少声明时为中置信，SOCKS greeting 和 HTTP CONNECT 提示不自动提升为高置信；明确高置信协议规则保留高置信。代理/VPN 域名线索为中置信，普通 QUIC、视频会议和 UDP/443 长连接保持低置信。页面复核动作仍须
携带标准 `evidence_ids`，没有证据时禁止写 label，聚合结果本身不直接触发处罚。

代理关键词按完整词或明确应用名称识别，不能将 `store`、`history` 内的 `tor` 或 `greeting` 内的 `gre` 算作代理线索。编号 VPN/proxy 域名标签及 SOCKS4/5、OpenVPN、TorBrowser、v2rayN 等明确名称保留识别。域名线索在证据和复核路径共同排除现有校园 VPN 域名规则。置信元数据只读取精确的字段或声明，`highly_unreliable` 和说明文字不能匹配 `high`；同条记录的冲突声明取较低置信度。低置信规则仍保留原始命中，但生成的线索证据最高 20 分、0.4 置信度，不能升级为高置信依据。`examples/proxy-review/hint-boundaries.jsonl` 覆盖标准事件、证据、风险与复核之间的一致性。

告警分类读取规则本身的签名与分类，识别前去除项目规则命名空间。`PROXY_SENTINEL` 前缀、采集来源、说明文字及 `proxy_sentinel_confidence` 字段名不能单独产生代理规则证据；只有规则已被识别为代理/VPN/隧道线索后，其精确置信声明才用于确定证据层级。原签名和元数据保留在标准事件中，方便审计。

身份关联以每条标准事件的实际时间及传感器、校区范围为准，身份记录不能反向解释发生在它之前的流量。登出关闭旧关联；同一时间身份冲突或流量时间段跨越身份变化时，不推断账号和终端组合。明确写在事件主体上的身份保留，但与历史身份冲突时不拼接其他身份字段。IP 聚合混合不同账号、终端或部分身份缺失时，只保留全体事件一致的字段，并提示按事件时间核验。ClickHouse 聚合须按原始标准事件的传感器、校区、账号和终端分组，防止在进入复核逻辑前丢失归属差异。

风险补充必须匹配真实主体和 IP。账号、终端风险快照中的 IP 仅是上下文，不作为 IP 风险的别名；快照明确包含的账号、终端绑定也必须与复核记录一致。混合身份的聚合不能继承其中一个账号的证据、分数或人工复核结论。

风险案件的旧处置 API 在创建动作与实际发送前均校验当前依据。快照时间、窗口和动作引用的每条证据必须有效且未过期；未来时间、缺失窗口、引用丢失或换成其他账号/IP 的证据不能支持处罚。旧规则的高置信回退只允许引用集合中的有效规则，不能从同 IP 的其他历史规则借用强信号。待发送动作的有效期、案件结论、当前账号/终端/会话和例外策略均再次校验，风险降级或归属变化后阻止发送。

此路径的当前认证会话复用策略层的登记来源、心跳有效性及冲突校验，并保留身份置信度至少 0.8 的门槛。仅有“没有登出”的历史记录、未登记来源或未来登录不构成当前会话。数据库发送前只定向读取最新案件头，不依赖缓存中的身份，也不加载证据历史或获取全局 operations 锁。释放、撤销及到期恢复不要求违规证据继续存在；账号策略、共享发现和明确代理事务的已有人工授权校验继续保留。

## 2026-09-30 现场误报收敛

UA 的系统文案、TLS 指纹多样性与 TTL 差异只属于行为线索。这些线索叠加也不能建立物理设备身份，缺少可信设备族或并发认证身份时，风险分类保持 `behavioral_only`，最高 59 分。旧的 `device_signal_conflict` 混合了软件与协议差异，不能再充当身份锚点；`device_fingerprint_conflict` 也只是历史画像集合：名称、DHCP 画像差异可能来自顺序租约或局域网广播，不能证明并发；新生成记录降为最高 30 分、0.65 置信度，旧记录保留但不能充当身份锚点。旧的 `account_concurrent_*` 也是窗口内的关联集合，不证明会话重叠。MAC、实体、接入位置差异降为最高 30 分、0.65 置信度的复核线索，风险引擎不把旧高置信集合当作并发锚点。通用 `behavioral_only` 结果最高 59 分、0.79 置信度。真实硬件并发确认由当前共享发现窗口完成，真实账号并发由策略引擎对权威会话做时点、有效性和身份冲突校验。

终端库存不再按 JA3/JA4 指纹创建物理设备候选；协议指纹保留在原始信号中。仅有 UA、TLS 等弱线索时，不把弱线索包计作普通终端，不把整批协议上下文重复附到每个候选上。这同时避免单个 IPv6 地址产生数千个虚构设备与重复快照。

共享发现继续采用 `shared-behavior/v11`：当前窗口的有效 IEEE1905 多客户端关联，或重复硬件型号并发且有 TCP/TLS 佐证，才能确认共享。24 小时参考历史不充当当前并发设备数，历史共享结论不循环支撑新的路由器结论。

## TTL 初始簇与路径变化

IPv4主机TTL线索仅来自适用的单播标准事件。同一方向的63/64、126/127等同一推测初始TTL簇内的跳数变化，生成零分`ttl_path_variation`说明；保留原始路径样本和证据ID，不累计风险分，也不作为独立共享信号。不同方向不能互相拼接为多主机线索。

同一方向出现不同推测初始TTL簇时，仍生成弱`ttl_clusters`；每个初始簇只计一次，不因其中跳数变体多而抬高分数。共享窗口还要求不同初始簇各自具有足够的独立标准事件并重复共现；一个短暂的新簇不能借用两个同簇路径的共现。共享行为规则为`shared-behavior/v12`，账号共享规则为`shared-access/v4`。硬件型号共现和IEEE1905明确接入证据的强分支独立保留。

初始TTL是按常见上界推测，不等于已识别的操作系统或设备身份。[RFC791](https://www.rfc-editor.org/rfc/rfc791.html)规定TTL在IP处理过程中递减；因此单纯跳数变化不足以证明更多主机。风险引擎统计计分证据类型时忽略零分说明，零分条目不增加强证据数量，也不放宽单弱信号评分上限。风险摘要只列计分贡献，所有说明证据仍保留在审计ID中。

IP 设备库存的冲突解释只比较同类线索。DHCP 的 `device_hint` 与客户端 Vendor Class 先归并家族：`linux`/`dhcpcd-16`、Windows/MSFT 或客户端版本变化不形成两台设备；Android、ChromeOS 与通用 Linux 客户端也不互相充当排他身份。实际系统线索分歧仅为中置信复核依据，不证明并发共享。JA3 与 JA4 分别比较，同一握手的两种编码不能混算为客户端数量。TTL 与 IPID 不再拼成 TCP 栈冲突，原始包字段仍保留。旧库存读取时按现行规则重算冲突解释与设备置信度，候选身份、来源信号、原始存储快照不修改。

IP 风险详情的 `window=none` 表示没有有效评估，不展示正常零分、零置信度或请求时刻作为评估时刻；说明文本仍保留。真实风险窗口展示分数、置信度、计分依据、证据 ID 和中文影子建议动作。

通用 DHCP 客户端不能单独支持 Linux/desktop 设备画像。新标准事件不再据此生成 Linux 提示；库存和风险家族推断也排除旧适配器从这类客户端派生的 Linux 提示。旧库存读取时，若 Linux/desktop 只有通用 DHCP/软件来源，缺少独立系统或类型依据，撤销该属性展示结论，原始信号、MAC 候选、设备 ID 与存储快照保留；独立的身份系统、明确 Ubuntu 名称或其他系统依据仍保留。协议与基础设施线索的 `non_endpoint_or_weak` 状态纳入 API 枚举，不显示为成功识别的普通设备。

### 设备档案与当前共享窗口

共享发现入口默认显示设备档案，另设当前共享、历史观察和账号复核视图。设备档案由独立物化器写入 PostgreSQL 持久化读模型，不因 24 小时证据有效期结束而删除；当前风险和共享判定仍使用原有有效期、完整窗口与强锚点要求。物化器只消费部署切点后的脏任务，不回填旧证据。

设备档案分别返回身份依据时间、地址最近流量和共享最后确认时间。厂商云服务证书只作为厂商关联线索，不赋予路由器角色；由旧共享判断派生的路由画像不能作为独立身份依据。历史视图保留旧规则记录，并明确要求复核，不将旧确认恢复为当前确认。

硬件档案按采集范围与 endpoint、MAC、DHCP 事件时间绑定区分，不能仅凭 IP 将两台设备合并。随机 MAC 只有在 DHCP 同时确认时才成为可靠键；IP 仅用于同采集范围、校区和 VLAN 内的临时档案。租约失效或 IP 重新分配时保留身份档案，并将地址状态转为历史或已转移。认证账号只按精确 endpoint 或 MAC 在后台物化，最近可靠账号在会话结束后仍保留，账号变化写入 365 天历史。

`GET /shared-access/devices` 只执行一次 PostgreSQL 快照查询，不访问 ClickHouse，也不在请求中扫描认证会话或逐设备补充；响应返回物化时间、积压数和新鲜度。`GET /shared-access/devices/{profile_id}` 返回当前档案与变化历史。接口要求 `cases:read`；`GET /shared-access/observations?view=history` 为只读历史视图。上述档案不参与风险评分或处罚授权，也不自动认定设备属于违规私接。


### 历史共享观察的证据筛选（2026-10-06）

历史观察默认只展示当时确认、采集覆盖已验证、无冲突且设备下界至少为 2 的记录；强依据限定为 EasyMesh 多终端关联或明确硬件型号重复共现。旧规则评分、协议栈差异、厂商关联和派生路由画像均不能替代多终端证据。API 的 `view=history` 缺省采用 `history_basis=shared`；`history_basis=clues` 单独查询较弱的旧规则复核线索，不将它们表示为曾经确认共享。

先按证据范围筛选，再选取每个采集范围、地址与终端的最近历史记录，避免较新的弱线索遮盖较早的明确接入证据。原始观察和审计记录保持完整，详情仍可按 ID 追溯；这项筛选不改变当前风险、身份、处罚或证据时间。


### 全局动作白名单（参考旧南昌大学防代理系统）

白名单支持 IP、认证账号、MAC、网段（CIDR 或起止地址）与用户组，支持 IPv4/IPv6、限定校区/接入域、延迟生效、过期、停用和重新启用。账号与组标识分别匹配；MAC 仅取权威当前认证会话，不使用邻居 OUI 或厂商推测。地址范围不得跨地址族或逆序。相同类型、规范化匹配值及校区/接入域范围不允许重复。

白名单命中保留事件、证据、风险和历史记录，禁止通知、断线、降速、封禁等新动作；同账号任一当前会话命中时保护该账号的整体处置。策略决策、审批预览、阶段建单、共享断线预览和最终动作投递均检查白名单。最终投递与原生 4K 的发送前检查重新读取已提交的配置，保护已排队动作；读取失败时不放行。恢复/撤销不被白名单阻断。已发出的动作不会自动撤回，仍需正常人工撤销流程。移出白名单后须重新满足持续时间、冷却与审批要求。

`/policies/whitelist` 提供查询、搜索、状态/类型筛选、新增、编辑、停用/启用和有效期管理。API `/whitelist` 使用 `policies:read`/`policies:manage` 权限及统一会话、CSRF 校验。修改须携带当前 revision，过期版本不能覆盖较新的修改。PostgreSQL 使用既有 `control_plane_settings` 的独立 `policy_whitelist_v1` 配置键；配置变更和包含前后值的审计在同一事务提交，无新数据库迁移。文件模式原子保存配置和变更日志，供单进程部署使用。名单默认空，不自动复制旧系统名单，不将测试账号或现场 IP 写入生产白名单。
