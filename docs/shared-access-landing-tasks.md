# 共享识别落地任务

本文保存可直接交给执行的任务说明。现场版本以 [当前工作](current-work.md) 为准，写这篇时是 `2026.11.24-f9a4a90a`，依据 2026-11-24 20:36:50–20:51:50 的自然流量。

观察期落地是指值班人员能核对镜像证据、排除校方设备，并让允许共享的账号留在豁免里。通知、下线、封禁和解封仍不发送。

先做 T1 到 T5。T6、T7 与之并行，结论出来前不改多终端确认规则。T5 没有看出成批误报后，再做 T8 到 T10。T11 到 T14 用来稳住运行。T1 的省略原因没落地前不做 T14。

T1 里少掉的 14 到 17 个优先出口，不是 300 条名额不够。预留上限是每桶 75 个，优先名单只有 36 个。

| 序号 | 优先级 | 任务 | 负责 | 完成标准 |
| --- | --- | --- | --- | --- |
| T1 | P0 | 解释优先出口为什么没有握手归档 | 采集 | 每个未归档的优先出口都有原因；桶内已有 TCP 活动的优先出口不再因上限丢失 |
| T2 | P0 | 主机名待核与可确认角色分开 | 识别与页面 | 仅主机名的账号能看出原因，策略命中为 0 |
| T3 | P0 | 归属失败按原因分开 | 认证桥 | 健康覆盖内的出口要么有账号，要么原因是绑定或 VLAN；缺口单列 |
| T4 | P0 | 登记校方基础设施并排除 | 学校台账 | 名单内设备不再新确认；4 个已确认账号标明是否在名单内 |
| T5 | P0 | 抽检已确认账号 | 运营抽检 | 16:33 之后的确认账号各有一档人工结论 |
| T6 | P1 | 对照拓扑响应是否进入镜像 | 网络与只读抓包 | 有带计数、丢包和结论的对照记录 |
| T7 | P1 | 消除第四口 LACP 回环 | 网络 | 回环告警停止，并有无丢包的配对计数 |
| T8 | P1 | 同一会话只保留一个未关闭案件 | 案件 | 间隔 200 秒的回放是 1 个案件、2 次命中 |
| T9 | P1 | 配置只记账的上报通道 | 配置 | 一次命中对应一条 recorded，没有出站请求 |
| T10 | P1 | 登录后页面做三视口现场验收 | 前端现场 | 三个视口的现场验收写入当前工作页 |
| T11 | P2 | 把两类证据过期分开计数 | 运行 | 两小时样本能分开两类过期和队列年龄 |
| T12 | P2 | 按登录名子串配置白名单 | 学校与白名单 | 允许账号有豁免记录，原文仍可核对 |
| T13 | P2 | 记录七天磁盘增量 | 只读容量 | 当前工作页有 7 个日点和一句容量结论 |
| T14 | P2 | 只为优先出口重组跨段 ClientHello | 采集 | 优先出口的跨段报文得到指纹；其他出口行为不变 |

## T1 解释优先出口为什么没有握手归档

负责：采集。优先级：P0。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作，分支以 codex/proxy-184 为准。先看 git status，只改本任务相关文件，不覆盖他人改动。

任务：说明认证出口优先名单里每一个没进握手归档的出口是什么原因，并且只修“桶里已经解析出 TCP 活动、却被 300 条上限丢掉”的情况。

现场事实（2026-11-24 20:36:50–20:51:50）：每 30 秒保留 300 条摘要，另省略约 1.3 万条。优先名单 36 个出口，每桶实际只留下 19–22 个的活动。另有一个已确认账号的原出口，该窗握手归档为 0。旁路采样看到同源 MAC 的帧，没计到 TCP 建连，而且采样有内核丢包，不能把这次当成程序漏采。

先读再改：
- internal/devicesignal/capture_bucket.go 的 selectHandshakeOutlets：只有 authenticatedRouters 中且 summary.activity != nil 的键进入预留，上限是 limit/4。36 小于 75，所以这 14–17 个缺口不是预留名额不够。
- internal/devicesignal/handshake.go 的 selectHandshakeKeys、selectHandshakePool。
- cmd/proxy-sentinel/handshake_priority.go：查询失败时 current.Store(nil)，下一桶会丢掉整份优先名单。失败应保留上一份成功结果，并记录失败。

实现：
1. 为每个优先出口记录有界原因：本桶没有报文、解析截断、没有 TCP 活动、查询失败后沿用旧名单、被名额丢掉。原因进入现有覆盖计数，不要为每个报文打一条日志。
2. 回放必须先失败再改：36 个已认证路由器都有 activity 时，输出里要有全部 36 个；没有 activity 的不得占坑；查询失败不清空旧名单；非优先出口仍受 300 上限。
3. 只有回放证明“有 activity 却被丢掉”时，才改选择顺序。桶上限保持 300，优先出口先占，剩余名额继续给全网轮转。

不要做：不提高 180 秒新鲜度，不把缺少归档的出口判成共享，不把 UA、TTL、TLS 指纹当作 TCP 活动，不在 184 造流量，不发送通知或断网。

验证：先写 internal/devicesignal 与 cmd/proxy-sentinel 的回放，再跑 go test ./internal/devicesignal ./cmd/proxy-sentinel、go test ./...、go build ./...、go vet ./...。原因计数还对不上现场样本时，不发布。

完成标准：优先名单里每个未归档出口都有一种原因；桶内已有 TCP 活动的优先出口不再因 300 上限丢失。
```

## T2 主机名待核与可确认角色分开

负责：识别与页面。优先级：P0。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。先看 git status，只改本任务文件。

任务：DHCP 主机名继续不能产生策略命中。共享发现页要把“仅主机名”和“角色证据仍在核验”分成可区分的结果。

现场事实：2026-11-24 20:36–20:51 有 22 个账号待核。修复前同类记录回查原文后只命中主机名。现有文案在 internal/store/shared_outlet.go 的 routerRoleReviewReason：input 为 hostname 时是“型号仅来自 DHCP 主机名，缺少独立路由器角色证据”；input 为空时是“DHCP 型号记录缺少匹配字段，无法确认路由器角色”。RoleEvidenceID 为空时不会写入 RouterProof。

实现：
1. 保持可确认角色只来自 explicit_role：SSDP InternetGatewayDevice、首跳冗余路由器角色、强厂商类，以及 LLDP、CDP、HTTP、软件描述中的强型号。主机名、空匹配字段、UA 不得写入 RoleEvidenceID。
2. 先补失败回放：只有 hostname 的画像得到上述待核原因，NewObservationDecision 不是 matched，不写案件、处置和上报。
3. 查前端共享发现列表是否把所有待核显示成同一句。若是，按 ReviewReason 展示这两句固定中文。缺字段留空，不要用“未识别”“—”占位。相关页在 frontend/src/pages，文案转换不要散落成多套近义句。

不要做：不要加把主机名标成确认的按钮或接口。不要降低确认条件。不要改已应用迁移。

验证：go test 覆盖 internal/store 的出口画像和 internal/sharedaccess。改了前端就在 frontend 跑 pnpm test、pnpm typecheck、pnpm build，并在 390×844、1280×800、1440×900 检查该列表。

完成标准：仅主机名的账号可以在列表上看出原因，对应策略命中为 0。
```

## T3 归属失败按原因分开

负责：认证桥。优先级：P0。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。先看 git status。本任务先只读 184，原因没核对清楚不改解析器。

任务：报表和判定里分开三种未归属：认证覆盖缺口、缺少同窗绑定、镜像 MAC 或 VLAN 与认证出口不符。报文时刻没有认证覆盖时，不得用处理时刻已经恢复的会话补归属。

现场事实：20:36:50–20:51:50，93 个候选出口中 50 个始终未归属，其中 40 个只有覆盖缺口，8 个缺少同窗绑定，2 个 MAC 或 VLAN 不符。该 15 分钟认证覆盖 795.4 秒，15 段缺口共 104.6 秒（按健康区间并集在固定窗口取补集）。19:17 抽样时 NCU 隔离队列 154 条，三条通道 healthy，桥接 degraded。20:52 那次核对没有重计隔离队列。

实现：
1. 只读 184，按当前错误原因分组隔离队列，并看源队列、处理中队列。把条数和原因写入 docs/current-work.md。不要在分组前改解析。
2. 核对 internal/store/shared_outlet.go 的 verifyOutlet、assessOutlet。报表若把三类合成一个“未归属”，改成与 20:52 只读口径一致的三项计数。
3. 回放两条相反时序：报文时有覆盖、处理时有缺口，应归属；报文时无覆盖、处理时已恢复，保持无法归属。身份源中断、变更待处理、快照索引未完成，都走对应 ReviewReason。
4. 隔离项能对应到一条确定的解析缺陷时，用该失败样本写回放再修。源数据问题保持隔离，保留原文、哈希和原因，不计完成。

不要做：不移动身份新起点，不把已取消历史计作完成，不向认证系统写会话，不在 184 造数。

验证：相关 go test 通过后再全量 go test、go build、go vet。再用一段新的自然流量只读复核三项计数。

完成标准：健康覆盖里的出口要么有账号，要么原因是绑定或 VLAN；缺口出口单独计数；新隔离项带原因。
```

## T4 登记校方基础设施并排除

负责：学校台账。优先级：P0。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。先看 git status。没有学校给出的 MAC 名单时，只做只读核对，不登记设备。

任务：已登记为基础设施的 MAC，即使有 SSDP 网关公告和认证会话，也不能产生认证路由器确认。

已有代码：internal/store/shared_outlet.go 的 excludeInfrastructureOutlet。endpoint_entities 中 registration_status=registered 且 ownership_class=infrastructure，或路由器画像带 infrastructure 证据时，清除 RouterProof，冲突记 infrastructure_ownership。回放在 internal/controlplane/shared_observation_integration_test.go。

实现：
1. 只读 184，统计符合上述条件的实体数，并核对现场两个认证 NAS 的 MAC 是否已登记。
2. 只用学校提供的 NAS、楼栋网关、控制器 MAC。通过现有终端登记接口写入，不直接改表。不把 network_device 角色批量改成基础设施。
3. 沿用或补一条回放：登记 MAC 同时具备 IGD 公告、认证会话和 TCP 活动时，没有 RouterProof，结果不是 matched。
4. 只读核对 16:33:06 之后已确认的 4 个账号是否落在名单里。落在名单里的保留案件和原文，把账号标给 T5，不删证据。

不要做：不猜测 MAC，不改已应用迁移，不发送断网或通知。

验证：回放通过后，现场只读确认名单内 MAC 的新确认命中为 0。

完成标准：名单内设备不再新确认；4 个已确认账号各自标明在名单内或不在。
```

## T5 抽检已确认账号

负责：运营抽检。优先级：P0。

```text
这是只读抽检，不改业务代码，不改判定结果。工作区是 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy。

任务：给 2026-11-24 16:33:06 之后每一个确认账号一份人工结论。截至当天 20:51，确认账号共 4 个。

导出字段：账号、出口 IP、MAC、外层 VLAN、内层 VLAN、会话、命中次数、案件编号、角色规则 ID、角色原文事件 ID、握手事件 ID、两份原文 SHA256、公告源 IP 是否与认证出口 IP 不同。公告源 IP 不同本身不是误报，结论要看 MAC 和角色原文。

结论只许三档：共享、校方设备、证据不够。证据不够时写明缺的是角色原文、握手原文还是会话覆盖。结论写入 docs/current-work.md 或现场审计文件。不关闭案件，不改命中状态；若要处置，走页面上已有流程。

对照 T4 的基础设施名单。不要造流量，不要发通知。

完成标准：4 个账号各有一档结论；证据不够的账号写明缺哪一份原文。
```

## T6 对照拓扑响应是否进入镜像

负责：网络与只读抓包。优先级：P1。

```text
这是只读对照，先不改 internal/sharedaccess 的确认规则。工作区是 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy。

任务：判断 IEEE 1905 拓扑响应有没有到达 184 的采集口。

现场事实：多终端确认要求覆盖已核验的成员快照，终端数至少为 2。20:36 后的 15 分钟有 19,458 个 1905 帧，拓扑响应和成员快照是 0。加入和离开各 17 条，涉及 3 个终端、2 个网关，这两个网关没有对上当时在线的认证出口。第四口有 LACP 回环，所以必须同时看 bond0 和四个物理口。

做法：
1. 选一个仍在发送 1905 的网关。在 AP 或控制器记下一次拓扑查询的消息 ID。
2. 同一时段在 bond0、enp8s0f0、enp8s0f1、enp8s0f2、enp8s0f3 上只计 EtherType 0x893a：组播发现、单播查询、单播响应、带成员清单的响应。只留计数、消息 ID 是否出现、VLAN 和接口。不落报文正文。
3. 每个套接字的内核丢包单独记录。有丢包的样本不能用来证明响应不存在。
4. 结论只写两种：该消息 ID 的响应已经出现在 bond0；或在无丢包的物理入口就不存在。后一种写入 docs/current-work.md，并停止为“多终端确认为 0”改确认规则。

不要做：不从 184 发送拓扑查询，不把加入/离开计成成员快照，不改镜像采集进程。

完成标准：一份带时间、接口、计数、丢包和结论的记录。
```

## T7 消除第四口 LACP 回环

负责：网络。优先级：P1。

```text
这是网络侧任务。程序先不改。工作记录写在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy/docs/current-work.md。

任务：消除 enp8s0f3 的 LACP 回环，并复查聚合切换时帧是否只到达物理口。

已有事实：2026-11-23 本机发出的 LACPDU 在 f3 上被原样送回，间隔 11–64 微秒。活动聚合对端是 9c:2b:a6:dc:37:c5，键 15。f3 属于另一聚合组。all_slaves_active=0 时，未活动成员上的帧可能进不了 bond0。

做法：
1. 由网络校正第四口接线、聚合成员，以及镜像是否回送 LACP 控制帧。
2. 校正后在 184 复测：内核日志里的回环告警是否停止。
3. 无内核丢包地同时读活动成员口和 bond0，时长 60 秒。成员口上的帧应能在 bond0 配到。若切换瞬间仍有帧只在物理口，记录接口、帧类型和数量。

不要做：不在主机上关闭 bond，不改业务采集进程来绕过回环，不保存报文正文。

完成标准：回环告警停止，并且有一份无丢包的成员口与 bond0 配对计数。
```

## T8 同一会话只保留一个未关闭案件

负责：案件。优先级：P1。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。先看 git status，只改案件合并相关文件。

任务：同一账号、同一出口 IP、同一认证会话代次，在会话仍然有效时只保留一个未关闭案件。每次命中仍受 180 秒证据新鲜度约束。

现场事实：19:27 后的窗口里，一个账号有 3 个案件，相邻可确认活动间隔 191 秒和 202 秒，超过前一段证据的 180 秒有效期。

先读：
- internal/controlplane/shared_observation_episode.go 的 ensureSharedObservationEpisode。它只延续 expires_at 仍晚于本次判定时间的 recorded 执行，证据过期后会新开 episode。
- internal/controlplane/operations.go 的 activeCaseMatches、caseDedupeKey。带 SessionGeneration 的共享案件只按 dedupeKey 合并。先用回放看清 3 个案件来自 episode 过期，还是 dedupeKey 把同一 IP 拆开。

实现：
1. 先写失败回放：同一账号、IP、会话代次，两段活动间隔 200 秒，每段单独满足新鲜证据。改动前应出现 2 个未关闭案件。
2. 改动后仍是 2 次 matched 决策和 2 份证据快照，未关闭案件只有 1 个。会话结束、换 IP、换账号、案件已关闭，都新开案件，已关闭案件不吸收新命中。
3. 不修改 FreshnessSeconds。处理时已经超过 180 秒的决策仍是 expired，不补成命中。

不要做：不合并不同账号，不删除已有案件和原文，不发通知或断网。

验证：更新 shared_observation_episode_test.go 和案件同步测试，再跑相关包、go test ./...、go build、go vet。

完成标准：200 秒间隔的回放是 1 个未关闭案件、2 次命中。
```

## T9 配置只记账的上报通道

负责：配置。优先级：P1。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。先看 git status。

任务：共享确认命中时写一条 status=recorded 的上报记录。请求不离开本机。

现场事实：2026-11-24 20:52，启用的处置通道和上报通道都是 0，3 条处置没有连接器、没有远端动作 ID。测试里启用通道后会写 behavior_report_outbox，见 internal/controlplane/shared_observation_integration_test.go。

实现：
1. 核对观察期路径：命中写入的动作模式保持 record_only，不调用连接器，不写远端动作 ID。页面继续显示“仅记录、未执行”。
2. 在 184 增加一条本地记账通道。沿用现场配置，不把地址、密钥写入仓库或文档。
3. 有下一次自然命中时只读核对：outbox 新增 recorded，连接器和远端动作 ID 为空。没有自然命中时，用现有集成测试证明写入路径，并在 docs/current-work.md 写明现场还待下一次命中。不要为了验收制造共享流量。

不要做：不把通道指到学校通报地址，不打开真实 HTTP 上报，不发送通知、下线、封禁。

验证：相关 controlplane 测试、go test、go build、go vet。若改了页面文案，补前端测试和三个视口。

完成标准：通道存在且一次命中对应一条 recorded；没有出站请求。
```

## T10 登录后页面做三视口现场验收

负责：前端现场。优先级：P1。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。先验收，确认有缺陷再改代码。

任务：在 184 登录后的页面完成 390×844、1280×800、1440×900 验收。本地回放不能代替这次现场验收。

页面：共享发现、策略与处置记录、白名单、案件历史。路由在 frontend/src/app/routePages.tsx。

做法：
1. 从共享发现打开一条确认或待核，进入案件，看到仅记录处置，再打开白名单。
2. 每个视口检查文字折行、按钮挤成竖排、长标识撑宽、选中态对比度、控制台错误和失败请求。
3. 缺失字段留空。不要出现“未识别”“未获取”“未关联”“未知”或用“—”占位。处置文案保持“仅记录、未执行”。
4. 只有发现具体缺陷才改 frontend。改动后在 frontend 跑 pnpm test、pnpm typecheck、pnpm build。不要用单独的 tsc --noEmit 代替 typecheck。

不要做：不改接口语义来掩盖空字段，不把模拟记录写成已送达。

完成标准：三个视口的结果写入 docs/current-work.md，并标明这是 184 登录态现场验收。
```

## T11 把两类证据过期分开计数

负责：运行。优先级：P2。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。先看 git status。

任务：共享判定的 expired 要能分成两类：证据活动时间到处理时已经超过 180 秒；入队时还没超过、排队后才超过。后一类不得改写成 matched。

现场事实：共享判定并发为 5 时，10 分钟内 239 次在入队时证据仍有效、处理时已超过 180 秒。并发调到 7 后，P50/P95 约 16.4/45.4 秒，10 分钟过期 11 次。20:53 共享队列 992 项，最老 54 秒，带错误 0 项。

实现：
1. 在现有判定日志中保留证据最后活动时间、入队时间、开始处理时间和结果。缺哪个补哪个，不另建队列。
2. 回放覆盖两类：活动时间距处理超过 180 秒，结果是 expired；入队时未超过、处理时超过，结果仍是 expired，并带排队过期原因。
3. 磁盘出现 WAL 等待时，先记录等待，再决定是否调整现场并发。调整要留下原参数。不要增大 FreshnessSeconds。

不要做：不用放宽新鲜度消化积压，不在 184 造数压测。

验证：相关回放、go test、go build、go vet。发布后用两小时自然流量只读样本核对。

完成标准：样本能报出两类过期的次数，以及队列最老年龄。
```

## T12 按登录名子串配置白名单

负责：学校与白名单。优先级：P2。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。学校没有给出登录名原文子串时，不做配置。

任务：允许共享的账号按登录名子串豁免处置。观察和原文保留。

已有能力：白名单类型 username_contains，页面是 frontend/src/pages/WhitelistPage.tsx，匹配在 internal/policy/whitelist.go。匹配区分大小写。豁免抑制动作，不删除证据。

实现：
1. 每个子串填写原因、校区和有效期。不把口令或无关账号写进仓库。
2. 用一个已知允许账号做回放：共享观察仍在，决策结果是 whitelist_suppressed，不新建案件，不写待发送动作。
3. 有自然流量后只读核对这一账号产生豁免记录且案件数不增加。

不要做：不用删除观察来表示豁免，不放宽其他账号的确认条件。

验证：internal/policy 白名单测试和一条共享决策回放。改了页面再跑前端测试、typecheck、build 和三个视口。

完成标准：该账号的后续命中有豁免记录，证据仍可按原文哈希核对。
```

## T13 记录七天磁盘增量

负责：只读容量。优先级：P2。

```text
这是只读容量记录，不清理数据，不改保留期。记录写入 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy/docs/current-work.md。

任务：连续 7 天记录 184 根盘可用空间、PostgreSQL 数据目录、ClickHouse 中握手与报文原文、query_log 的占用量，并算出日增量。

对照规则：必要证据热查 30 天，归档到首次入库后一年。11 月 22 日清库后，20:52 根盘约剩 656 GiB。这块盘此前到过使用率 93%。没有这 7 天斜率之前，不写“一年放得下”。

做法：每天同一口径只读采样一次。7 天后写明 30 天热数据放得下，或差多少。不删除唯一原文、案件证据和未核验归档，不缩短保留期，不在 184 造数。

完成标准：docs/current-work.md 有 7 个日点和一句容量结论。
```

## T14 只为优先出口重组跨段 ClientHello

负责：采集。优先级：P2。

```text
你在 /Users/yuantong/Developer/Projects/work/proxy-sentinel/anti-proxy 工作。T1 的省略原因还没落地时，不做本任务。

任务：优先出口上跨 TCP 段的 ClientHello 在有界缓冲内重组。重组只改善指纹，不产生共享确认。

现场事实：解析以单帧为界，TLS 记录长度超过当前 TCP 段时记为截断。非优先出口仍保持单帧解析。

实现：
1. 在 internal/devicesignal 先写回放：一条首段放不下的 ClientHello，旧结果是截断；新结果在缓冲上限内得到指纹。超过上限仍记截断，不保留无界报文。
2. 只对 T1 的认证路由器优先出口启用。全网其他出口的解析、内存和 300 条输出上限保持原样。
3. 重组失败或截断不得写入 RouterProof，也不得让 NewObservationDecision 变成 matched。

不要做：不把指纹差异升为确认，不保存超出上限的报文，不在 184 造流量。

验证：devicesignal 回放、现有 Linux 握手过滤测试、go test ./...、go build、go vet。

完成标准：回放中的跨段 ClientHello 得到指纹；非优先出口的截断行为与改动前一致。
```
