# 当前工作与下一步（2026-10-31）

## 目标

在只有镜像流量、没有 SNMP/NDM 凭据的前提下，尽可能提升发现设备的识别覆盖率，并把识别结果以“终端台账”的方式展示出来。

要求：

- 不发起主动扫描；
- 不伪造操作系统、接入端口或服务端口；
- 每个结论必须能追溯到镜像证据；
- 低置信度结果明确标注为“线索”。

## 2026-11-01 现场进展（184 测试联调环境）

下方“本地进展、待部署”段落保留当时的实施记录；本节追加记录 2026-11-01 的现场检查，不代表长期容量验收。

- 应用 `2026.11.01-mirror-discovery-r9` 已部署到 `/opt/proxy-sentinel/current`，`previous` 保留 r8；源码提交 `36f4ce44`，发布包 SHA256 `183d0f404972d9c690213875e6f5da88496a6ea6140546df537807655fdaf577`。PostgreSQL 候选迁移 214 项、ClickHouse 59 项与现场账本校验一致；本次 r9 为应用更新，未重新执行迁移。此次工作已执行 PostgreSQL 212/213 与 ClickHouse 059 迁移，按测试环境约定跳过备份。
- DHCP 旧 `device_dhcp_binding.log` reader 已审计退役；逐消息源 `dhcp-message-fresh-20261101T180643Z` 使用 `zeek-dhcp-message-v1` 持续读取 `device_dhcp_message.log`。旧源未完成输入按固定截止点和逐批清单标记为取消、未处理，原始文件及既有有效租约事实保留。REQUEST 只产生客户端识别线索，ACK 才产生地址绑定。
- 发现列表现按已生成的 current 投影读取，详情证据单独读取。路由镜像中同一网关 MAC 会伴随多个 IP；服务公告和 TTL 线索现须匹配来源 IP，OUI 补全只用于直接 DHCP 客户端 MAC，避免把网关的厂商、服务或 OS 线索传播给多台终端。页面标明 DHCP“逐消息源已登记”，旧协议计数标为“旧链路累计”。
- 一段已归档但未确认的发现 journal 曾使 ARP/DNS-SD/SSDP 停滞；已用原始 token 核验的 `stream-repair` 只重放该段的 archive lane，未删除原文。恢复后协议最近成功时间继续前进，隔离未处理数为 0。历史重置后的 TTL/握手文件源与共享任务代次不一致，已以旧/新代次哈希审计关闭两条旧共享源并激活新源 `shared-history-reset-recovered-20261101`；旧共享待办取消数均为 0，两条 reader 恢复逐批确认。
- 03:02 的只读健康核对：Redpanda 健康、两个消费组 lag 均为 0、控制面 `/readyz` 为 200、发现隔离未处理数为 0，current 台账 26,845 行，`missing_stream=0`。03:04 的台账快照有 26,856 行、25,467 行带 IP 与 MAC、14,250 个不同 MAC、14,310 行带名称；这些是带代次和作用域的**台账行**，不能视为唯一物理设备数。数字随事实自然过期和持续输入变化。
- 390×844、1280×800、1440×900 的现场截图与 DOM 探针通过：页面宽度均等于文档滚动宽度，表格容器宽度分别为 336、982、1142 px，文字按钮未折成竖排，控制台 0 条消息；现场 DHCP 覆盖卡显示逐消息源。应用相关 Go 测试、构建、vet，前端测试、类型检查及生产构建通过。
- `2026.11.01-mirror-discovery-r11` 已按应用更新流程发布，`current` 为 r11、`previous` 为 r10；源码提交 `df641e31`，发布包 SHA256 `85ee1afcea424ae07b92043fe26c0ef1d1b74b0584dd6e80b1e144da2f45babf`。PostgreSQL 214 项、ClickHouse 59 项候选迁移均与现场账本匹配，未执行新迁移。现场登记 `/opt/proxy-sentinel/config/discovery-handshake-scope-map.json`，SHA256 `d22d685556878957f17ef6b46e6921a7ce3b721db6f065744822165bd2c808d5`；它仅把同一 `ncu-184-router-pilot` 传感器的发现域 `bond0-passive-pilot` 与握手域 `bond0-router-minimal-overnight` 在 `10.202.0.0/16` 内显式对应，已与两份采集范围配置逐字段核验。控制面 systemd drop-in `zzzzzz-mirror-handshake-r11.conf` 指向该映射文件；回退应用时可移除该 drop-in 与映射，再重载并重启控制面。
- 握手侧车已有的 HTTP User-Agent、JA3 原文现可在发现设备详情按当前 IP 受限读取：只查询活动代次、同传感器映射范围、最近 11 分钟的索引和已核验归档原文，最多展示 12 条，保留标准事件号与观测时间，明确标成 IP 弱线索。列表仍只读 current 投影。现场详情接口实际请求返回 200，浏览器记录的该次请求约 98 毫秒；但所选 IP 暂无可展示样本，尚不能宣称 UA/JA3 现场非空覆盖。r11 的 390×844、1280×800、1440×900 现场截图与 DOM 探针再次通过：文档宽度分别等于 390、1280、1440，表格容器宽 336、982、1142 px，文字按钮未竖排，控制台 0 条消息。
- `2026.11.01-mirror-discovery-r12` 已按应用更新流程发布，`current` 为 r12、`previous` 为 r11；源码提交 `b81843667204a18da10404a05ea07fff435ea8da`，发布包 SHA256 `015cd99caf0080a91c523e8282262f88bcc8f95ecb21622978efef933ff63a27`。PostgreSQL 214 项、ClickHouse 59 项候选迁移与现场账本匹配，未执行新迁移。覆盖面板现将 HTTP/TLS 标为“握手侧车已登记 · 详情弱线索”，其零计数明确标成“发现链路累计”，不与独立侧车的数据量混淆；DHCP 仍标明逐消息源。控制面 `/readyz` 为 200，逐消息 DHCP、握手、packet 三个文件 reader 均活动。相关 Go 测试、build、vet，前端 167 项测试、typecheck、build 通过。r12 现场 390×844、1280×800、1440×900 截图和 DOM 探针完成：文档宽度分别为 390、1280、1440 px，表格宽 336/982/1142 px，均小于父容器，文字按钮没有折成竖排；列表初次检查时控制台 0 条消息。移动端详情弹窗可展示弱线索且未见横向爆框。随后一次详情重渲染时浏览器记录到瞬时 HTTP 502，重新打开详情后网络面板记录的 2 次请求均无失败；该次错误仍需观察，不能写成零网络错误。
- 04:00 后现场选择 current 台账行 `10.202.185.195` 核对，详情实际显示 12 条近期握手弱线索（9 条 TLS JA3、3 条 HTTP User-Agent），每条均有 `stream-` 标准事件号和观测时间；同一 IP 可能共享或复用，页面已标明归属边界。本轮只读健康脚本：Redpanda 健康、两个消费组 lag 均为 0，控制面 readyz 200，current 台账 28,430 行、`missing_stream=0`，另有 10 行 `fact_count=0` 的孤立 current 行；这些计数不是唯一物理设备数，也不能替代长期容量验收。
- `2026.11.01-mirror-discovery-r13` 已发布，`current` 为 r13、`previous` 保留 r12；源码提交 `2c6b7a79a0f2169549980a6048f3ce2d12326fcb`，发布包 SHA256 `1059f6c154f297923ae1220eaeefcdaae3d2c5948af3273b8937d6466beec1e1`，清单标记工作区无未提交改动。PostgreSQL 214 项、ClickHouse 59 项候选迁移均已应用且校验值一致，本次未执行迁移。第一次常规应用更新发现现场 `proxy-sentinel-inventory.service` 固定运行旧版而自动回退到 r12；检查 r12 控制面 `/readyz` 200 后，保留失败发布目录，再以脚本支持的 `--preserve-inventory` 成功切换。该固定版本服务仍按现场原配置运行，不能计作已更新到 r13。
- r13 在同一受限 TLS ClientHello 侧车中按 [FoxIO JA4 规范](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)计算 JA4；只有完整握手才留样本，不改变镜像 BPF，也不将 JA3 和 JA4 从同一握手重复计作两个客户端栈。JA4 详情按当前 IP、原始事件号和观测时间展示弱线索，不能推出 OS 版本或确定设备归属。针对性 Go 回放、相关 Go test/build/vet、前端 167 项测试、typecheck/build 均通过；390×844、1280×800、1440×900 的 mock 截图和 DOM 探针通过，移动端 JA4 长值 `overflow-wrap:anywhere`、弹窗右缘不越界，页面无 console/page/network 错误。r13 现场浏览器会话接入超时、新标签返回 HTTP 响应错误，**尚未完成 r13 现场三视口页面验收**；此前 r12 的现场截图不能代替 r13 验收。
- r13 的 04:48 只读核对：`handshake.jsonl` 当前文件 cursor 与当次大小同为 206,474,121 字节；最近 8 MiB 原文有 116 个 `10.202.0.0/16` 不同 IP 带 JA4 样本，这只是被动捕获地址样本范围，不能当作唯一终端数或已展示覆盖率。检索索引最近 10 分钟有 772 条该网段握手事件、274 个不同 IP；`10.202.185.195` 的新事件索引行和相同键/哈希的归档正文已核对，正文含 JA4 样本。控制面 readyz 200、握手采集和文件 reader 活动，身份同步 readyz 仍为 503。04:48 current 台账 26,887 行，瞬时 `missing_stream=9`、无事实孤立行 4；04:50 对活动代次逐行复查两项均为 0，仍不能由此宣称长期无缺口。共享观测待办 2,628，最旧约 111 分钟，发现事件消费组当次 lag 183；其唤醒模式仍为 `legacy`，并发升级须按独立影子/异步切换文档验收。近期两小时的实际访问端口 ClickHouse 聚合表仍为 0 行；现有镜像采集未提供非 DHCP flow 标准事件。
- `2026.11.01-mirror-discovery-r14` 已按应用更新流程及现场固定版本服务约束，使用 `--preserve-inventory` 发布；`current` 为 r14、`previous` 保留 r13。源码提交 `3785f7926c76afe5fbaa51b390b6010fd4ffe7d7`，发布包 SHA256 `81807d73e62aefac348e75a456b4ee573221da644ffc7bbfbd1be33bb6e2ebc3`。PostgreSQL 214 项、ClickHouse 59 项候选迁移与现场账本一致，未执行新迁移。握手侧车仍每 30 秒最多输出 200 个 IP/MAC 摘要，其中一半优先保留高活跃客户端，其余按时间轮换低活跃客户端，防止相同的高频客户端长期占满名额；没有扩大 BPF 或提高每桶写入上限。针对性轮换测试及相关 Go 测试、build、vet 均通过；本次未改前端，r13 的三视口 mock 检查适用于同一前端资产。r14 现场浏览器会话仍超时，现场三视口与 JA4 详情呈现验收尚未完成。
- r14 切换前后各取完整的五分钟、10 个 30 秒桶，同为每桶最多 200 条：原始握手摘要各 2,000 条，`10.202.0.0/16` 不同 IP 从 175 个增加到 403 个；ClickHouse 检索索引相同窗口分别有 382/584 条该网段握手事件、175/403 个不同 IP，后窗最后索引时间为 21:01:25 UTC。原文覆盖记录两窗内核丢包分别为 2,804/2,110、因输出上限省略的 IP/MAC 键为 16,783/17,254，键容量丢弃均为 0；21:01 采集进程约 149 MiB RSS，握手采集与 reader 均活动，控制面 readyz 200、两个消费组 lag 0。该短窗口证明被动捕获到的不同地址样本增加，但流量组成会变化，不能当作唯一物理设备数、稳定识别率或容量达标。21:02 current 台账 26,773 行，瞬时 `missing_stream=3`、孤立无事实行为 0；共享观测实时待办 2,983、最旧约 125 分钟，仍处于 `legacy` 唤醒模式，身份同步 readyz 503，均须继续处理或验收。
- `2026.11.01-mirror-discovery-r15` 已发布到 `current`，`previous` 保留 r14；源码提交 `24bc4515327449490de7a25aab9f21cfce88dd47`，发布包 SHA256 `b2b82d034ed87da1dcd7877cbc15d174e2b3b113cef319eab414fa4809386061`，工作区清单为无未提交改动。PostgreSQL 214 项、ClickHouse 59 项候选迁移均与账本一致，本次未执行迁移；应用更新使用 `--preserve-inventory`。现场登记 `proxy-sentinel-handshake-signal.service.d/zzzzzz-mirror-priority-r15.conf`，SHA256 `3baa307462c484f9146910b39e8724ef22760543e7d37f2901db1a909c7c2749`，只把现有发现范围中明示的 `10.202.0.0/16` 设为握手输出优先网段；每桶最多 200 条不变，其他网段有至少 50 个候选时仍保留 50 个名额，优先网段至多使用其余 150 个，空位可由另一组补满。不修改证据归属、BPF 或原文保留。原单元配置已保存到 `/opt/proxy-sentinel/config/handshake-signal-unit-before-r15-20261101.txt`，SHA256 `2db1b19a5cdb16b70d08664178b92f953f9d31b043cf38358fe609564b6f3a9f`；回退此选择策略时移除新增 drop-in、重载并重启握手服务，应用回退入口为 r14。启动后进程环境已核对为 `10.202.0.0/16`，握手采集和 reader 均活动，控制面 readyz 200。相关 Go 测试、build、vet 及发布包前端 typecheck/build 通过；本次未改前端，现场浏览器三视口验收仍未完成。
- r15 的前后完整五分钟窗口分别为 21:05–21:10 和 21:12–21:17 UTC，各有 10 个桶、2,000 条原始握手摘要；`10.202.0.0/16` 摘要从 420 条增至 1,500 条，不同 IP 从 293 个增至 625 个。ClickHouse 检索索引同口径的事件数与不同 IP 数均与原文一致，后窗最后索引时间为 21:17:05 UTC。覆盖记录的内核丢包分别为 3,288/1,710、输出省略的 IP/MAC 键为 16,826/16,621，键容量丢弃均为 0；采集进程 21:17 约 154 MiB RSS，控制面 readyz 200，两个消费组 lag 0。此结果只说明同一输出上限下目标网段的**被动地址样本**在短窗口内增多；实际流量组成会变化，不能把不同 IP 当成物理设备识别率，也不能据此宣称持续吞吐或故障恢复达标。21:17 current 台账 23,554 行，瞬时 `missing_stream=1`、无事实孤立行 3；身份同步 readyz 503，均未作长期稳定性结论。
- `2026.11.01-mirror-discovery-r16` 已按应用更新流程发布，`current` 为 r16、`previous` 为 r15；源码提交 `11b7713eb10aa66fa99373b9b41ca23e54d73300`，发布包 SHA256 `3493ad9d38a5c67ad592b3b01873424e4b766b8c2ce892aef6bbe1c70e306ef2`，清单标记工作区无未提交改动。PostgreSQL 214 项、ClickHouse 59 项候选迁移与现场账本校验一致，本次无新迁移，使用 `--preserve-inventory`。同一现有 80/443 端口握手侧车现在把每条完整 HTTP User-Agent、TLS JA3/JA4 样本的实际 TCP 目标端口写入权威原文；发现详情只对有端口字段的新样本展示“握手目标 TCP/80 或 TCP/443”，旧证据保持空白，仍按当前 IP、事件号和时间标为弱线索。它只能说明观测到该握手包的目标端口，不代表设备自身端口开放，也不代替全量 observed flow。没有扩大 BPF 或每桶事件上限。
- r16 新桶的 `10.202.0.0/16` 原文实际有 150 条摘要、150 个不同 IP，其中样本的 `dst_port` 为 JA3/TLS 443 共 705 条、JA4/TLS 443 共 700 条、HTTP User-Agent 80 共 197 条；这些是同桶多条握手样本，不能视为设备数。`10.202.0.55` 的新检索索引行与归档正文按同一事件键、作用域、归档月份和内容 SHA256 点查匹配，正文同时含 `dst_port:443` 和 `dst_port:80`，原文哈希与段引用各唯一。相关 Go 测试、build、vet、前端 167 项测试、typecheck/build 均通过；390×844、1280×800、1440×900 的 mock 截图与 DOM 探针通过，弹窗宽度和文档滚动宽度均未越界，未见 page/console/network 错误。21:26 控制面 readyz 200、握手采集和 reader 活动；身份同步 readyz 503。现场浏览器工具报告 Mac 锁定且自动解锁失败，r16 现场三视口和详情实际呈现仍待验收。
- 21:30 发现服务被原样保留的段 `02a6782961f1a1426f8cdae89401f7da2c007c98936570fe8f14664100699750` 的 search lane 卡住；该段 335 个事件的检索索引均缺失，导致 ARP 当前事实自然过期，活动发现状态曾从约 3,233 行降至 77 行。停服务后核对段内容、索引缺失、异步队列和原 token 的查询日志，使用 `stream-repair --lane search` 以原段原 token 受限重试，未删除原文或伪造确认；重启后服务连续提交积压段，原阻塞段文件从待办目录正常退出。21:32 的只读复核：该发现代次活动状态 2,858 行、过期 0 行，ARP/DNS-SD/SSDP 活跃事实分别为 2,047/225/86，最新观测已到 21:32 UTC，目录当时余 2 个待处理段，控制面 `/readyz` 200。恢复后的短时增长不能视为持续可靠性或容量验收；需继续监测索引确认与活动状态是否再次停滞。
- 健康脚本 `scripts/eventbus-184-health.sh` 增加发现、握手采集和握手 reader 服务状态，以及活动被动发现代次的 `last_seen` 和相对当前时间的延迟；超过 120 秒或缺少观测时只在脚本输出 `ALERT`，不发送通知或自动跳过段。提交 `c13eb615fca33b8f805824b54b8c5e1104012b16`；184 脚本 SHA256 `87de5340dce411be576a0040286b5658bd0bdc5446a82ff5c9ea56ae09c9743c`，旧脚本保留在 `/opt/proxy-sentinel/config/eventbus-184-health-before-r17-20261101.sh`。本地与现场 `bash -n` 通过，现场执行显示该发现代次延迟约 4 秒；这是人工只读巡检入口，不是自动修复或持续监控验收。
- 21:43 的设备台账只读基线为 24,428 条 current 行，其中 22,913 行带 MAC、11,640 行带名称、14 行为已识别类型；原始 current 文档仅 10 行带制造商，列表读取时另对直接 DHCP 客户端 MAC 做 OUI 补全，不能用原始列数推断页面已展示的厂商覆盖。18,214 条带 DHCP 协议的 current MAC 行中，13,909 条为本地管理地址、4,305 条为全局地址；现场离线 OUI 库有 54,289 项，全局地址中 4,278 条能匹配登记前缀。这些是带代次和作用域的行，不是唯一物理终端；本地管理地址不做 OUI 厂商推断。只读短时抓包在 5 秒内看到 TCP/445 约 133 包、全网 TCP SYN 约 9,229 包，均无该次抓包的内核丢包；另一段 10 秒、81 包的 445 样本未见完整 SMB1/SMB2 报文头，样本不足以证明现场没有 SMB native OS 证据，也不足以授权扩大采集范围。
- r17/r18 修复关闭 DHCP 文件源后的持久识别线索读取：仍有效的旧租约事实原先因为只查 `active` 源而无法进入线索接口；查询现只对仍在当前设备状态的 `closed` DHCP 事实回退，新源有同传感器、MAC、VLAN 的有效**识别字段**时优先使用新源，单纯 ACK 地址绑定不会抹去旧线索。仍按每个来源代次和 MAC 最多四条、保留原事件号与观测时间，REQUEST 不产生地址绑定。184 只读抽样中，旧源 current 的 100 个 MAC 有 99 个返回旧源事实共 178 条；新源 current 的 100 个 MAC 有 9 个返回新源识别事实、73 个还能取得有效旧线索。PostgreSQL 对此查询默认 JIT 编译约耗 1.28 秒，故仅在该只读事务内关闭 JIT；同样 100 个 MAC 的现场 `EXPLAIN ANALYZE` 执行约 60–95 毫秒，未包含网络和页面耗时，不能代替接口 P95 验收。相关 Go 测试、build、vet 通过。
- r19 发布时 `previous` 保留 r18；源码提交 `377e0c63fba15618ed1bc9e14713fa85fa1b4ead`，发布包 SHA256 `7b84411555759186da14c0cd8d00d4d4a4c995618d9277fc99962f715bc56c2c`，清单无未提交改动。r17/r18 候选包分别为提交 `81045b692ecd5b78b8613cee7ea9a40076c15188`、`ce559cc29637d6f2d10f8b231123877c1df69372`，SHA256 `71d8035daeee2b65bdbf7b3f89bd6f0802308c87e076793d3a02f99dce4bbf92`、`78d792c115fd1aed0b0ba2f28d9af76d165c2977fa01d0b4040abec9ab6b8ff9`。三次均用 `--preserve-inventory` 应用更新，PostgreSQL 214 项、ClickHouse 59 项迁移已应用且校验值一致，无新迁移。发布脚本原先漏掉实际运行的 `control-plane-eventbus` 和逐消息 DHCP reader，导致前者需手动切换、后者曾仍运行 r12；r19 已把两单元纳入今后升级的 CLI 与进程目录校验。本次用旧脚本发布后已单独重启并确认两者实际执行 r19，控制面 `/readyz` 200、两个消费组 lag 0、隔离未处理数 0；22:05 UTC 发现代次最新状态延迟约 4 秒。固定版本 inventory 服务仍按现场原配置运行。现场浏览器仍因 Mac 锁定无法完成 r19 页面与接口的登录态验收。

- `2026.11.01-mirror-discovery-r20` 发布时 `previous` 保留 r19；源码提交 `ce2788e630b2aba6fb7a28b366d25e57cb6df00a`，发布包 SHA256 `5b1458e2eb408925c9df81133a779306ba7528e109952516884c8d63e9138006`，清单无未提交改动。PostgreSQL 214 项、ClickHouse 59 项候选迁移与现场账本校验一致，本次没有新迁移；按现场固定版本 inventory 服务约束使用 `--preserve-inventory`。升级脚本核对并重启控制面、逐消息 DHCP、握手、packet、发现等活动单元，实际进程均指向 r20；旧发布目录和回退链接保留。
- 逐消息 DHCP 的 REQUEST 识别字段约五分钟后自然失效，而同 MAC 的 ACK 租约仍可持续有效。r20 只在**活动逐消息源**、同一传感器/MAC/VLAN 有有效 ACK 事实及当前设备状态时，受限读取最近 24 小时内已经过期的 REQUEST 识别字段；REQUEST 仍不产生地址绑定，历史 OS 线索降为弱置信度。台账操作系统列和详情明确显示“历史线索”、观测时间及证据事件号，不能将其当成当前确定 OS。查询显式匹配既有 DHCP MAC 索引的非空 MAC 条件，未增加索引或存储副本。184 对新源和旧源各 100 个当前租约 MAC 的只读 `EXPLAIN ANALYZE` 分别约 96/116 毫秒；新源样本查询返回 177 条、覆盖 98 个 MAC，其中 93 条为历史线索、涉及 91 个 MAC。这只是该两组样本的数据库执行时间和返回范围，未验证登录态接口 P95 或全网识别率。
- 本次相关 Go 单元测试、build、vet，前端 167 项测试、API 契约/typecheck 和生产构建通过。新增 Playwright mock 回归在 390×844、1280×800、1440×900 三视口捕获列表与详情截图并探查 DOM：无文档横向溢出、历史标签裁切或按钮竖排，390px 列表为卡片，浏览器 page/network 错误为 0。现场 22:20 UTC 只读核对：控制面 `/readyz` 200、现场本机前端页面 200、Redpanda 健康、两个消费组 lag 0、发现隔离未处理数 0、活动代次最后观测延迟约 4 秒；current 台账约 25,018 行，一次复核 `missing_stream=0`、无事实孤立行为 0，不能据此宣称持续容量与故障恢复达标。现场 8088 是转发到 18080 的入口，防火墙仅允许回环与 `10.124.0.0/16` VPN；本机命令行当前不在 VPN 内且 Mac 已锁定，故 r20 登录态页面、三视口和真实接口响应仍未验收。

- `2026.11.01-mirror-discovery-r21` 已作为当前应用按同一应用更新流程发布，`previous` 保留 r20；源码提交 `ae3295f9b6b8d4289dc4c2b4e807121513a0806f`，发布包 SHA256 `f47cda7448bd0cb625086d884a2d9db436e3bb7e555028147c01a6845b34b01d`，包内清单无未提交改动。r21 补齐同一 MAC 的历史 REQUEST 与有效旧来源 OS 线索合并时的置信度：只要合并结果含历史 DHCP 线索，`os_confidence` 保持 `weak`；新增单元回归通过。PostgreSQL 214 项、ClickHouse 59 项候选迁移仍与账本匹配，本次无新迁移；活动应用服务均由发布脚本核对为 r21 目录，固定版本 inventory 仍按现场配置保留。22:23 UTC 只读复核控制面 readyz 200、现场本机前端 200、Redpanda 健康、两个消费组 lag 0、隔离未处理数 0、活动发现代次最新状态延迟约 3 秒；current 约 24,792 行，瞬时 `missing_stream=15`、无事实孤立行 0。这个短时缺口仍须持续观察，不据此宣称长期一致性。对活动逐消息 DHCP 源另取五组不同的 100 MAC 页，用与 Go 相同的参数化 SQL 在现场只读执行，`EXPLAIN ANALYZE` 分别约 61.2、58.7、65.2、59.7、62.3 毫秒；未包含 HTTP、连接池、页面加载或长期并发，不能代替接口 P95/P99 验收。22:25–22:26 UTC 的后续只读巡检中，发现消费组瞬时 lag 分别为 185、221，投影服务同时持续写入约每秒数百条；`missing_stream` 从 12 变为 0，活动状态延迟约 2–3 秒。尚无持续负载与长期积压收敛结论。Mac 仍锁定，r21 登录态真实页面和接口的三视口验收尚未完成；r20 mock 回归不能代替现场验收。

- 22:29 UTC 只读核对三个文件 reader 的权威 cursor 与当前文件身份、大小：逐消息 DHCP 同文件尚差 1,253 字节，握手和 packet/TTL 同文件差 0 字节，三者未提交 journal 段均为 0；这是该时点的进度，不证明后续轮转或重启恢复。控制面日志同时显示共享观测实时待办 2,909、最旧约 12,721 秒，延迟窗口样本仍不完整；此积压尚未收敛。ClickHouse `discovery_observed_flow_ports_10m` 当前为 0 行，不能在台账声称非 DHCP 实际访问端口覆盖。对镜像口仅作 20 秒、最多 1,000 包的被动 TCP/445 样本检查：实际捕获 172 包，166 包为 SYN、未见含 TCP 载荷的包，抓包内核丢包 0；该短样本不能证明全时段不存在 SMB native OS，也不足以扩大采集过滤器或生成 OS 结论。

**仍需如实保留的缺口：** 握手与 packet/TTL 文件 reader 仅有短时追平核对，尚无持续吞吐、故障恢复或后续日志轮转的容量验收。共享观测投影仍有待办和较长的最旧处理延迟。当前 Zeek 采集过滤器仅含 DHCP 67/68，Suricata EVE 当前仅有 DNS 与统计事件；现场未见 SMB native OS 或非 DHCP observed flow，页面不推断精确 OS 版本、开放端口或物理接入端口。NCU 身份同步本机 `/18082/readyz` 仍为 503，属于本次发现链路之外的现场遗留问题；其现行 binary 没有文档提及的 `--read-only=true` 参数，需另行核对该项现场约定，不将本次发现验收写成整站全部服务通过。

04:23 连续只读核对：握手和 packet/TTL reader 都已读完各自保留的轮转原文并切入当前文件，两个当前文件的 cursor 与当次文件大小相等；三个文件 reader 仍活动，控制面 readyz 200、Redpanda 健康、两个消费组 lag 0。这是当次处理进度，仍须持续观察积压与日志轮转。共享观测投影另有约 2,699 个实时待办，最旧约 85 分钟，延迟窗口样本尚不完整；本轮健康脚本曾瞬时显示 `missing_stream=1`，随后查询恢复为 0，孤立无事实 current 行也由 10 降至 0，不据短时样本宣称长期一致性。

03:15 复核：TTL cursor 已到约 26%；握手源在 03:14 按日志轮转规则重命名为 `handshake.jsonl-20261101-031402`，旧 inode 和 1.6 GiB 原文仍保留，reader 按文件身份继续读取，尚未读完；轮转后的新文件不能作为旧 cursor 的进度分母。恢复后两条 reader 的最终确认错误数仍为 0。现场 Suricata 的 BPF 仅纳入 ARP、发现类多播和指定 UDP/VRRP，Zeek 的 BPF 仅纳入 DHCP；对 `bond0` 上 TCP 80/443/445 的短时只读抓包可见大量报文，未做资源与丢包验收前不能直接放开全量 TCP 捕获。

## 2026-11-01 后续事项

- 持续核对握手与 packet/TTL 当前文件在后续流量、轮转和重启后的积压，以及共享观测投影待办的最旧时间；保留原文和未完成缺口，不用移动起点或跳过输入制造追平结果。
- 排查 10 行无事实 current 台账与详情重渲染时的一次 HTTP 502；复现后按具体查询或网关日志定位，不能把一次重试成功当作长期可用性验收。
- SMB native OS 和非 DHCP 全量实际访问端口需先确认受限镜像源能提供标准事件，再做回放、丢包与资源验证；r16 的握手目标端口仅覆盖现有 TCP/80、TCP/443 的完整握手样本，不能把 JA3/JA4 或服务公告改写成设备端口开放，也不覆盖其他 TLS 端口、QUIC 或无完整握手的会话。
- 完成 r21 现场登录态三视口截图、DOM/网络/控制台检查，以及历史 DHCP 线索、JA4 和握手目标端口实际呈现核对；继续监测瞬时 502 与 current 短时缺口，复现稳定错误时按日志和查询定位。检查现有 observed-flow 聚合表的非空覆盖、写入增长和查询延迟后，才可给服务/端口覆盖率结论。

## 当前已落地

### 数据链路

- 新发现代次：`discovery-fresh-20261031T092000Z`；
- 采集范围文件：`/opt/proxy-sentinel/config/discovery-capture-scope-layered-r7.json`，有效期已延长到 `2026-12-31T00:00:00Z`；
- 被动协议：ARP、DHCP、DNS-SD、SSDP、LLDP；
- LLDP 现场 0 包；SNMP 被动开关暂时关闭，避免 scope mismatch；
- eventbus current、发现页、服务线索和 TTL/DHCP 被动信号已接入。

### 发现页

路径：`/devices?tab=discovery`。

已具备：

- 顶部概览卡片：发现设备、哑终端线索、本页服务线索、本页近期活跃；
- 终端类型图标；
- 地址/名称/MAC、终端类型、制造商/型号、操作系统线索、网络位置、发现依据、服务/端口、证据状态、最近观测、操作；
- 服务/端口来自 DNS-SD/SSDP 镜像公告，例如 `_airplay._tcp · 7386`、`_lyra-mdns._udp · 5353`；
- 设备详情展示厂商、型号、VLAN、网络域、传感器、TTL、DHCP 主机名/厂商类/请求选项、服务线索和证据历史；
- MAC OUI 厂商补全；
- 主机名类型/OS 线索。

### 当前已知边界

- 精确 OS 版本无法从镜像稳定得到，只能给 OS 家族线索；
- 接入交换机物理端口需要 LLDP/FDB/SNMP，当前镜像位置不可得；
- 服务端口只能看到公告或实际流量，不能证明开放/关闭；
- SNMP/NDM 事件不在镜像中；
- 当前页面部分字段是低置信度线索，前端必须保留“线索”标识。

## 代码入口

- 发现页：`frontend/src/pages/PassiveDiscoveryPanel.tsx`
- 发现查询：`internal/discovery/eventbus_query.go`
- 被动信号 API：`internal/controlplane/passive_signals.go`
- 镜像握手详情读取与采集域映射：`internal/store/discovery_handshake_clues.go`、`internal/controlplane/discovery_handshake_scope.go`；现场映射由 `PROXY_SENTINEL_DISCOVERY_HANDSHAKE_SCOPE_MAP` 指定，未配置时不返回跨域握手线索。
- 服务线索读取：`internal/store/discovery_services.go`
- 当前切流/清库说明：`docs/discovery-data-reset-20261031.md`
- 高性能流式架构：`docs/high-performance-streaming-architecture-20261030.md`
- 设备中心查询设计：`docs/device-center-storage-query-design.md`

## 2026-10-31 原计划与本地进展（历史记录）

> **2026-10-31 本地进展，尚未部署或现场验收。** 发现台账合并了终端类型/厂商和证据状态/观测时间列，固定右侧操作列；390、1280、1440 三视口的 mock 截图和 DOM 探针通过。被动信号接口按 MAC 与 VLAN 聚合 TTL、DHCP REQUEST 的 option 55/60 线索，增加 15 秒日志尾部快照缓存、观测时间与 Windows/Android 家族线索；跨来源冲突在页面标为“线索冲突”，服务公告按类型和端口去重并在详情显示观测时间。上述改动没有把 DHCP REQUEST 当作地址绑定。
>
> **仍待完成：** HTTP User-Agent、TLS JA3/JA4、SMB native OS 和 observed flow 端口尚未进入此台账。现有快照只覆盖日志尾部，不能代替逐消息 REQUEST 的持久化被动信号投影，也未测量现场识别覆盖率。坏段隔离告警及现场验收仍待处理。后续接入时须按标准事件与证据语义实现，不能将访问端口表述为开放端口。

> **2026-10-31 后续本地进展与现场只读基线。** 184 在核对时 Kafka 两个消费组积压均为 0，但 67,580 条活跃流式设备状态中有 2,155 条尚未进入 65,059 条的 current 台账；现场应用仍为 `2026.10.29-stream-retry-r16b`。本地新增按代次、结果版本推进的有界补入游标，每轮最多 200 行和 8 MiB，同事务写入台账与进度；尚未迁移或部署，不能把上述缺口称作已修复。采集范围有效期由 API 检查，提前 14 天在发现页提示；现场文件有效期至 `2026-12-31T00:00:00Z`，目前不会触发提醒。当前逐消息 DHCP 文件约 5.7 MiB，TTL 文件约 577 MiB，后者只读尾部明显不足以覆盖完整观测历史。对应持久化投影仍是下一项工作。

> **2026-10-31 本地续进展，仍未部署。** current shadow 的 fact 变化和自然过期改为每轮各最多 1000 行的复合游标，更新受影响设备后同事务推进，删除了每次 fact 变化触发的全表聚合与清理。发现页按本页 MAC 从活跃流式 DHCP 事实取最近的持久线索与事件号，和近期 REQUEST 日志合并；这只覆盖已进入流式事实的 DHCP 观测，逐消息 REQUEST 尚未正式持久化。Zeek 回放确认 option 61 的客户端标识类型和硬件地址、option 93 的**出现状态**可保留到 ACK 绑定和标准事件；当前 Zeek 解析器不提供 option 93 的架构值，页面不推断该值。改动涉及的 Go 测试、构建、vet、前端测试/类型检查/构建及三视口 mock 检查通过；本机 Zeek 8.2 的集群回放基线因未配置 cluster backend 失败，单机包回放 3 项通过。现场索引增长、性能和识别覆盖仍未验收。

> **坏段处理的本地实现，仍待现场验证。** 对确定性的流式 fact scope/device 冲突，发现 worker 会在隔离目录为原始 segment 建立硬链接和内容哈希审计记录，保留原任务为“未处理”并停止该链路；重启时看到隔离记录会暂停，避免继续重试同一坏段。采集覆盖页与只读健康脚本显示隔离数量和处理缺口。其他错误仍遵循原有重试与恢复策略。切流后旧代次文档按设备键有界清理；未部署，不能将现有现场坏段或旧代次残留视为已处理。

> **后续本地核对。** 隔离清单改为同步临时文件后原子发布，避免崩溃留下半份审计记录。流式状态分配结果版本时加事务锁；eventbus fact 改用事务有序的变化版本游标，避免并发事务逆序提交令 current 台账永久漏行。迁移会一次性为现有 fact 补齐版本，后续由触发器维护。被动 DHCP、TTL 按传感器及 VLAN 合并；HTTP User-Agent 与 TLS JA3/JA4 从已有设备信号事实按传感器、当前 IP 限量读取，带最近事件号与时间，仅作为 IP 弱线索。MAC 设备不会仅凭 IP 上的 UA 推断操作系统。上述新改动完成本地单元、类型检查、构建和三视口 mock 检查；仍未部署、未测现场查询延迟与覆盖率。[Zeek 8.2 的类型定义](https://docs.zeek.org/en/v8.2.2/scripts/base/init-bare.zeek.html)仅在 SMB1 会话中提供 native OS 字段，当前尚未接入采集与台账。

> **current 切流复核。** 流式文档更新不再重复读取该设备全部 eventbus facts；旧代次按批退役时先移除旧流式事实，再从仍有效的 eventbus facts 恢复，并在 Redis 中先失效后回填。常规 eventbus fact 变更仍会重读该设备事实，后续需要增量计数与事实映射改造，不能将这一点视为已满足有界事实处理。逐消息 DHCP REQUEST 持久化、observed flow 端口投影、现场覆盖率与索引增长测试仍未完成。

> **实际访问端口本地实现，待迁移与验收。** 新增按传感器、源 IP、协议、目标端口及 10 分钟窗口聚合的 ClickHouse 读模型，仅从新流量写入，保留 7 天；发现页只对当前地址读取最近两小时桶，标为“实际访问线索”，展示样本事件号与观测时间，明确不代表设备端口开放。读模型每个分组增加一份聚合写入，需在 184 验证实际增长和查询延迟；未回填的时间段不宣称覆盖。

> **服务公告归属复核。** 服务线索改按传感器与 MAC 成对读取和匹配，详情展示样本事件号与最近观测时间；仍从两小时 `normalized_events` 原表读取，需在现场测量请求成本，再决定是否建设独立公告投影。访问端口桶采用最大时间和对应样本事件，避免重试写入把次数虚增。

> **逐消息 DHCP 本地链路，待现场切源。** 受审计的 Zeek 文件流新增 `--zeek-dhcp-message` 入口，固定解析版本 `zeek-dhcp-message-v1`，沿用按文件代次、偏移及原文哈希确认的持久段。`device_dhcp_message.log` 的 REQUEST 形成 MAC 线索事实，保留 option 55/60/61 与 option 93 出现状态，但删除其请求地址作为当前绑定；ACK 只用明确分配地址形成绑定，OFFER 等消息只留标准事件、不进入设备事实；缺失或无效 MAC/IP 的消息也只保留原文与不可投影事件。现场切源须先停用旧 reader，使用 `stream-cancel` 预览与应用审计退役旧源，再用 `stream-prepare --zeek-dhcp-message` 确认固定起点与旧输入审计，最后以 `stream-run --zeek-dhcp-message` 启动；运行时拒绝两个 DHCP 文件源并行。2026-11-01 只读核对显示 184 的 `proxy-sentinel-ingest-stream-dhcp-layered-r8.service` 仍活动，使用 `zeek-dhcp-binding` 读取 `/opt/proxy-sentinel/data/zeek/logs/current/device_dhcp_binding.log`；尚未执行切源，也不能把本地测试称为现场覆盖。

### P0：修正发现页布局和空列

- 当前表格列较多，1440 视口下“最近观测/操作”容易互相挤压；
- 需要把操作列固定在右侧，或压缩列宽/合并列；
- 增加三视口检查：390×844、1280×800、1440×900；
- 不允许使用“未识别/未获取/未知/—”占位。

### P0：完善被动 OS 指纹

现有：

- 主机名前缀；
- MAC OUI；
- TTL；
- DHCP vendor class/requested options（API 直接读日志尾部）。

下一步：

1. 把 `device_dhcp_message.log` 正式纳入数据链路，按 MAC/IP 聚合并缓存，不要每页请求重复读大文件；
2. 解析 DHCP option 55、60、61、93；
3. 增加 HTTP User-Agent、TLS JA3/JA4、SMB native OS 信号；
4. 输出 `os_family`、`confidence`、`evidence`，不要输出确定版本；
5. 多个信号冲突时显示冲突，不要取第一条。

### P1：服务端口/服务名称

- 已从 DNS-SD/SSDP payload 提取；
- 增加 observed flow 的 `dst_port` 聚合，区分“服务公告”和“实际访问”；
- 输出证据来源和时间，避免把访问端口当成开放端口；
- 页面按服务类型/端口去重，避免一个服务实例刷多行。

### P1：接入位置

- 当前只有 VLAN/网络域/传感器；
- 若后续能把镜像点放到接入交换机，可补 LLDP/FDB；
- 当前不要用 VLAN 推测物理端口。

### P2：采集可靠性

- 发现 segment 曾因 fact scope mismatch 阻塞，坏段已移到 `/var/lib/proxy-sentinel/discovery-quarantine-20261031`；
- 为同类坏段增加自动隔离和告警，不要无限重试；
- 监控 `discovery_device_current_shadow` 最新时间和 eventbus lag；
- 采集范围有效期到期前自动提醒；
- 不在采集路径里做无界文件读取。

### P2：页面验收

- 发现页总数与 current 表口径对齐；
- 服务线索、OS 线索、类型线索在详情可追溯；
- 页面无 console/page error；
- 390 宽度使用卡片布局，不出现表格爆框。

## 明确不做

- 不主动扫描全网；
- 不猜 SNMP community；
- 不伪造 OS/端口/接入位置；
- 不把线索写成确定结论；
- 不删除唯一原文或未核验归档。

## 验证命令

后端：

```bash
go test ./internal/controlplane ./internal/discovery ./internal/store
go build ./cmd/proxy-sentinel
go build ./cmd/event-bus-current-shadow
```

前端：

```bash
cd frontend
pnpm test --run
pnpm typecheck
pnpm build
```

现场只读核对：

```bash
/opt/proxy-sentinel/scripts/eventbus-184-health.sh
```

页面：

```text
http://222.204.3.184:8088/devices?tab=discovery
```

## 最近提交

```text
85eb38c8 接入被动TTL与DHCP信号
b4cd6e66 增加被动服务端口列并修复采集范围过期
25f8268f 增加镜像流量被动服务线索
00bc6954 优化SNMP网关候选排序
3a26cae6 增加从发现网段选择SNMP候选
```
