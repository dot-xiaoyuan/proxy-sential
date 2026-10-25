# 184 新存查链交接（2026-10-26）

本轮目标和验收规则见[端到端架构](stream-storage-query-architecture-20261024.md)及[实施状态](stream-storage-query-implementation-status-20261024.md)。换电脑后先拉取远端分支 [`codex/stream-storage-handoff-20261026`](https://github.com/dot-xiaoyuan/proxy-sential/tree/codex/stream-storage-handoff-20261026)，核对现场后继续。184 上的 `/opt/proxy-sentinel/handoff/stream-storage-handoff-20261026.bundle` 是推送前的旧离线备份，**不能代替远端最新提交**。本地不启动 Docker/OrbStack 数据库栈；SSH 目标只用 `root@222.204.3.184`。

## 已发布和审计

- 2026-10-26 00:43 CST 发布 B57：`current=/opt/proxy-sentinel/releases/2026.10.26-stream-b57`，兼容回退 `previous=/opt/proxy-sentinel/releases/2026.10.25-stream-compat-a44`。B57 包 SHA256 为 `3f01c78b88187a6f415d39007032f0af8016ecb2a3172075896f0eee2589e0e4`，源码提交 `6147af8`；旧 B56/B55 和 A44 目录保留。应用升级器确认 PostgreSQL 191、ClickHouse 055 个候选迁移均已应用且哈希一致，无新迁移。控制面 `18080/readyz`、身份桥 `18082/readyz` 在 00:47 均为 200，根盘余量约 452 GiB。
- DHCP B47 失败原因已定位：Zeek 16:00 UTC 的新文件复用 14:03 文件 inode，旧事件键只含路径/inode/偏移，导致同键不同正文。B56 新增有尾部哈希证明的轮转恢复、单调文件代次和代次事件键。首次真实接入发现 ClickHouse 归档入口遗漏 `generation-v2` 键，B57 加入校验与回归测试。Go 全量测试、构建、vet 通过。
- 用户明确放弃未处理历史。旧 B47 以不可变清单 `artifacts/stream-b2-184/dhcp-b47-retirement-b56.json` 审计关闭：未处理 1,461 条/468,531 字节，清单 SHA256 `17ef75d08501aa586aaaba1051d22413f34a1799c8ac95863589b0018ef3b61d`。新起点 `2026-10-25T16:37:35Z` 的 `stream-prepare` 又审计取消 95 条/30,614 字节，清单 SHA256 `ed959c02fc397b298d28e3dc48652af77f3715c7cb46b616b7f6536a791695f8`。合计 1,556 条/499,145 字节均标为**取消未处理**，不计成功；原始文件和旧片段保留。新代次 `dhcp-binding-b56-fresh-20261025T163735Z` 从偏移 742359 开始，journal 为 `/opt/proxy-sentinel/data/stream-journal/dhcp-binding-b56-fresh14`，消费者单元名为 `proxy-sentinel-ingest-stream-dhcp-binding-b56.service`，旧 B47 单元仍 failed，不能重启。
- B56 的第一个 50 条片段曾因本地键校验失败留下 `archive=attempted`，没有发出 ClickHouse 请求。B57 重启后按未知结果只读核对，正确地没有盲重发，故 60 秒无归档进展时已停消费者。针对片段 `ab19753c95848b711a4187309b0d417bce80f5874d521b161dd752b8b3e7b816` 核实原始哈希、ClickHouse 原文/正文均 0 行、异步插入 0、原 token 查询日志 0、同期间查询日志覆盖 296 条后，使用精确限定的小工具把这**一次已知未发送**的 archive attempt 恢复为 pending；没有伪造 ack 或清空片段。随后 B57 正常归档。00:47 CST PostgreSQL 16 片/541 条投影，541 条归档状态 confirmed，journal 片段已归零，源偏移与当时文件大小相同。此前停机片段已超过 5 秒，须单列失败，不得用于新鲜验收。
- 本地随后新增流处理器纯本地预检：归档/检索入参、原文哈希在记录 attempted 之前验证，防止确定性本地错误再次滞留成未知结果。`go test ./...`、`go build ./...`、`go vet ./...` 均通过；候选 B58 包 SHA256 为 `a2986aa0edf14d736a44b148057e3e71acda4a0dcf4fbf02bf19adef5d70febe`，已上传到 184 `/tmp/ps184-b57/`，**尚未发布**，现场仍为 B57。换机后以远端最新提交为准，并按迁移校验及受控应用升级发布。
- 00:58 CST 另发现 DNS-SD B3 服务虽然 active，但自 2026-10-24 15:29 UTC 起有 66 个片段滞留；首片 79 条正文存在、检索 0 行、原 token 在 ClickHouse 查询日志 0 次、异步插入 0，且同期日志有 180 条插入覆盖。已停止新抓取，只对这一精确片段把已知未发送的检索尝试恢复为 pending；使用 `discovery-worker --mode=stream-drain` 排空全部 66 片。现场核对 4,916 条 PostgreSQL 投影与归档确认、ClickHouse 正文与窄检索均对齐，保留片段归零。**这些片段逾期约一天，不能计作实时验收。** DNS-SD 抓取仍停止，`service-expectations.json` 已记录停止状态，原文件备份在 `/tmp/ps184-b57/service-expectations-before-dns-pause.json`。
- 01:03 CST 在侧车采集器保持关闭的条件下启动 B54 新流消费者，排空 packet 与 handshake 的保留片段和来源文件未读尾部。原失败高扇出片段 `1eea26d0024fb4125a79152f21bb89d57ab9467fc5f1f98160bca95d948dde76` 50 条在 B57 成功投影；packet 代次 938 条发现回执均归档确认，82 台设备中 1 台摘要标记 `facts_truncated`，最高精确事实数 413；handshake 有 2,244 条共享片段回执。两路来源游标均追到当时文件末尾、待处理片段归零。**侧车新抓取仍关闭，旧片段逾期不能计入实时验收。**

## 尚未通过的门槛

1. DHCP B57 当前消费者已启动，仍须重新检查**当次**源偏移、journal 未确认片、ClickHouse 原文与窄索引、PostgreSQL 回执、逐条查询，以及两个完整连续 15 分钟窗口。00:47 的 541 条确认仅证明故障片段排空，不能作为实时 5 秒验收。尤其要观察 17:00 UTC Zeek 轮转后文件代次能否正确加 1，不能只看服务 active。风险新消费者和新增 Zeek 协议都保持关闭。
2. DNS-SD B3 的旧片段已排空，但新抓取停止。DHCP 门槛通过后才恢复真实新输入，重新逐条验收两个完整 15 分钟窗口；不能用旧片段排空代替。
3. packet/handshake 的 B54 stream 消费者已恢复，采集器仍关闭；旧采集入口受新 cutover 保护。B57 在原失败高扇出片段上已验证有界摘要与精确事实数，但新抓取尚未通过。DHCP 窗口后受控开放新输入、按来源单独观察两个 15 分钟窗口；失败即停新增输入，保留证据。当前共享作业新代次 582 个 IP、1 个网关均已完成且自然过期，不能作为新鲜设备结论。
4. B47 失败片段在 ClickHouse 留有 6 条孤立正文、6 条检索、6 条风险特征及 1 条原始段，PostgreSQL 无成功投影。精确核验无案件引用、旧 14:03 正文可区别之后才能清理孤立重复行；不能广泛删除或把取消任务计作已处理。
5. 身份新链此前通过两个连续 15 分钟真实窗口，目录接口曾返回 `remote_http_409`、业务状态 degraded；须复核当前状态。风险新链、packet/handshake、新 Zeek 协议尚未通过端到端验收，不能宣称新方案全量落实。协议扩展仍按原计划逐批执行，普通 conn/DNS/HTTP/SSL 及无适配器协议不直接开启。

现场凭据不写入此文档。每次操作前重新只读核对版本、服务、迁移和积压；保留 A44 的 `previous` 回退入口，不改写已应用迁移，不在现场造数，不将日志产生或 ready 当作业务验收。
