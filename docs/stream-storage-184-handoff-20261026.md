# 184 新存查链交接（2026-10-26）

本文件供换电脑后继续本轮任务。目标仍是按 [端到端架构](stream-storage-query-architecture-20261024.md) 完成当前采集路径的切流和真实验收，再分批扩 Zeek。历史未处理输入仅在有不可变截止点、数量和哈希的取消清单后放弃；新起点后的输入不得暗中跳过。现场状态须每次重新只读核对。

代码已提交到 `codex/stream-storage-handoff-20261026`。GitHub 推送遇到本机 SSH/HTTP 代理断连，因此另将包含完整提交历史的 Git bundle 放在 184：`/opt/proxy-sentinel/handoff/stream-storage-handoff-20261026.bundle`，同目录有 `.sha256`。换电脑后先从 184 下载两文件，校验 SHA256，再用 `git fetch ./stream-storage-handoff-20261026.bundle refs/heads/codex/stream-storage-handoff-20261026:refs/heads/codex/stream-storage-handoff-20261026` 导入并切换分支。后续若远端网络恢复，再推送该分支。bundle 仅含代码、迁移、测试与文档，不含现场原始事件、发布包或口令。

## 当前已完成

- 184 的 `current=/opt/proxy-sentinel/releases/2026.10.26-stream-b55`，兼容回退 `previous=/opt/proxy-sentinel/releases/2026.10.25-stream-compat-a44`。B55 发布包 SHA256 为 `3b04819acf1fb163eefe1358b7488dad244bc9ef7e212da44747bf3e5caed8fa`。PostgreSQL 已应用至 191，ClickHouse 至 055；应用升级器逐项核对所有迁移哈希，B55 无新迁移。旧 B54、B53 等发布目录保留。2026-10-26 00:26 CST 控制面 `18080/readyz` 与身份桥 `18082/readyz` 均为 200，旧 ingest 与身份桥活动；根盘余量约 451 GiB。
- DHCP 绑定新链和身份新链接入了按来源位点的持久日志、ClickHouse 互斥正文及窄检索、独立归档和 PostgreSQL 投影回执。DHCP B47 与身份 B51 各通过两个连续 15 分钟真实输入窗口，逐条 API 没有 5 秒超限。验收仅覆盖当时输入与已启用路径，不代表当前容量或新增协议通过。对应分析和原始观察在 `artifacts/stream-b2-184/`，实施状态见 [持续记录](stream-storage-query-implementation-status-20261024.md)。
- B55 修复侧车 SSDP 高扇出：单一 IP 在失败片段前已有 214 个事实键，新增 50 条里有 47 个不同 USN，旧代码超过 256 后整片回滚。B55 仍保存全部事实、回执和差量，设备摘要最多读取 256 条，维护精确事实数，并对摘要不完整的分类降级。Go 全量测试、构建、vet 通过。该修复**尚未在侧车真实输入上验收**。

## 现场停点与数据完整性

1. `proxy-sentinel-ingest-stream-packet-b54.service`、`proxy-sentinel-ingest-stream-handshake-b54.service` 及对应 `proxy-sentinel-device-signal.service`、`proxy-sentinel-handshake-signal.service` 均停止。packet/handshake 来源 cutover 仍 active，旧 ingest 会排除这两路；不能直接重开旧消费者造成双写。packet 约 8 个、handshake 约 2 个未确认持久片段，源文件和游标仍在现场。原 15:52–15:55 UTC 试运行失败，packet 最老片段达 33.59 秒、未读约 171 KiB，不能计通过。packet 源文件 `/opt/proxy-sentinel/data/device-signals/ttl.jsonl`，日志 `/opt/proxy-sentinel/data/stream-journal/packet-b54-fresh`；handshake 对应 `handshake.jsonl`、`handshake-b54-fresh`。因采集器停止，现无新增这两路文件输入；重启前先排空已接受片段并单列过去的 5 秒超限。
2. `proxy-sentinel-ingest-stream-dhcp-binding.service` 处于 failed，**不要简单 restart**。B47 固定代次 `dhcp-binding-fresh-20261025T1402Z` 的片段 `4921960c4e69cd8dbf95c8e9d14c8f9352fe0a50927cbb987ddc3e4084ff4ced` 含 6 条 16:12 UTC 的真实 DHCP 记录，归档和检索已确认，PostgreSQL 投影因同事件键不同哈希拒绝，片段保存在 `/opt/proxy-sentinel/data/stream-journal/dhcp-binding-b47-fresh13/`。同一事件键的旧正文于 14:03 入库；16:00 新建的 Zeek 文件复用了旧文件 inode `46670368`，旧键只用路径、设备号、inode、偏移，发生碰撞。ClickHouse 对失败片段已有 6 条正文、6 条检索、6 条风险特征及 1 条原始段，PostgreSQL 无该片段的投影或回执；其中一个键在 ClickHouse 有旧新两种哈希。先保留全部证据，不把这 6 条算作成功。当前 Zeek 文件还会轮转，恢复时用压缩归档和原文哈希核对，不依赖当时的 `current/` inode。
3. 本地 **B56 候选未发布**：`internal/realtime/zeek_archive.go` 已改为每次核对已提交尾部哈希，遇 inode 复用时搜索压缩归档；`internal/streamlog` 新增单调文件代次，`internal/realtime/stream_capture.go` 以代次参与固定事件键，`cmd/proxy-sentinel/ingest_stream*.go` 将 DHCP 绑定 parser 升至 v2。模拟同 inode 轮转、归档取回、位点恢复和不同代次键的测试、`go test ./...`、`go build ./...`、`go vet ./...` 均通过。**尚缺将 B47 未确认片段及后续未读新输入无损转入新代次的审计流程**，因此不要打包发布或启动 B56。新的代次应从失败片段起始偏移 243214 重新消费，先核验该范围与已存片段、压缩归档一致；不得把这段新输入写成“已处理”或悄悄取消。新代次完全确认后，核验旧段无案件引用，再针对旧代次孤立的 ClickHouse 正文、检索、风险特征和原始段做精确清理，保留 14:03 的旧正文和修复审计。普通 ClickHouse 重试仍须按固定键核对，不盲发。
4. 风险常驻新消费者与新增 Zeek 协议均保持关闭。身份桥的目录接口曾持续返回 `remote_http_409`，桥 `ready=200` 但业务状态 degraded；与本次 DHCP/SSDP 修复分开核实。当前只证明 DHCP 和身份在先前限定窗口可运行，机械盘资源曾接近饱和，不能对更多协议作容量承诺。

## 接下来

1. 在新电脑取得本仓库的交接分支后，先确认 Git 工作区和 184 的 `current`/`previous`、服务、数据库迁移账本、四条停止来源及源文件归档。SSH 只连 `root@222.204.3.184`，不要使用默认指向其他节点的快捷命令；凭据不写入仓库或命令输出。本地不启动 Docker/OrbStack 数据库栈。
2. 为 B47→B56 做受控无损代次转移：逐段核对原始哈希、旧回执和新代次起点；补测试覆盖同 inode 两代、停机、跨小时压缩归档、ClickHouse 部分写入、冲突正文清理、重新消费的幂等。若现场旧源范围无法验证，停在隔离状态并报告准确缺口。
3. 本地测试、构建、vet 后，按现场规则构建唯一包；184 应用升级器会核对迁移 SHA。保留 A44 为 `previous`，不能覆盖旧发布目录。先仅恢复 DHCP 和失败片段，逐条记录首次入库、投影、归档、API 可见及旧异常；再单独排空 packet/handshake 的保留片段，完成短时保护试运行及两个完整 15 分钟窗口。任一超时、内容冲突、资源或积压门槛失败即停新增采集，不能跳新任务或靠加超时/并发通过。
4. 当前已启用路径全数通过后，依原协议计划逐批开启 Zeek；普通 conn/DNS/HTTP/SSL、无适配器协议和受限 IoT 候选仍不能直接开启。每批以真实新输入的归档、投影、查询、资源和积压验收，而非服务 ready 或日志出现。

本次记录不包含服务器口令。`artifacts/stream-b2-184/` 中包含本机观察、临时脚本和发布包，未必随 Git 交接；现场 `/tmp/ps184-b54/`、`/tmp/ps184-b55/` 及持久日志仍在 184。先重新核对现场，不把本文件的数值当作实时状态。
