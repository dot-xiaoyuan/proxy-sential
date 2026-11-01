# 被动发现 Journal WAL：当前实现与后续持久化设计

更新时间：2026-11-02。本文是本地实现说明和下一阶段设计，不是现场启用或容量验收记录。现场版本、授权与运行结果由[当前任务](current-work-20261031.md)记录。整体存储约束见 [AGENTS.md](../AGENTS.md) 和[高性能流式存储方案](high-performance-streaming-architecture-20261030.md)。

## 1. 当前状态与边界

**WAL 写入尚未启用；`discovery-worker` 没有 WAL 可写 CLI 参数。** 当前 cmd 使用 `WriteEnabled=false`：没有 WAL 时继续原 v1 Journal；存在有效 WAL 时可恢复、读取和通过 `DrainOnly` 排空，不能向新 WAL 写入，也不能悄悄改回 v1 写入。需要隔离的段仍阻止正常采集/排空，必须先解决隔离原因。实验性库接口允许本地测试显式开启写入，但不构成现场启用入口。

当前文件上限默认 **1 GiB**，适配器默认最多 **4096 个 v2 accept**，其中已经 finalized 的段也计数。没有轮转、checkpoint 或 GC；`Release` 只追加 finalized，正文和索引项仍保留。因此即使消费者没有积压，持续输入也会到达上限。本阶段不能通过增大文件或段数上限来宣称可长期运行。

r39 实际输入下，journal 在 1,170 秒阶段窗口内接受 532 段，最近 200 个已投影段的来源字节平均约 519 KiB。若 WAL 编码量与来源字节同量级，以这些短样本粗算，现有 1 GiB/4096 段实验上限可能在约 1–2.5 小时触达某个边界；来源字节不等于 WAL 编码大小，不能当作容量预测。单来源 accept 持有 `sourceMu` 直到持久回执，现有 group commit 不会合并两个 accept；仅加轮转而不做有证明的正文与索引退休，也不能解除累计增长。

容量准入批已将字节拒绝移到入队之前：总硬限 `MaxLogBytes` 默认 1 GiB，控制预留默认 `min(16 MiB, 总限/16)`，Data 高水位 `MaxDataBytes` 默认总限减预留，显式高水位只能进一步调低。accept 使用 Data，genesis/lane/finalized/quarantine 使用 Control；所有已耐久、排队和在途记录按共同文件位置计费，每条在途记录保守预留独立 seal，group 成功后原子归还多余 seal 空间。

数据达到高水位时返回明确的 `ErrNotWritten + ErrCapacity + ErrDataCapacity`，不停止 writer；控制记录仍可用剩余总预算。总硬限不足时两类追加都明确拒绝；不会因重启而获得 EOF 之上的新额度。真实短写/同步未知错误仍停止整个 writer。原始 `9e65f20` 实现在提交时才发现超限并停止全部 lane/finalized，此回归已由本批容量测试覆盖。4096 仍是累计 accept 上限，不因 finalized 减少。

降低 Data 高水位仍可利用总限内的 Control 空间；降低总限到 EOF 以下仍可读取/回放，但不能再追加控制记录。现有 cmd 在 capture 失败后仍会取消各 lane，本批没有修改该生命周期，也没有开放可写 CLI；库内可利用预留排空，不代表 cmd 已自动进入停采排空模式。

设每秒接受段数为 `r`、平均每段正文及其控制记录字节为 `B`，无回收时触顶时间近似为 `min(4096/r, 1 GiB/(r×B))`，与是否及时 finalized 无关。仅作量级示例：平均每段约 1 MiB 时，字节上限约容纳一千段；小于约 256 KiB 时，累计段数上限可能先到。这不是现场速率或容量承诺。

只支持 `passive-discovery` / `passive-frame-v1` 的标准发现事件。保留 scope 验证、固定新起点、首次 `AcceptedAt`、内容哈希和三条消费 lane。拒绝 Zeek、source-backed raw、early processing、generation-v2、额外 risk lane 等尚未适配的模式。不会改变处罚与上报的仅记录边界。

## 2. 已实现内容

| 位置 | 职责 | 当前限制 |
| --- | --- | --- |
| [streamwal](../internal/streamwal/doc.go) | 单 writer、有界 group commit、frame/seal 校验、LSN 与结果回执、恢复和读取 | 单文件，本地文件系统耐久语义，无复制与自动修复 |
| [passive_wal.go](../internal/streamlog/passive_wal.go) | accept 原子推进 cursor、旧段路由、三 lane 状态、finalized、quarantine | 单来源、内存索引有上限、没有退休 |
| [processor.go](../internal/streamlog/processor.go) | `ProcessorJournal` 接口，沿用现有 sink write/reconcile/finalize | 不把 Unknown 当作已失败重写 |
| [stream.go](../cmd/discovery-worker/stream.go) | 默认 v1 / WAL 兼容读取、起点验证、停止错误处理 | 未暴露 WAL 写入开关 |
| [passive_quarantine.go](../cmd/discovery-worker/passive_quarantine.go) | WAL 隔离记录及正文引用，v1 继续硬链接原文件 | WAL locator 尚未支持文件轮转 |

### 2.1 底层 WAL

`Open` 持有独占 writer lease，验证既有文件、同步文件和目录祖先后才返回。`Append` 先按记录数和字节数双重准入，复制 payload，并返回单结果 channel；只有完整 group 与 seal 的 `Sync` 成功后才能返回成功 receipt。等待中的记录和正在同步的记录都计入队列预算。入队后的 context 取消不撤回所有权，调用方必须等回执或重启核对结果。

默认单 payload 上限 4 MiB，group 上限 8 MiB / 128 条，队列上限 32 MiB / 256 条；读取按格式硬上限验证。每条 data frame 的头和正文均有 SHA256，seal 绑定 group 的起始位置、首 LSN、条数和完整 frame 集合。当前 receipt 内部保存 frame/seal 校验信息，外部不能随意构造可信 receipt。

- 未入队错误：请求没有被接收，可以明确区分。
- 写入或 `Sync` 错误：本组返回 `ErrIndeterminate` 并停止 writer；不能把已写入可能性伪装成明确失败。
- 尚未发送的排队项：返回 `ErrNotWritten`。文件容量不足且尚未写入也保持明确未写入语义。
- 不完整 tail 或校验损坏：保留原字节并拒绝可写重开，不截断、不跳过、不自动修复。
- 完整 sealed group 的前一次同步结果可能未知；`Open` 重新校验和同步后，允许适配器按稳定业务 ID 核对。

只读恢复已与新写入预算分离：`Open` / `Inspect` / `Read` / `Replay` 使用独立的 64 GiB 文件守卫和既有逐 frame/group 格式限制，不因调低 `MaxLogBytes` 拒绝既有合法数据。配置组合本身仍须合法；总限低于 EOF 时只保证恢复读取，不承诺可以追加 ack/finalized。

`DurablePosition` 现在可返回当前单文件 v1 的已同步 LSN、EOF 和逐组 seal 累积摘要；`VerifyPosition` 从文件起点回放到指定边界并核对摘要。它只证明这一个 v1 文件的内容前缀，不能证明业务适配器已经折叠所有回执，也没有跨代际 journal UUID 或可退休文件的证明。checkpoint 须先取得下文的 mutation 独占门；新格式仍需文件头和磁盘上的 seal 链。

### 2.2 业务状态与兼容入口

构造顺序为：取得 source lease → 读取原 cursor → 调用 `BeforeRecovery` 验证数据库中的固定新起点 → 才允许恢复旧段或建立 WAL genesis。callback 失败时 cursor/state 不变、不创建 WAL、释放 lease。默认纯 v1 分支不提前 `RecoverSource`，继续由 cmd 在验证后显式恢复。

第一次建立 WAL 时，genesis 固定完整 legacy cursor；之后 v1 `.cursor` 冻结为切换锚。每个 accept 的 payload 直接使用 Segment 编码，原子包含不可变正文、source predecessor、结束 offset、首次接收时间和归档月，不额外包裹一份正文。单段精确 4 MiB 边界仍可使用。重复 ID 必须具有相同语义哈希，保留首次时间；新的 accept 必须严格接续 cursor。

WAL 回放一次构建有界 metadata 索引；正文只存于 accept frame。`Load` 按 receipt 定位并验证 frame/seal、ID 和内容哈希。状态读取不需要重新解码正文，但三条 lane 初次取正文、finalize/release 的必要验证仍存在；本批没有正文缓存，不能宣称已消除所有重复解码。

三条 lane 分别遵循 `Pending → Attempted → Acked`。Attempted 必须在外部写之前耐久；结果不明时只能走既有 reconcile。只有能够证明尚未发出的请求才允许 `Attempted → Pending`，已 Acked 不能撤销。三 lane 均确认且外部 finalizer 成功后追加 finalized；尚未完成、Unknown、隔离和失败都不计作完成。

旧 v1 未完成段仍从原 `.segment/.state/.acklog` 恢复和消费，不复制成 WAL accept；旧 Release 成功后才移出跟踪集合，异常缺失正文不能跳过。纯 v1 保留 cmd 原有按 recovered ID 检查隔离 manifest 的行为；WAL 激活/恢复另有全目录 unresolved manifest 门禁。

`Quarantine` 与 accept 共用 source 锁，先持久化 WAL 隔离状态再输出外部 manifest；后续 accept、Release 和写模式重开都会被阻止。manifest 保存 WAL reference，不生成伪造的 v1 `.segment`。即使在 WAL 隔离成功、manifest 尚未发布之间崩溃，原文和停止条件仍由 WAL 保留。

### 2.3 同步边界变化不等于实测收益

以下是普通 passive 段成功路径的代码级持久化边界，不包括数据库内部同步、首次建目录、恢复、重试或未来 checkpoint/head 成本。

| 操作 | v1 的同步调用 | 当前实验 WAL 的耐久记录边界 |
| --- | ---: | ---: |
| Append 正文 | 2 | 与 source commit 合并 |
| CommitSource：acklog/state/cursor | 4 | accept：1 |
| 三条 lane 的 Attempted 和 Acked | 6 | lane：6 |
| Release 标记与原文件退休 | 4 | finalized：1；尚未删除正文 |
| 合计 | 约 16 | 8 |

**“16 → 8”是调用/记录类型边界比较，不是实测 fsync 次数或磁盘吞吐提升。** 多个并发记录可以共用 group 的一次 `Sync`；同一段的因果顺序不能跨越耐久边界。单 capture 调用同步等待 accept，不能假设一个来源的多个 accept 自动合批。如后续选择增强的独立 head 模式，每组会增加同步；优先方案中的轮转/checkpoint/退休也有成本，必须重新测量。最终收益由真实磁盘、group 大小、lane 并发、sink 延迟和写入分布决定。

## 3. 下一阶段格式：文件代际、locator、seal 链和 manifest 锚

本节均为待实现设计。不能修改已有 v1 文件的含义或让旧 reader 误读新格式。建议新增明确的格式版本，保留当前单文件 v1 的完整读取路径；是否原地升级须由显式迁移流程决定。

### 3.1 文件与 locator

轮转文件按 journal UUID 和递增 generation 标识；全局 LSN 跨文件连续，不随轮转归零。文件头应绑定格式版本、journal/source identity、generation、首 LSN 和带类型的前代锚。每个新 seal 再绑定前 group seal hash；checkpoint 保留被删除前缀的认证锚，避免删除中间文件后把两个合法文件直接拼接。

新 locator 至少包含：格式版本、journal UUID、generation、全局 LSN、frame offset/length/digest、group start/count、seal offset/digest。路径只作定位，不能作为完整性证明；必须核对文件头和 reference 的 journal identity。当前 `PassiveWALReference` 只有目录/LSN/offset/length/content hash，是单文件诊断引用，不能直接当作跨代际、可持久导入的可信 locator。

v1 `Receipt` 虽在内存里另有 frame/seal digest，但这些字段未导出，也没有文件 UUID、generation、文件头或磁盘上的前组 seal 链。现有 `Read(Receipt)` 信任其由 commit/replay 生成，只读目标 frame 与 seal；把字段直接序列化后再读取，尚不能证明该 frame 属于该 seal 覆盖的完整 group。`DurablePosition` 的累积摘要可核验当前单文件前缀，但它不为单条正文生成跨代际身份。隔离记录中的旧 `PassiveWALReference` 必须保持诊断含义，不能隐式升级成可信 locator。

v2 文件头应绑定格式、journal UUID、固定来源身份（source/path、epoch 和 genesis 锚）、generation、首个全局 LSN 与前代末 seal 锚。从 v1 切代时，首代的前驱锚须显式标为 v1 前缀摘要，后代才是 v2 seal digest。每组 seal 在现有 group hash 之外记录前组 seal digest；跨文件的第一组以前代末 seal 为前驱。`ReadLocator` 先由 manifest 选定代际文件并核对文件头，再在有界 group 内核对连续 LSN、全部 frame、group hash、前驱 seal、目标 frame 的 offset/length/digest 与 locator 的 seal digest；最后由适配器核对段 ID 和业务 content hash。不能仅比对目标 frame 与某个合法 seal，也不能在缺文件、错代际或 hash 冲突时改读同名/同 offset 的其他文件。已经验证的完整 group 可缓存证明，避免每次详情读取重扫整个 journal。

隔离 manifest 和 checkpoint 必须使用版本化 locator。重定位 pending 正文时，旧引用通过受控 relocation 映射解析，不能原地改变历史 manifest 中的证据标识。读者正在使用的 generation 有引用保护，GC 不能先删除其文件再等待读者。

### 3.2 两种保证，优先采用轮转/checkpoint manifest

下一阶段首先保证**正确履行文件及目录 `Sync` 的文件系统上的常规进程崩溃/断电恢复**：普通 group 的成功回执仍只依赖 WAL group/seal 同步，不为每组增加独立 head 同步。accept 正文与 source cursor 同属一个有校验的记录，恢复不会只保留 cursor 而漏掉同组正文；未知结果仍按稳定 ID 核对，不完整 tail 保留并停止写入。

轮转或 checkpoint 时才发布独立耐久 manifest。它绑定完整 `SourceCursor`、journal identity、代际清单、连续 durable/applied LSN、end offset、seal hash，以及 checkpoint 文件名/版本/hash。写临时文件并同步，rename 后同步目录；成功发布前不能删除旧恢复依赖。manifest 是已经锚定前缀的最低水位，恢复发现 WAL 短于该锚、缺代际或 hash 不符必须停止，不能用更短前缀自行重建较旧 cursor。

这与更强的**外部删除/存储回滚检测**不同。一个完整合法的 active suffix 若在最后一次 manifest 之后被外部删除，剩余前缀仍然合法；本阶段不保证检测这种未锚定 suffix 回滚。`Sync` 成功后底层仍丢数据、文件被外部修改或连同 manifest 一起回滚，也不属于普通崩溃保证。seal 链可发现不连续、错误拼接和内容改变，不能凭空证明一个已经完全消失的合法末尾曾存在。

如果后续明确要求检测每个已确认 group 的这类删尾，需要额外独立 head/外部耐久收据，并在其同步之后才发布成功回执；周期性 head 不等价。可以研究双槽 head，但它会多一次 `Sync/group`、增加 WAL 成功而 head 未确认的 Unknown 窗口，并引入双槽选择/恢复规则。同盘 head 仅在自身幸存时帮助检测，仍不提供介质冗余。本批不实现此增强模式，也不把它设为最小轮转/checkpoint 的前置。

### 3.3 轮转提交协议

只在完整 group 边界轮转，不能把一组拆在两个文件中。建议先以可配置的小文件预算做本地验证，现场值依据实测设置。

1. 暂停新的 journal mutation，并等待所有已接收 mutation 完成耐久回执及内存折叠；记录当前 group/seal 和准确 cursor。
2. 创建下一代际文件，写绑定前代际的文件头，文件同步，再发布文件名并同步目录。
3. 将 checkpoint 和新 active generation 发布到耐久 manifest，再允许新文件接收业务记录；最低 durable LSN/seal locator 仍指向前代际已封口组，active 文件后续组由 WAL 自身恢复。
4. 崩溃留下未被 manifest 引用的新文件时，先检查其中是否有完整组和未知结果，再决定恢复；不能用“孤儿文件”名称直接删除证据。manifest 发布结果不明时停止切换，通过恢复核对，不能同时向新旧文件继续写。

轮转不等于 GC，旧文件要等 checkpoint、正文落点和读者引用都满足要求才可删除。容量不足必须在接收前明确背压，并给完成已接收的 lane/finalized、checkpoint 和迁移保留空间；不能把最后一点磁盘都用于新 accept，造成再也无法确认或释放旧段。

### 3.4 最小兼容发布顺序

1. **旧格式降级门禁**：先让仍只写/读 v1 的二进制识别未来格式标记，并在标记存在或版本未知时停止，不能静默回到冻结的 v1 cursor。保持 v1 WAL 原样且不开放新写入。v1 已接受的 pending 可继续从保留的完整 v1 文件回放；初次切代无需把旧诊断引用伪装成 v2 locator。这一批可独立发布。更早的二进制无法补上门禁，部署/回退脚本还须拒绝把已切代现场指向不兼容版本。
2. **v2 只读兼容**：实现上述文件头、seal 链、locator 与 manifest 的读取/校验，用本地构造文件回放错 UUID、错代际、跨组拼接、缺文件和截尾；cmd 仍不写 v2。此批可先独立发布并验证旧 v1 回放。随后才允许单独实施写入切代：在 mutation 门下核验 v1 最终 `Position`，先在与 v1 共享的来源 WAL 目录耐久发布格式门禁文件（文件和目录均 `Sync`），再以该前缀摘要锚定新 journal UUID 和首个 v2 header，耐久发布 manifest 后开始 v2 写入；v1 文件须保留到其全部引用经核验退休。

一旦有第一条 v2 accept，回退只能到已验证能读取该 UUID、manifest 和代际链的兼容版本；旧 v1 二进制即使能启动也不属于回退入口。格式标记或 manifest 发布结果不明时停止并核对文件，不自动删“孤儿”新代际，也不把旧 manifest 当作较短 cursor 继续运行。locator 校验只证明 WAL 字节及引用一致，正文退休仍另需归档与案件保护证明。

## 4. Checkpoint、正文退休与空间回收

### 4.1 Checkpoint 的正确水位

checkpoint 必须覆盖**连续已折叠的 durable LSN 前缀**。不能取多个 goroutine 已拿到 receipt 的最大 LSN：后一个 ack 可能先更新内存，前一个 accept 尚未更新；此时取最大值会遗漏 pending 正文。

最小实现可用一个 journal mutation 门：普通 accept/lane/finalized/quarantine 在持共享门期间等待回执并折叠状态；checkpoint 取得独占门，等待这些 mutation 完成，再读取 WAL durable position 和有界 metadata 快照。门只覆盖 journal 操作，不能覆盖外部数据库 RPC；在途 RPC 的 Attempted 仍出现在快照中，其后 Ack 等门释放再提交。这比立即引入全序异步状态协调器更小，但需要测量切代暂停时长。若未来改成在线快照，再引入明确的连续 `appliedLSN` 发布协议。

现已在 WAL 适配器实现共享 mutation 门和 `CheckpointCandidate` 内存切面；普通 WAL mutation 共享读锁，纯 v1 路径不经过该门。候选包含已折叠的 cursor、状态、原 receipt 和 durable position，不写磁盘、不发布 manifest。receipt 尚非可持久导入的跨代际 locator；必须先完成版本化 locator、正文验证与 manifest 恢复门禁，才能把候选保存为有效 checkpoint。

快照记录完整 cursor、legacy genesis 锚、prefix 的 generation/LSN/end/seal、所有未 finalized 的段及每 lane 状态、正文 locator/hash、隔离状态/原因和必要的完成索引，不重复保存全部正文。新记录只从该边界之后重放。barrier 之前的结果必须全部折叠，单纯等底层 `Sync` 或关闭 writer 不足以证明适配器 goroutine 已更新内存。

先写并同步 checkpoint 临时文件，发布文件名并同步目录，再通过耐久 manifest 原子引用该 checkpoint 及其 hash。此前的 checkpoint 和日志仍为恢复依据。只有新 checkpoint 与 manifest 均确认、所有引用验证通过后，才能进入 GC。若保留旧 checkpoint 作为回退，其引用的旧文件也必须保留；不能保留一个看似可回退但正文已删除的 checkpoint。

已 finalized 的索引不能无界增长。下一步需定义“已结束连续来源区间 + 未完成缺口 + 有界近期 ID/hash”的压缩格式。连续完成水位不能跳过任何 pending/Unknown/quarantine，也不是原文已归档的证明。超出近期索引的旧 ID 重试必须返回明确的已退休/需受控查询结果，或查有界外部收据；不能在不知道原哈希时冒充重复成功，更不能再次推进 cursor/重新外写。

### 4.2 正文退休的证明

当前 finalized 只证明现有 Processor 成功走过 lane/finalizer 协议，payload 仅包含段内容哈希，**尚不足以直接实现自动正文 GC**。下一任务须补充一个可核对的 retirement proof，或以稳定 ID 查询既有耐久收据并验证完整字段。

删除唯一 WAL 正文前同时满足：

- Archive、Projection、Search 的确认对应同一 segment ID / content hash；Unknown 结果已经完成 reconcile，不以超时推定成功。
- 外部 finalizer 的耐久收据可核对：来源、epoch、事件覆盖范围/数量、首次 `AcceptedAt`、内容哈希和归档位置一致。归档能重建必要证据；若归档缺少 Segment 的必要 source/header 信息，checkpoint/归档头必须保存这些字段。
- 归档内容、哈希、引用和覆盖范围已经核验，而不是仅收到一次 HTTP/数据库无错响应。该证明与 finalized/checkpoint 的引用关系已持久化。
- 没有隔离、案件引用或其他证据保护职责；未完成段、未知结果和最后一个 pending 段始终保留。
- 新恢复路径不再依赖被删文件：checkpoint、manifest、仍保留的完成索引及读者引用全部验证通过。

只有所有上述条件满足的 closed generation 才能整文件退休；先发布耐久 GC 计划/清单及证据证明，再 unlink，最后同步目录。崩溃后可区分“已授权退休但尚未删完”与“无退休证明却缺文件”，后者必须报错。删除不能推进来源水位或伪造消费完成。

一个 pending 段可以长期钉住混有已完成段的旧文件。第一步可保留整文件，空间按实际被钉住字节计量；需要压缩时只处理有界文件/字节：复制仍承担恢复职责的正文，保留 ID/哈希/首次时间，验证新副本并持久化 relocation/checkpoint/manifest 后，再移除旧引用和旧文件。复制阶段的临时第二份正文有明确恢复用途和结束条件，计入磁盘预算；不能为了压缩而在新副本确认前删除旧副本。

隔离正文不得因普通 finalized/TTL 回收。当前 v2 隔离需要后续补一个受控查看/修复或取消流程；必须记录原因和未处理缺口，不得以移走 manifest、删除 WAL 目录或换新起点解除门禁。

### 4.3 总容量与保留

总预算包含 active/closed WAL、被 pending/隔离钉住的文件、checkpoint/manifest、临时复制文件和必要文件系统余量，同时限制 pending 数量和字节。新 accept 准入时预留其完成所需控制记录和最坏 seal 开销，另有有界重试/隔离及 checkpoint 预算；等待和正在同步的记录也计费。触及新 accept 预算后应明确未接收，不停止健康 writer，让已接收工作继续提交控制记录。逻辑预留不能保证其他进程填满物理磁盘时仍可写，也不能承诺无限重试；真实短写/同步未知错误仍停止并恢复。

cmd 后续必须把停止新 capture 与排空既有 journal 的生命周期分开，或提供明确的停采后排空流程；只增加库内 reserve 而继续在首个容量错误时取消所有 lane，不会获得实际排空能力。若 pinned 证据占满预算，停止新 accept 并明确报告缺口；不能删证据腾空间，也不能用扩大内存队列代替容量方案。

容量模型使用实测事件速率、每段事件数/字节、最长计划 sink 中断和重试写放大：所需空间至少覆盖未归档输入、控制记录、活动文件、checkpoint 和一次有界迁移的峰值。记录实测分布和硬件，不给未经验证的固定倍数容量承诺。镜像流量不可回放部分在背压/停止期间仍可能丢失，应保留捕获、内核丢包、未接受范围与进程中断记录；“已接受不丢”不等同于无限停机仍完整采集。

WAL 是恢复暂存，不是另一个一年原文副本。必要且去重的发现证据及支撑标准事件继续遵守热查 30 天、归档至首次入库后一年；重试/迁移不能重置首次入库时间，案件引用独立保护。确认归档后且不再承担恢复职责的 WAL 原文才退出，不能缩短权威归档期限。

## 5. 启用与回退

先发布能读取新格式但默认仍 v1 的兼容二进制，再在轮转/checkpoint/manifest/GC 验证完成后增加受控可写入口。r39 发现 worker 已包含当前**单文件** WAL 的兼容读取接线，但没有可写 CLI；它不支持未来轮转/checkpoint 格式，不能据此认为现场 r31/r32 或任何旧版本可安全回退。切换前停止旧 producer、等待在途任务结束，验证 source lease、固定起点、隔离段、磁盘预算和所有旧 pending；保留旧 v1 文件作为独立恢复路径。用户授权部署和启用仍按当次任务记录执行。

回退二进制必须实际支持现场已写入的格式。本批单文件 reader 不会自动支持未来新增的轮转/checkpoint 格式；届时仍须先发布对应 reader，再开启该格式的写入，不能把“曾支持某种 WAL”视为永久兼容承诺。

**第一条 WAL accept 之后不能直接回退到旧 r31/r32 二进制。** 旧程序不识别 WAL/manifest，只会从冻结的 legacy cursor 继续写；writer lease 只保护同时运行，`Close` 后不能阻止旧程序再次取得 lease。回退发布必须使用 WAL-aware 二进制，禁止以切 `current` 到旧目录、移走 WAL 或关闭可写选项冒充安全回退。

若确需回到纯 v1，须先停采集并排空所有 WAL/legacy pending，核对无 Unknown/隔离、归档及 finalizer 证明；再由专门迁移工具导出精确的新 legacy cursor、切换审计和 rollback fence。此工具尚未实现。未通过核验时保留 WAL 和恢复兼容二进制，不执行数据退役。

Redpanda 当前 shadow 路径不是上述 WAL 的可靠替代：其发布与失败处理是 best-effort，业务 cursor 未以 broker 耐久确认作为接受边界，尚无完整的 producer Unknown/重放/归档退休协议。若将总线提升为权威，需要单独完成可靠 outbox/producer、持久化与副本策略、稳定分区/业务键、消费缺口及回退验证；不能只把 `Publish` 调用挪到热路径。

## 6. 可实施的下一任务与验收

第一批容量准入/控制空间预留已实现，本地回放验证 Data 拒绝后 Control 排空、排队/在途/held 计费、合组 seal 归还、并发硬限、真实 I/O Unknown、取消/Close 及两类预算调低。WAL 适配器的内存 checkpoint 切面已实现，仍不开放可写 CLI。下一批再做版本化 locator 和轮转/checkpoint 的耐久 manifest，暂不删除任何正文，只证明切代、manifest 提交和跨代读取。完成索引退休与有归档证明的 GC 单独验收后，才可能解除累计 4096 / 总字节持续增长的限制。轮转只是把文件分开，不是增加总容量或取得长期运行能力。

接口边界如下；`AppendWithClass`、`Usage` 及单文件 v1 的 `DurablePosition` / `VerifyPosition` 已实现，其余跨代际能力仍为待实现草案：

```go
// Data 不能使用控制预留；所有 queued/inflight 按最坏独立 seal 计费。
AppendWithClass(ctx context.Context, record Record, class AppendClass) (<-chan Result, error)
Usage() Usage // durable bytes、reserved bytes、Data/Control 可用空间

// 无新增热路径 Sync；在 adapter 独占 mutation 门后取得一致前缀。
DurablePosition() Position // journal/generation、LSN、end、seal proof
VerifyPosition(Position) error
ExportLocator(Receipt) (Locator, error)
ReadLocator(Locator) (Record, error) // 验证格式、文件代际及 frame/seal

// 串行化维护操作，生成 checkpoint、新文件和耐久 manifest；不执行 GC。
RotateCheckpoint(ctx context.Context) (CheckpointInfo, error)

// 由 sink 层提供证明，journal 不自行假设 Acked 等价于归档可恢复。
VerifyRetirement(ctx context.Context, id, contentHash string) (RetirementProof, error)
PlanRetirement(ctx context.Context, verifier RetirementVerifier, budget MaintenanceBudget) (RetirementPlan, error)
```

容量必须在同一个 admission 临界区内按 `durable + queued/inflight reserved + 本次最坏编码` 判定，防止多个 goroutine 一起用掉预留。保守预留每条独立 seal 的空间，group 合并后归还差额。已知未写入的容量拒绝不终止 writer；短写、同步未知和完整性冲突仍终止。区分队列暂满、Data 预算不足、控制预算耗尽与真实 I/O 错误，便于 cmd 正确停采/排空。只读扫描使用格式硬限，写入预算不能反过来禁止读取旧日志。

mutation 门的锁序固定为门 → source/segment/lane 锁 → metadata 锁；`AbortUnsentAttempt` 等内部嵌套调用不能重复取得读门，否则等待中的 checkpoint 写门可能造成死锁。门必须覆盖回执后的 fold；`DurablePosition` 不是独立的“适配器状态已更新”证明。首版 `RotateCheckpoint` 可以持独占门直至新 manifest 确认，避免旧文件在快照后又被追加；测得暂停成本后再考虑后台快照。取消不能把已经开始的文件提交伪装成安全撤回。

`RetirementProof` 至少绑定 ID/content hash、source/epoch/range、首次 `AcceptedAt`、归档位置和可验证收据版本/覆盖范围，并包含案件/隔离保护检查结果。`PlanRetirement` 只输出有界候选、证据和依赖，不自动 unlink；实际执行接口在 GC 中断回放通过后另行实现。未取得 proof、存在最后 pending 或旧 checkpoint/读者仍引用文件时，计划必须排除该文件并解释原因。

| 顺序 | 实施范围 | 完成条件 |
| --- | --- | --- |
| 1（本地实现） | 准入阶段的总字节与控制空间预留，读取配置与写预算分离 | 拒绝新 Data 后 writer 保持健康，控制记录可用预留提交；调低预算仍可读 |
| 2 | 版本化 locator、文件头/seal 链、跨 generation 读取；保留单文件 v1 reader | v1/v2 混合读取，错文件/错代际/缺文件失败；原 receipt 不能误读新代际 |
| 3 | mutation 门、组边界轮转、连续 prefix checkpoint、耐久 manifest | 任意回执调度顺序恢复一致；manifest 锚不倒退；本步不执行正文删除 |
| 4 | 可验证 retirement proof、整文件 GC、读者 pin、控制记录预留预算 | 仅核验归档且不再被任何恢复/证据引用的正文可退休；pending 不被跳过 |
| 5 | 必要时有界 relocation、稳定隔离引用、WAL-aware 发布/回退门禁 | 长期单个 pending 不导致所有后续 finalized 永久占满；压缩崩溃仍有有效正文 |
| 6 | cmd 受控写入入口与现场阶段观察 | 前述本地验证通过且另有启用授权；记录真实吞吐/积压/错误/资源与收益 |

故障注入至少覆盖以下边界，先在本地回放，不在 184 造数压测：

- 每个 frame/seal 字节截断、短写、文件/目录/manifest `Sync` 失败、写成功回执丢失；保留尾部且区分 NotWritten/Unknown。
- WAL 同步后回执前、轮转创建/rename/目录屏障、checkpoint 和 manifest 发布的每个中断点；删至 manifest 最低锚之前、删中间 generation、替换合法但错误 journal 的文件均须失败。另加显式限制用例：删除最低锚之后完整合法 suffix，不能将普通恢复结果宣称为已检测这种外部删尾。
- 后序回执先处理、accept 尚未折叠而 lane 已返回；checkpoint 只能选择连续 prefix，不遗漏任何正文或缺口。
- checkpoint 已同步未发布、发布后 manifest 未确认、GC 计划已确认未删除、部分 unlink、目录同步失败、旧 checkpoint 仍有引用、读者尚在使用旧 generation。
- 三条 lane 独立 Unknown、ack 已落 WAL 但内存未更新、finalizer 已成功但 finalized 未确认、quarantine 与 accept 并发；重启只走正确 reconcile，保留首次时间和全部隔离证据。
- 一个长期 pending/隔离、其余持续 finalized；正文搬迁前后崩溃；归档缺失/哈希不符/覆盖不足；最早和最后 pending 均不能消失。
- 总字节/记录/临时复制/控制预留边界：多个 accept 竞争最后空间、新 Data 被拒但 lane/finalized 可提交、控制预算也耗尽时明确拒绝且仍可读；下调写容量后仍可读取、并发 Close/后台 finalize join、旧二进制启动门禁。

增长验收使用本地可控回放让日志跨过多次轮转与 checkpoint/GC 周期，输入规模必须足以触发真实回收而非只测空文件；包含正常、长尾段、4 MiB 边界、乱序 lane 完成和持久 pending。记录 accept/完整生命周期吞吐、各阶段 P50/P95/P99、每组条数/字节、实际 fsync 次数和时长、CPU/分配、磁盘峰值/净增长、checkpoint/replay 时长、pending 数/字节及 Unknown 数。已完成输入的空间应回到由 active 文件、索引、checkpoint 和 pinned 证据决定的界限，不能随累计 finalized 数无限增长。

当前已完成的本地证明来自 [streamwal 故障测试](../internal/streamwal/wal_test.go)、[passive WAL 回放](../internal/streamlog/passive_wal_test.go) 及 cmd 回放；相关包的 race、vet 和 Linux amd64 构建通过。它们证明当前单文件基础及默认兼容接线，不证明本节尚未实现的轮转/GC，也不证明现场容量或磁盘性能已达标。
