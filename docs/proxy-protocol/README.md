# HTTP CONNECT / SOCKS5 代理事务识别

首版识别成功代理连接，并关联事件发生时的认证账号。协议识别与是否违规分开；只支持仅观测与人工确认，不开放自动处罚，不涉及 VPN 检测规则或应用统计 ClickHouse 改造。

## 数据流及判定

1. Suricata 保留原 HTTP 标准事件，同时为 CONNECT 生成 `type=proxy_transaction` 的派生标准事件。使用同一 EVE 事务内的 method、status、tx_id，2xx 为成功，最终非2xx为失败。缺少连接或事务 ID、不存在最终响应时为不完整。
2. Zeek `assets/zeek/proxy-transactions.zeek` 使用解析器 HTTP 和 SOCKS 事件输出 `proxy_transactions.log`。HTTP 使用解析器事务深度关联，只有请求头先完整、最终响应头随后完整才确认结果；状态行、截断头部及解析器在 EOF 补发的头部事件保留为不完整。SOCKS5 只确认 CONNECT 命令（1）的成功应答（0）。认证协商、SOCKS4、BIND 和 UDP 不算此类成功证据。同连接出现重复 SOCKS 请求时不冒险关联响应。
3. 请求先输出不完整记录，响应到来后输出完整记录。消费侧按传感器、来源、采集实例、连接、事务、协议组成稳定证据 ID；只替换整个完整事务，不拼接两条残缺记录的字段。相互矛盾的可信记录变成冲突，禁止用于处置。
4. 异步处理器每批最多读取 1000 条代理事务，独立保存结果。数据库模式下，结果与扫描游标在 PostgreSQL 同一事务提交；开发文件模式结果原子写入后推进游标，失败批次可重复处理。定期重新扫描最近七天以接收迟到记录。
5. 按请求时间、园区、接入域及 IP 重新查询身份；过期或冲突保持未知。Suricata 普通 EVE HTTP 记录没有可靠的请求时间，因此可确认协议成功，但不会凭日志时间归责账号；需要账号处置时使用 Zeek 事务记录提供准确请求时间。

`proxy-transactions/v2` 对完整事务要求连接 ID、事务 ID、请求时间、响应时间和观测时间齐全且顺序一致；登记的原生 Suricata HTTP 解析器仍允许同一 EVE 最终响应记录在不填写请求、响应时间的情况下提供协议观测结果，并明确提示不能归责账号。其他来源不能借用此例外；提供了畸形时间也不能当作时间省略。策略输入要求完整时序，拒绝晚于当前时间的响应或观测。结果读取、写入、合并和策略复核共同校验这一条件：旧的不完整成功记录显示为不完整、置信度为零，读取保留原始审计文档，后续完整记录可纠正派生结果并保留原事件编号。

结果包含 `success`、`failed`、`incomplete`、`unsupported`、`conflict` 五种状态；`trusted` 与结果分开。未通过来源校验的成功记录只是线索。证据不进入原有风险评分，返回的通用 evidence `score` 为 0，避免间接触发原有自动处罚。

## 受控来源配置

样例：`examples/proxy-protocol/producers.example.json`。样例密钥仅用于回放，实际使用必须替换随机密钥，并限制配置文件读取权限。采集适配进程与控制面使用对应登记配置。

登记项固定绑定 `sensor_id`、`source`、`instance_id`、`parser_id`、`parser_version`、`campus_id`、`access_domain` 和不少于32字节的密钥。`instance_id` 必须在采集器重启后变化；需要识别旧记录时保留旧实例登记。配置变更产生新的配置指纹并触发重新校验，旧配置结果不会继续用于处罚。

适配器用配置中的密钥对规范化代理事件签名，控制面验证签名、来源与版本。原始数据里的 `verified` 不参与判断，事件不能自行授予可信身份。日志文件目录也必须由受控采集器写入；签名证明经过登记适配器，不证明人为导入的原始日志真实。

签名和验签均要求整个规范化签名文档成功编码为 JSON；编码失败时不对空内容签名，也不授予可信来源或账号归属。失败的重签会清除旧签名，适配器返回错误而不输出未签名的派生事务。正常事件的签名格式保持一致，经过 JSON 保存再读取仍可校验。此保护覆盖进程内畸形数据，不表示现场已发生此类错误或已完成真实代理流量验收。

命令示例（本地离线回放）：

```bash
zeek -C -r capture.pcap assets/zeek/proxy-transactions.zeek LogAscii::use_json=T

go run ./cmd/proxy-sentinel adapter zeek \
  --log-kind proxy --sensor-id replay --collector-instance-id replay-boot \
  --proxy-protocol-config examples/proxy-protocol/producers.example.json \
  --input proxy_transactions.log --output normalized-proxy.jsonl
```

Suricata 适配命令同样新增 `--proxy-protocol-config`，HTTP 需要开启 EVE extended logging。实时 ingest 新增 `--zeek-proxy <日志路径>`，与 `--collector-instance-id`、`--proxy-protocol-config` 一起使用；控制面 serve 增加同名配置文件参数。未配置控制面来源登记时不启动代理证据物化。

生产数据库需要按项目既有流程应用 `019_proxy_protocol.sql`。v2 沿用现有表结构，无需新增迁移；升级程序会校验已应用迁移的内容。部署包的 assets/zeek 复制流程包含事务解析脚本。

## 标准事件与接口

新增标准事件类型 `proxy_transaction`，复用 Event 的 observer、subject、flow 和 raw_ref。payload 包含：

- 公共：protocol、transaction_id、request_at、response_at；时间缺失就不填写。
- HTTP CONNECT：method、status。
- SOCKS：version、command、reply。
- `flow.connection_id` 使用现有标准连接 ID；`observer` 包含 sensor_id、collector_instance_id、parser_id、parser_version、proxy_signature。

不采集 SOCKS 用户名、密码或认证内容。派生事件不会修改已存储的原始标准事件。

沿用现有 API：

- `/events/{id}` 返回原始事件字段并附加独立的 `proxy_protocol` 识别结果。
- `/ips/{ip}/evidence` 混合返回代理事务证据和已有证据，代理证据包含 `proxy_protocol` 字段。
- `/policies/{id}/simulate` 的明确代理评估附加 `proxy_evidence`。
- `/policy-executions` 为执行记录附加可查看的协议依据；`approve` 使用 `policies:authorize`，撤销沿用 `actions:revoke`。

配置 `explicit_proxy` 策略时，自动模式在后端验证中被拒绝。即使绕过配置校验导入了自动策略，策略输入和动作执行端仍阻止执行。人工确认记录当前证据 ID 集合；发送前再次检查证据时效、事件时刻归责、当前账号会话、策略优先级和豁免。证据集合变化要求重新确认，不能把审批复用到新证据。既有影子准入、全局停止、控制器能力声明、重试和撤销保持生效。

## 验证与限制

执行 `scripts/proxy-protocol/replay.sh` 可本地生成 TCP PCAP、通过真实 Zeek 解析，再运行适配和策略沙箱测试；不会向外部网络发送数据包。需要 Python3、Zeek、Go。

本次验证：

- Zeek 8.2.0 解析实际生成的 PCAP：14条日志合并为8个事务，2成功、3失败、2不完整、1不支持；普通 HTTP 与仅认证协商未算作成功事务。
- Go 测试包含伪造签名、内容篡改、事务边界、迟到补正、身份换绑/冲突、证据过期、文件结果重启恢复、FileStore/ClickHouse HTTP 模拟源一致性、手工确认及自动模式阻止。
- 内置 HTTP 控制器沙箱验证人工确认后发送及重复执行去重；现有账号动作测试覆盖部分失败与解除。
- `go test ./...`、相关包 `go test -race`、前端类型检查和生产构建通过。
- Playwright 完成390×844、1280×800、1440×900的事件证据、执行记录及表单检查，6项用例通过；截图和 DOM 探针位于 `frontend/test-results/proxy-protocol/`。

没有执行真实流量观测、真实控制器或实际 PostgreSQL/ClickHouse 服务器的联合验收；数据库源测试使用 HTTP 沙箱，不能替代真实数据库部署验证。源配置假定同一登记传感器的流量属于其登记园区/接入域，不能将跨园区镜像任意归入一个园区。一次策略评估最多处理一万条近七天证据，超出时返回不可用并停止据此判断，不能静默截断后继续处罚。

五分钟以上未关联响应的 Zeek 请求保持不完整；加密代理握手、SOCKS4、UDP ASSOCIATE、WireGuard/OpenVPN 不属于本次成功识别范围。

## 受控现场采集与实例轮换

管理式部署可在 `config/proxy-source-scope.json` 登记实际镜像口所属的传感器、园区、接入域及启用来源，格式见 `examples/proxy-protocol/source-scope.example.json`。必须来自现场受控配置，不从私网 IP、报文字段或推测名称推导。跨园区镜像须先拆分采集归属，不能用该配置统一归责。

`proxy-sentinel-proxy-source-refresh.timer` 检查 Suricata 与 Zeek 各自的 systemd InvocationID；采集器重启或受控归属变更后，生成新实例登记和随机密钥，原子写入仅 root 可读的 `proxy-producers.json` 与 `proxy-source.env`，然后重启 ingest 与控制面。重复检查不重启服务。关闭来源会封闭旧实例有效区间；保留八天旧登记以校验迟到证据。

登记可带 `valid_from`、`valid_until`。事件时间、请求时间、响应时间均须落在来源区间内；即使旧日志由新适配实例签名，仍不会得到可信园区或接入域。ingest 的 `--zeek-collector-instance-id` 独立于 Suricata 实例；省略时保留原单实例兼容行为。管理式配置通过 EnvironmentFile 提供路径和实例，禁止用旧的固定实例命令参数覆盖。

Zeek 需加载 `assets/zeek/proxy-transactions.zeek`，安装器已纳入服务启动命令。此部署不改变明确代理策略仅支持影子和人工确认的限制。真实流量没有成功代理事务时，页面为空是有效结果；离线 PCAP 正例不能写入业务库或冒充现场违规。

## SOCKS TCP 分段修复与 30 上的隔离验收

30 上的 Zeek 8.0.9 原生 SOCKS BinPAC 解析器将每次 `DeliverStream` 当作完整消息处理。真实 CONNECT 请求分成两个 TCP 数据段时会发生 `out_of_bound: SOCKS5_Address:ipv4`，即使握手签名匹配且实际转发成功，也不输出交易。原先将整条请求放在一个数据段的回放不能覆盖此问题。

`collectors/zeek/socks-stream` 在原生解析器前增加有界消息分帧：每方向最多缓存 1024 字节握手，按协议长度逐条交给原生解析器，连接建立后的业务数据直接转发、不缓存。完整协商、受支持认证成功、请求与完整应答仍分别验证；有缺口、畸形字段、未提供的认证方法和失败认证停止解析。SOCKS4 保留原有“不支持”结果，SOCKS5 只将 CONNECT 命令及成功应答确认为成功。风险引擎继续只消费签名后的标准交易事件。原生 SOCKS 诊断日志排除用户名、密码字段。

原生扩展必须针对目标 Zeek 编译，使用当前目标程序的 SHA256、版本和架构固定绑定；发布包同时保留扩展源码、原生包和逐文件校验。`scripts/deploy/activate-zeek-socks-stream.py --release /opt/proxy-sentinel/current` 仅预检，加 `--activate` 才启用。启用时只增加专用 Zeek 环境配置，重启 Zeek 并执行现有来源实例轮换；失败会删除本次配置、恢复采集与来源登记。已有非受控插件路径或配置会停止，避免覆盖其他扩展。对本工具登记并逐文件校验通过的扩展，支持原子升级；同版本重复启用会核验正在加载的动态库而不重启。应用升级与采集扩展启用共用发布锁。此扩展依赖目标已安装的 Zeek，不能把 30 编译的原生包直接用于不同 Zeek 程序。

2026-10-02 在 30 的私有 loopback 测试目录，18 个真实套接字场景验证了 6 次实际转发；32 个生成回放验证逐字节分段、IPv4/IPv6、255 字节域名、认证、SOCKS4、错误字段、普通 HTTP/TLS 和不完整响应。日志经实际适配器签名、JSON 往返和事务合并后逐场景核验。测试地址和端口只属于临时自建服务，抓包不读取业务镜像口，测试事件不写入业务数据库，也不关联真实账号。此项证明采集链对受控代理流量的行为，不能替代校园真实代理、真实账号断网/恢复或长期误判率验收。

SOCKSStream 1.1.0 进一步校验每个握手阶段的方向与顺序。原 1.0.0 会缓存提前的应答或请求，在后续阶段重新递送并赋予较晚的解析时间，造成异常交互被误认为成功交易。现在提前应答、认证未成功即发请求、请求未完整即应答会停止确认；请求后但成功应答前出现业务数据时，已输出的请求保留为不完整。完整成功应答与后续业务数据同一 TCP 数据段仍允许。抓包乱序或缺口造成的时序不足同样不提供成功证据，不能把这种保守结果解释为终端没有代理行为。

时序修复验证覆盖 41 个生成回放和 22 个真实 loopback 场景，包含正常逐字节分段、完整应答后的数据合并，以及提前应答/提前请求等异常序列。发布工具用同一安装锁保护扩展升级，完整文件落盘后才切换 systemd 配置；采集恢复失败时恢复上一份受控配置并刷新来源实例。配置原子写入失败、首次启用失败、升级恢复失败与外部配置变化均有隔离故障测试。现场验证不会为测试故意中断正常业务或启用真实处罚。

### CONNECT 头部完整性

Zeek 8.0.9 的 `http_reply` 在状态行到达时触发，`http_all_headers` 也可能由 MIME 解析器在连接结束时补发，因此两者单独均不足以证明握手完整。采集脚本保留请求头完成状态，在最终响应状态行到达时快照请求是否已完成，再在顶层响应头事件后排队确认；已排队的“entity body missing”诊断会阻止补发事件产生成功证据。连接内状态随连接释放，待处理事务另有五分钟过期限制。嵌套 MIME 头部不作为新的代理响应头。

最终 2xx 都支持成功判定，100 等临时响应继续等待最终响应。按 [RFC 9110 CONNECT 语义](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect)，确认完整 2xx 响应头后无需等待隧道关闭或响应体；响应携带的 Content-Length、Transfer-Encoding 不决定隧道边界。完整拒绝响应头之后正文截断仍属于拒绝，完整成功握手后连接重置也不撤销已经发生的成功。

`scripts/proxy-protocol/make-http-boundary-replay.py` 覆盖 36 个头部、时序、逐字节分段、重传、缺口、重置、临时响应合并与重试场景。真实 loopback 验收扩展到 30 个场景、9 次实际转发，额外验证截断请求/响应、重置以及 201、204 和带长度头的成功隧道。所有用例仍经签名标准事件和事务合并核验，均不写业务数据库。

### CONNECT 状态容量与过期

每条连接最多保留 100 条待响应 CONNECT 事务；原生 `HTTP::max_pending_requests` 配置为更小的正数时，采用该更小值。原生限额设为 0 也不会取消本系统的 100 条限制。达到容量后再出现请求，清空关联状态、停止为该连接确认完整事务，并写入 `Sentinel_CONNECT_pending_limit` 解析诊断；先前请求已经输出的不完整标准事件保留。原生 HTTP 因过量流水线请求清空队列时，也停止该连接的事务确认，避免在事务深度重新匹配后拼接错误的成功证据。新连接独立判断，连续完成的事务释放容量，不累计到连接总请求次数中。

五分钟过期属性必须放在创建表值的局部声明上，只有类型别名上的属性不会配置实际 `table()` 对象。成功确认另行检查请求到完整响应头的真实时间跨度，防止过期扫描延迟让旧事务成为成功证据。到期删除只影响待处理关联状态，不删除已输出的原始请求事件。

`make-http-load-replay.py` 与 `check-http-state.zeek`、`check-http-load-state.py` 在私有回放中验证状态峰值、响应前的残留数量、连接结束状态和逐事务结果。覆盖 99/100/101 条边界、500/5,000 条突发、300 次连续拒绝、普通 HTTP 混合队列、299 秒正常响应和 360 秒过期响应；另在原生限额 10、原生限额关闭和过期扫描延迟到十分钟的配置下验证。真实套接字验收增加到 31 个场景，其中 101 条请求后伪造成功应答不会产生成功事务，9 次正常代理转发仍成功。

### NUL 头部与 SOCKS 应答窗口

SOCKSStream 1.2.0 为已经观测到 CONNECT 的原生 HTTP 分析器增加 TCP 辅助分析器。它观察原生重组后的头部行，只保留阶段标志，不缓存头部、认证内容或隧道数据。Zeek MIME 解析器会把以 NUL 开头的非空行当作头部结束，因此采集端在解析器处理该行前检测 NUL，产生一次 `Sentinel_HTTP_invalid_header` 诊断并停止该连接的完整事务确认；请求目标中的 NUL 也在原生请求事件排队时检查。异常头部保留已经输出的不完整请求，异常目标不生成事务请求。正文和完整成功握手后的二进制数据不作为头部检查。此保护覆盖已验证的 NUL 边界，并不声明完成所有 HTTP 语法校验。

SOCKS 最终应答也独立检查五分钟请求到应答窗口，不依赖定时过期扫描及时执行。299 秒以内的完整正常应答仍确认，360 秒应答保留为不完整，不把超时拒绝应答补成完整失败记录。

`make-parser-boundary-replay.py` 的 19 个私有回放覆盖请求/响应头部 NUL、请求目标 NUL、整段与逐字节分片、正常二进制正文/隧道及延迟 SOCKS 应答。旧版本在其中 12 个异常场景得到错误完整结果，修复后全部符合逐事务预期。真实 loopback 验收扩展到 37 个场景、10 次实际隧道转发，包含 NUL 头部负例与带 NUL 的正常隧道正文；测试事件不进入生产数据库。TCP 辅助分析器使用 TCP 专用生命周期接口，既有 FIN、RST、头部截断和队列回放同时回归。

### HTTP 首行完整标记

Zeek 8.0.9 会把版本号的前三个字符解析成版本，也会把状态码的前三个字符解析成状态，因此 `HTTP/1.1junk`、`HTTP/1.10`、`2000` 和 `200junk` 可能留下成功值。采集脚本在原生请求事件之前处理 `bad_HTTP_version` 与 `crud after HTTP version is ignored` 诊断，停止异常连接的完整事务确认。SOCKSStream 1.3.0 的 TCP 辅助分析器在解析器处理响应首行前核验版本和三位状态码的完整标记边界，不保留该行内容；异常响应保留为不完整请求。

版本标记采用原生解析器的一位主版本、一位次版本格式；状态码之后只能结束或进入空格/制表符分隔。正常 HTTP/1.0、HTTP/1.1、空原因短语、制表符分隔、请求尾部空格、原因短语中的数字及原生解析器允许的大小写前缀仍保留原有结果。此项针对已证实的标记截断问题，不代替全部 HTTP 语法与代理转发行为验收。

`make-http-start-line-replay.py` 包含 28 个整段/逐字节回放，修复前 20 个异常首行产生错误完整结果，修复后逐事务预期全部通过。另回归之前 136 个头部、控制字节、SOCKS 和四种队列配置回放。真实 loopback 扩展到 50 个场景、13 次实际隧道转发，包含异常版本/状态码负例及正常 HTTP/1.0、空原因短语和制表符分隔的真实转发。
