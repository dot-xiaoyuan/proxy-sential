# 应用统计数据库处理

2026-09-14。该改造适用于 Sentinel 的应用相关服务访问统计，不改变风险评分、设备配额或代理处罚。

## 数据与启动

DBStore 自动使用数据库应用后端。ClickHouse 的 `application_observations` 保存独立分类结果，PostgreSQL 的 `application_processing_jobs`、`application_processing_batches` 保存三个任务通道和可重放批次。原始标准事件保持不变。

部署前使用现有 `proxy-sentinel migrate` 命令执行增量迁移：PostgreSQL `020_application_processing.sql`、`021_application_batch_retention.sql` 与 ClickHouse `005_application_observations.sql`。DSN 沿用 `PROXY_SENTINEL_POSTGRES_DSN`、`PROXY_SENTINEL_CLICKHOUSE_DSN` 环境变量。本文不表示已执行生产迁移或部署。

数据库模式不读取或修改旧 `observations/*.json` 与 `state.json`，不导入这些历史分类文件。规则包和运行配置继续存储在应用目录中，旧文件保留。启动不载入七天分类明细；缺少数据库表时报告错误，不静默退回文件模式。多个进程连接同一任务库时，应挂载一致的规则目录和配置。

冷启动的实时通道先处理最近两分钟，较早的七天事件由低优先级补扫处理。已有实时游标从上轮结束时间继续。历史手动重分类固定开始时的七天范围与规则版本；实际已经读到的范围通过 `available_from`、`available_to` 展示，不把缺失的原始事件假称已经回填。结果默认保留七天，查询显式排除过期数据；物理回收由 ClickHouse TTL 后台完成。

## 批次与恢复

1. 通道领取 PostgreSQL 租约，默认 90 秒；一次处理上下文限制 60 秒。
2. 源事件先分页选择时间、传感器、事件 ID，再读取该页原始字段，每页最多 1,000 条。时间比较保留纳秒精度，避免微秒游标被截断导致重复读取。
3. PostgreSQL 登记批次 ID、完整分类内容、下一游标和计数。普通扫描仅补充未分类事件，已分类事件不会随每次补扫重复追加。
4. ClickHouse 同步写入成功后，事务提交 PostgreSQL 游标及批次完成状态。已提交批次释放正文，保留七天诊断元数据。
5. 写入结果不确定、数据库中断或进程重启时，复用原批次内容和身份。租约失效的工作者不能提交游标；过期租约允许重新领取。

分类修订号高者生效，同修订号以原始批次优先；普通扫描使用基础修订，不能覆盖历史重分类。查询显式按事件身份去重，不等待 ClickHouse 合并。重分类按批次逐步生效；暂停、取消保留已经提交的结果，版本分布反映实际处理结果。

## 调度与操作

实时与后台使用独立循环，进程内最多一个实时批次、一个后台批次。后台轮流执行历史重分类和迟到事件补扫；跨进程通过租约和后台准入锁限制并发。实时有未完成批次或错误时，后台让出新的批次准入。已经在途的后台批次允许完成。

实时有后续页面时间隔 100 毫秒，空闲轮询间隔两秒；后台批次默认间隔一秒。`POST /application-library/config` 新增可选 `history_interval_ms`，范围 1,000—60,000；省略时保留配置。数据库错误退避 30 秒。补扫一轮结束后按五分钟窗口安排下一轮，不启动并发补扫。

现有任务控制接口继续使用：

- `POST /application-library/reclassify`：创建固定范围的历史重分类。
- `POST /application-library/jobs/pause`、`resume`、`cancel`：请求暂停、恢复或取消。
- `GET /application-library`：查看请求状态和实际执行状态。

`requested_control` 非空表示请求已保存、正在等待当前批次提交。待重放批次不会被静默丢弃；数据库未恢复或功能关闭时，请求可能仍处于等待状态。恢复处理后提交该批次，再执行控制请求。未完成或暂停的历史任务会阻止替换其规则包。

## 查询与接口

应用排行、连接及终端统计、未知和多应用桶、版本分布由 ClickHouse 聚合。关联终端按园区内 IP 去重；DNS 只计观测；缺失字节返回 null。累计流量依据仍为“窗口内有观测连接的累计字节”，连接证据可来自保留期内窗口前的记录，禁止读取窗口结束后的计量。应用筛选在多应用连接判定之后执行。

明细接口增加 `cursor` 和响应字段 `next_cursor`，保留 `items`、`total`、`limit`、`offset`。游标不能与非零 offset 混用。前端翻页固定查询结束时间；旧 offset 客户端仍可使用。明细先选事件键再读取证据正文，避免完整正文参与全量排序。

未知域名按原 JSONL 契约分页聚合、逐页输出，每页最多 1,000 项；不导出账号、IP 或完整 URL。开始输出前失败返回 503；中途失败终止响应，避免将不完整下载显示为成功。

`processing` 新增实时、历史、补扫任务状态、最近成功时间、批次耗时、重试次数、游标时间差及最近统计查询耗时。数据库模式 `retained_observations_known=false`，不把默认的 0 当作实际保留条数。

`/metrics` 增加 `proxy_sentinel_application_` 前缀的任务已处理数、批次耗时、任务重试、失败状态、待生效控制、游标年龄、最近成功时间和查询耗时。游标年龄不是精确积压，也可能因没有新流量而增大。没有游标时不导出零延迟指标。

每个服务进程最多并发两个交互式数据库查询，使用独立于处理任务的准入预算。每条统计查询最多两个线程、512 MiB 查询内存，聚合允许落盘；源扫描最多一个线程、256 MiB，键聚合和排序允许落盘。上述是数据库查询资源预算，与 Go 进程内存指标分开记录。

## 验证与复现

共同回放文件为 `internal/appdomain/testdata/accounting.json`，验证重复、窗口前连接、未来字节隔离、DNS、多应用、缺失连接、缺失计量、基础设施以及筛选语义。数据库测试把时间平移至当前保留窗口。

仅对专用本地测试库设置以下环境变量，执行相关集成测试：

```sh
export PROXY_SENTINEL_TEST_POSTGRES_DSN='<专用 PostgreSQL 测试库 DSN>'
export PROXY_SENTINEL_TEST_CLICKHOUSE_DSN='<专用 ClickHouse 测试库 HTTP DSN>'
go test -race ./internal/store -run TestApplicationDatabase -count=1
PROXY_SENTINEL_APP_CAPACITY=100000 go test ./internal/store -run TestApplicationDatabaseEndToEndCapacity -count=1 -v -timeout 30m
PROXY_SENTINEL_APP_CAPACITY=1000000 go test ./internal/store -run TestApplicationDatabaseEndToEndCapacity -count=1 -v -timeout 30m
```

容量测试要求空的应用任务表，生成专用传感器数据并在结束时清理。它覆盖真实标准事件读取、分类、跨库提交和统计查询，手动连续推进批次以测量处理能力，不包含默认后台限速等待。测试报告同时记录 Go 峰值堆、回收后存活堆、查询延迟和历史处理期间的实时探针延迟；不能将其替代现场吞吐或端到端采集精度验收。

本地日志放在 `artifacts/application-database/`。页面使用 MSW 演示数据，截图和 DOM 探针覆盖 390×844、1280×800、1440×900；结果不代表真实校园数据。

现场仍需验证实际采集速率与积压消化能力、磁盘 TTL 回收、数据库资源预算及配置的历史限速。功能可以通过原独立开关关闭，不改变防代理处理。

完整本地验收结果见 [2026-09-14 验收记录](verification-database-20260914.md)。
