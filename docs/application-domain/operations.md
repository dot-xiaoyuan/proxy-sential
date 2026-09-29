# 应用观测启用与验收

应用模块默认关闭，不影响风险证据、评分及策略。现在可在“规则配置 → 应用域名特征库”保存运行开关与下载地址，即时启停后台扫描，无需重启。配置保存在应用目录的 `config.json`，优先于启动参数；启动参数只决定无配置文件时的默认值。启动默认值示例：

```sh
proxy-sentinel control-plane serve --applications-enabled --applications-dir /opt/proxy-sentinel/data/applications
```

合并到现有启动参数，继续使用原存储、身份认证和前端目录设置。应用目录需使用持久卷；FileStore 将独立分类结果保存在该目录；DBStore 使用 ClickHouse 保存分类结果、PostgreSQL 保存任务与游标，目录保留规则包和运行配置。原始事件仍分别来自影子回放文件及 ClickHouse。数据库改造说明见 [database-processing.md](database-processing.md)。

第一版为单控制面实例实现。目录不能由多个写进程共享。保留最近七天分类结果，分片原子写入并保存游标；每轮后台以稳定游标扫描七天源事件，完成后五分钟再巡检，以收集迟到事件。查询使用内存中的保留观测快照。此实现未经过校园全量吞吐测试，启用前应评估七天事件量与内存；海量部署需后续将分类分片替换为数据库原生聚合存储。页面可见最近完成同步时间和错误，不把未同步状态称为实时。

全局只读模式下可查询已有观测，不启动后台写入任务。导入切换、回滚、重分类继续受只读和 RBAC 控制。

## 采集连接标识

Suricata 适配和实时 ingest 接受 --collector-instance-id，必须对应真实采集器启动实例；采集器重启后换新值，同一实例的各批次保持一致。不得填固定永久值。历史日志混合多个实例时先按实例拆分转换。缺少此信息仍支持域名分类，但连接与流量无法可靠归属，显示不可用。

```sh
proxy-sentinel adapter suricata --sensor-id sensor-a --collector-instance-id suricata-boot-20260908T000000Z --input eve.json --output normalized.jsonl
```

实时 ingest 使用同名参数。shadow run 同样接受该参数，未提供实例时不会猜测连接 ID。当前 Zeek DHCP/software/设备发现事件本身不属于连接流量数据，不生成连接计量。

## 离线包与回放

```sh
go run ./cmd/application-bundle --example-output /tmp/application-contract-fixture.tar.gz
go run ./cmd/application-bundle --verify /tmp/application-contract-fixture.tar.gz
go test ./internal/appdomain ./internal/store ./internal/controlplane ./internal/adapter/suricata ./internal/normalized
go test -race ./internal/appdomain ./internal/adapter/suricata ./internal/normalized
```

样例包是格式/回放测试夹具，覆盖六个应用和生态/共享 CDN 的边界，不是生产审核结果。测试向量见 examples/application-domain/matching-vectors.json。真实人工标注集和准确率仍需现场采集，不能用这些确定性测试代替。

在“规则配置 → 应用域名特征库”导入经审核的生产包，查看版本和规则数。只保留当前及两个有效旧版本。损坏包、未知格式及冲突规则不会切换当前库。

新包不自动重分类已存观测。点击“重分类最近 7 天”后，后台保存进度；过程中不允许改库。重分类中可能同时显示新旧版本，页面给出分布。若进程中断，重启继续；源查询错误自动重试。

在“网络态势 → 应用访问”和 IP 详情“应用访问”验收排行与依据。导出未知域名 JSONL，交 featurelib-new 离线导入分类、审核，再发布新包。

## 上线前现场验收

为微信、企业微信、抖音、B站、QQ、腾讯视频各准备人工确认的正例和易混淆反例；检查共享 CDN、后台请求、DNS 单独命中、QUIC 无 SNI、未知连接、多应用连接。报告正确/错误归属及未知比例、可归属字节比例，不承诺根据域名判断用户打开客户端。

关闭 --applications-enabled 即停止独立模块；保留目录可再次启用。未配置自动上线或生产部署。

## 页面在线拉取

应用包下载地址使用 featurelib-new 的 `/api/features/application-domain/bundles/{version}/download`，例如现有服务基址 `http://192.168.0.30:8081`。先在特征库侧发布审核后的版本，再将该版本的下载地址保存到 Sentinel 页面。它不同于旧版游戏加速器特征下载接口。

点击“拉取并回填”时，可填写特征库 Bearer Token，仅用于本次下载，不保存到配置，也不在错误中回显。下载限制 60 秒、64 MiB，拒绝重定向、URL 内嵌账号和查询参数。内网 HTTP 地址可用，认证信息应通过可信网络传输。校验包格式、来源和文件校验和后原子导入；失败保留原版本，同版本相同包可重复拉取。启用时页面会随后发起最近七天重分类；关闭时仅导入。

新增 POST `/application-library/config` 和 `/application-library/pull`，沿用指纹库更新权限、CSRF、审计和只读限制。配置不会将下载错误或认证失败伪装成已同步。

2026-09-08 现场检查：`192.168.0.30:8081/api/features/application-domain/bundles` 返回 404。服务器运行的 featurelib-backend 镜像尚未提供本地仓库里的新接口，因此不能在该服务上完成真实应用包拉取。需要更新特征库服务并发布有效版本；测试夹具不能替代生产包。

页面运行配置已部署到 Sentinel `2026.09.08-app-runtime1`，原系统启动参数不需要增加 applications-enabled。Go 全量测试、appdomain/controlplane 竞态测试、TypeScript、生产构建、14 项前端单元测试以及三视口截图与 DOM 探针通过。实际生产包拉取因上述上游 404 尚未完成。日志见 `artifacts/device-brand-inference/runtime-*.log`。

## 默认更新服务

新部署及旧空地址配置默认使用 `http://192.168.0.30:8081`，已保存的非空自定义地址保持不变。页面只需修改服务基址。拉取时请求 `/api/features/application-domain/bundles`，按版本名称字典序选取最大版本，再下载该版本并核对包内版本。上游列表未提供发布时间，因此不是按发布时间选择；建议发布方使用固定宽度日期版本号。仍兼容指定完整下载地址来固定版本。版本列表为空、格式错误、下载失败或版本不一致均保留原规则。

## 服务下载凭证（2026-09-09）

featurelib-new 使用 CAS Cookie 管理登录，服务下载不复用用户会话。特征库“离线发布 → 应用包下载凭证”支持创建（默认 90 天）、查看元数据和撤销；密钥仅在创建时显示一次，服务端仅保存 SHA-256 摘要。凭证只允许 GET 应用版本列表与版本包，不能读取候选、修改规则或发布版本。

Sentinel 页面“服务下载凭证”输入后点击保存，存到应用目录独立的 `download-credential.json`（0600），状态仅回传 credential_configured。留空保存保留现有凭证；它绑定服务协议与主机，修改到其他来源后不会自动转发。点击拉取可直接使用已保存凭证。旧版临时 Bearer 登录令牌说明已被此方案替代。上游凭证撤销或到期后，需创建新凭证并在 Sentinel 中替换。

### 2026-09-09 现场结果

两边已部署。Sentinel 运行 `2026.09.09-app-credential1`；featurelib-backend 镜像 `download-credential-20260909`，frontend 为对应 `-r1`。专用凭证名称 `Proxy Sentinel office-30`，有效期至 2026-12-08 08:11:19 UTC，已保存到 Sentinel，两个私密文件均为 0600。

实际凭证请求：应用包列表 200，管理状态接口 401；Sentinel status 的 `credential_configured=true`。实际拉取返回“特征库尚未发布应用规则包”。只读检查治理库备份：候选 0、来源 0、发布版本 0；未擅自审核旧规则或发布测试夹具。没有规则时保持应用扫描关闭，等待有效包后启用回填。

备份目录 `/opt/featurelib-new/releases/20260909-downloadcredential/` 保存原 Compose、镜像引用、认证目录和治理库。原 Sentinel 发布目录保持可恢复。两边后端相关包及竞态测试通过，Sentinel 全量 Go 测试通过；两边前端类型与构建、三视口截图和 DOM 探针通过，featurelib 改动 TSX 的 ESLint 通过。现场状态记录在 `artifacts/device-brand-inference/credential-final-status.txt`，不含密钥。

### 2026-09-09 pilot1 联调

已下载并启用正式发布包 `2026.09.09-pilot1`（61 条规则）。发现来源约定允许 confidence=0 表示未量化评分，修正 Sentinel 对 0 的错误拒绝，页面显示“未评估”而非抬高分数；负值仍拒绝。程序已更新为 `2026.09.09-app-pilot1`，相关 Go/竞态测试及三视口页面测试通过。

七天回填于 2026-09-09 08:45:53 UTC 开始。初次确认游标已推进 1,000 条，持久观测中出现 14 条钉钉应用命中；回填尚在运行，该计数不是最终结果或准确率。默认 24 小时列表可能要等游标处理到近期数据后才显示历史结果。
