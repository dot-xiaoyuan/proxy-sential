# 开发阶段止损执行记录（2026-09-16）

## 已实际执行

- 现场 192.168.0.30 根分区清理前使用率 94%。清理 541 份超过一天的 shadow/runs/*/normalized.jsonl，共计逻辑大小 32,373,192,134 字节；保留 evidence、risk、summary 文件及数据库标准事件。清理后文件系统使用率 79%，可用 47,871,279,104 字节。逻辑删除大小不等于文件系统释放大小。
- 安装每小时开发副本清理 timer，仅清理上述超过一天的可重建原始副本，不删除其他文件。
- 增加 PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED=true 部署开关，拦截 history/reconcile 调度、创建重分类及恢复历史任务；实时 lane 保留。
- 现场控制面使用独立 /opt/proxy-sentinel/config/proxy-sentinel-dev-p0 二进制及 systemd drop-in，原 release 和其他采集进程不替换。已重启两次，健康检查通过。相关 appdomain race、controlplane 和 deployment 测试通过。
- 历史 reconcile 持久化标记 cancelled，processed 固定 18,204,242；重启后实时 last_success 继续前进。现场原先没有 history lane 任务。

## 正在观测，尚未验收

03:28:38 UTC 启动 proxy-sentinel-development-space-observation.service，每分钟采样，共 61 次；输出 /opt/proxy-sentinel/data/development-space-observation.log。首样可用空间 47,674,691,584 字节，设备快照表物理大小 67,125,927,936 字节。必须检查完整日志才能判定一小时增长是否受控，不能把采样任务启动当作完成。

设备快照仍采用已有七天保护性保留，Docker 现有容器日志轮转尚未应用，数据库聚合页面查询仍需核验。当前未进入人工处置扩展阶段。

本地原始输出见 artifacts/shared-access-p0/development-space-recovery.txt 和 development-history-disabled.txt。未清理其他项目旧 Elasticsearch 日志，未执行 VACUUM FULL，也未删除账号、凭据或审计。

## 第二批空间回收与日志限制（03:32 UTC）

- 发现 ClickHouse system 库的 text/query/trace/processors 等诊断日志占约 23GiB。关闭这些开发阶段不必要的详细日志，并 truncate 已明确枚举的 system 诊断表；未动 proxy_sentinel 的业务证据和审计。
- 根分区使用率进一步降至 67%，03:31 采样可用 74,617,954,304 字节。
- PostgreSQL、ClickHouse 容器已按原镜像 ID、原数据挂载、原账号环境及原端口逐一重建，应用 json-file max-size=20m/max-file=5。inspect 已验证实际生效。ClickHouse 开发日志配置以只读 bind mount 持久化，文件日志 warning 级别、20M/5 份。
- 采集及风险物化服务 active；ClickHouse 查询最近五分钟标准事件 23,890 条；实时 last_success 在数据库重建后继续推进。
- 一小时观测尚未结束，03:32 观测服务仍 active。完整稳定时段须涵盖最后一次容器调整之后，不能把之前短时样本算作最终验收。

## 页面查询核验（03:37 UTC）

通过现场已有管理员浏览器会话只读访问：防代理策略页正常显示“尚未配置防代理策略”和空执行记录；风险处置页完成查询，显示 45 条案件，与数据库计数一致。未创建策略、未修改案件、未执行动作。此前未登录 curl 的 401 不作为业务查询成功依据。

## 磁盘阶段验收通过（04:34 UTC）

最后一次容器调整后的有效窗口为 03:33:39—04:34:05 UTC，61 次采样，3626 秒。磁盘使用率始终为 67%，可用空间从 74,906,505,216 降至 74,526,011,392 字节，净增长 380,493,824 字节（约 0.38GB/小时，仅代表此窗口，不外推长期增长）。设备快照表物理增长 327,680 字节。

全部健康响应 alive；实时 last_success 的采样最大延迟 4.10916 秒；reconcile 始终 cancelled，处理数量恒为 18,204,242。策略及案件页面查询已通过。原采样和补采服务均 Result=success、inactive，已结束，无需再持续轮询。

原始日志：artifacts/shared-access-p0/development-space-observation.log；统计：development-space-acceptance.json。阶段 1、2 通过，允许进入指定测试账号人工处置闭环；不代表长期容量测试或真实共享识别准确率通过。

## 阶段 3 本地进展（未作现场完成声明）

已开放 shared_access 的人工确认输入与下线动作生成，自动模式仍拒绝、无策略授权的共享证据直接动作仍拒绝。确认请求在全局操作锁外读取共享窗口，确认时核对当前证据集合与身份，发送前再次校验；复用已有会话指纹、幂等阶段、影子准入及审计撤销。

新增人工确认回放覆盖新鲜/过期/变化证据、身份缺失、自动模式、同账号两个会话、重复确认与发送前证据失效。相关 sharedaccess、policy、controlplane 竞态测试通过，结果在 artifacts/shared-access-srunapi/shared-manual-tests.txt。未修改前端；OpenAPI 补充人工共享下线约束说明。

当前改动未部署到 .30；190 全链路验收尚待完成，不能使用此前原生 API 直接测试代替。下一步在已有本地 28080 测试控制面与 190 认证环境联调，不新增其他处置能力。

## 190 只读实接及已授权测试例外

用户明确批准仅在本地测试控制面、仅对 190 的 yuantong 人工下线的测试例外，生产七天影子准入不变。private native 配置新增 test_account；服务监听必须是显式回环地址。例外只支持匹配账号/接入域的 shared_access 人工 disconnect，不把 ShadowReady 改为 true。连接器审计标注 active_scoped_test_exception。

本地 28080 已加载最新代码和私有配置。190 新版身份采集通过 SSH 回环转发持续提供全量清单，81 会话/161 地址记录。本地管理用户 lab-admin 登录成功；原生连接器 srun-radius-lab 已登记，mode=active、shadow_ready=false。凭据仅存在 /tmp/sentinel-auth190-lab/native.json（0600），不进入仓库。

发现来源时钟快约 59ms。原生清单读取对最多 250ms 的正偏差等待本机追上，不放宽消费者未来时间判断；超过界限或上下文取消仍拒绝。相关回放和竞态通过。

05:26 UTC 通过 Sentinel 现有连接器测试入口读取正式 API 与权威清单：reachable=true、online_total=81、inventory_records=81、read_only=true。结果存于 artifacts/shared-access-srunapi/manual-field-readonly-probe.json。尚未发送真实下线；下一步测试账号登录、标准共享回放进入证据、预览确认、发送和重新登录恢复。

当前运行：本地控制面 exec 52508；SSH 主连接 exec 63308、ControlPath=/tmp/sentinel-190-control（Redis 本地26381→190:16380；反向190:28081→本地28080）；身份采集 exec 11663。结束现场验收后需清理这些临时进程、转发及私有临时文件。


## 最终验收与收尾（2026-09-16）

本轮收缩目标已完成。后续认证联调全部通过接口，Portal 的重定向和页面行为不属于 Sentinel 的交付范围。

### 磁盘及持续处理

- 开发主机磁盘由约 94% 降至 67%，最终可用空间约 74.5 GB。
- 03:33:39—04:34:05 UTC 共 61 次采样，持续 3626 秒；使用率最高 67%，净增长 380,493,824 字节。该值仅代表此观察窗口，不外推长期增长。
- 实时处理最近成功时间的最大延迟为 4.11 秒；历史 reconcile 始终 cancelled，处理数保持不变。重启后不会重建历史任务。
- 开发诊断日志和影子副本已限量；保留业务证据、审计、配置及凭据。快照约 67 GB 的既有占用未整表重写，七天受保护保留继续生效。
- 验收原始数据见 artifacts/shared-access-p0/development-space-acceptance.json。

### Sentinel 人工处置链路

- 合成共享事件经过标准事件存储、共享证据聚合和事件时间身份归属，关联 190 的指定账号 yuantong。未知设备数量继续显示未知，不借此认定超配额。
- 通过 Sentinel 策略人工确认接口创建动作 policy-action-0bf26b9171226154d2190aa635eca0e5，原生执行器对实际会话 209 下线。
- 动作 succeeded、retry_count=0；原生观察记录同时确认 acknowledged 和 absent，不以请求提交冒充下线成功。
- 重复确认返回 409，没有创建第二条动作；违规轮次已人工撤销并设置冷却。
- 重新认证后，身份快照接口确认新的在线会话，原会话为 stop；之后动作列表仍只有上述一条下线动作。恢复是重新认证，不是恢复旧连接。
- 用户明确批准的例外只用于回环监听的本地测试控制面、指定连接器/账号/园区/接入域、人工共享下线；没有修改 .30 的影子准入，也未开启自动处罚。
- 测试结束已禁用策略和连接器、停止临时控制面及身份采集进程、关闭 SSH 转发、删除私有测试例外配置与临时登录票据。新认证会话保留在线。

### 验证范围

- go test -race：sharedaccess、policy、controlplane、appdomain、store、cmd/proxy-sentinel 全部通过；合成回放工具编译通过。
- 真实本地 PostgreSQL、Redis 与 TLS 测试控制器集成：两会话全部成功、部分拒绝通过，包含队列持久化及重启防重复执行。
- 190 实机仅有一条指定账号在线会话，已完成下线及新会话恢复；多会话、部分失败属于本地集成验收，不能描述为现场多会话通过。
- 共享输入为明确标注的合成事件，不报告真实校园网准确率。本轮未修改前端页面，没有将此前前端改动重新计作本轮交付。
- 修复代码保留在工作区；190 联调使用本地控制面。共享人工处置改动未部署到 .30，.30 本轮仅部署历史停用及磁盘治理相关配置/程序。

详细记录位于 artifacts/shared-access-srunapi/manual-field-*.json，最终测试输出为 final-focused-tests.txt、final-native-integration.txt。七天回填、Portal 调试、限速、停用账号和自动处罚不再继续扩展。
