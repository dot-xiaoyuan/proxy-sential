# 30 机器生产存储编排

30 机器使用 `deploy/compose/storage.yml` 启动 Proxy Sentinel 控制面存储。正式安装与升级统一由 `make deploy` 完成，不再在目标机复制环境、执行 Git 或逐条运行迁移。

默认只绑定本机端口，避免和已有服务冲突或对外暴露：

- PostgreSQL：`127.0.0.1:25432 -> 5432`
- ClickHouse HTTP：`127.0.0.1:28123 -> 8123`
- ClickHouse native：`127.0.0.1:29000 -> 9000`

镜像必须来自 Coding 且使用不可变 digest，例如：

- `srun-docker.pkg.coding.net/dpi/image/postgres@sha256:...`
- `srun-docker.pkg.coding.net/dpi/image/clickhouse@sha256:...`

## 部署

复制环境文件并修改密码：

```bash
cp deploy/compose/storage.env.example deploy/compose/storage.env
chmod 0600 deploy/compose/storage.env
make deploy TARGET=root@192.168.0.30 VERSION=<version> ENV_FILE=deploy/compose/storage.env
```

安装器使用迁移台账和 SHA-256 校验自动执行两个数据库的全部增量迁移；失败时禁止应用切换。

## Proxy Sentinel DSN

systemd 中 control-plane、ingest 和读模型服务使用生产 `db` 模式，不允许 JSON 文件产生多实例数据分叉：

```text
PROXY_SENTINEL_STORAGE_MODE=db
PROXY_SENTINEL_POSTGRES_DSN='postgres://...'
PROXY_SENTINEL_CLICKHOUSE_DSN='http://...?database=proxy_sentinel'
```

完整的一键部署、回滚、备份和恢复说明见 `docs/openeuler-one-click-deployment.md`。

## 旧影子采集任务与磁盘恢复

启用实时 ingest 和读模型的生产部署应保持 `proxy-sentinel-shadow.timer` 停用，安装器也采用这个默认值。旧 `shadow run` 是文件回放入口：写库失败时不推进游标，下次可能重新生成整个日志区间的 normalized 副本。它不能作为实时管线的第二套常驻采集任务。停用这个任务不改变策略连接器的影子模式，也不关闭实时证据和风险评估。

磁盘耗尽时先暂停重复回放和失败重启的写入服务，核对 `df` 的可用空间以及 ext4 预留块。数据库进程需要普通用户可用空间，释放少量文件后 `df` 仍可能显示零可用。不要删除 PostgreSQL 数据目录、WAL 或受保留规则保护的证据。只清理已独立备份并逐文件核对大小和 SHA-256 的任务副本，保留运行摘要及证据，并保存删除审计。恢复空间后检查数据库健康、应用就绪、采集进程和生产者轮次绑定，再发布新版本。

库存维护按七天保留规则分批执行，额外保留案件 IP 的全部历史、每个传感器/窗口的最新批次和每个 IP 的最新快照。出现没有 IP 的案件时，全局停止清理。删除行数不等于释放磁盘字节；普通 VACUUM 可以回收空间供表内复用，不能保证立即缩小数据文件。应分别核对 JSON 存储值大小、表及 TOAST 的实际文件大小和文件系统可用空间，不能仅凭文件体积认定全部属于空洞。空间不足时禁止直接执行 `VACUUM FULL` 或重写大表。

共享判断与路由识别的状态写入最多等待五秒，并跟随服务退出取消。工作窗口超时后，诊断写入使用服务上下文，仍记录真实失败原因；路由识别失败时不推进游标。状态写入失败由日志记录，下一轮可以重试，避免数据库异常把识别循环永久阻塞。当前共享列表为空时，还应检查 `read_model_runtime_state` 中 `shared-behavior` 的窗口、输入行数和覆盖状态，区分证据不足与管线异常。

应用目录清退使用 `scripts/deploy/retire-releases.py`，兼容日期加描述名的早期版本和编号版本，均要求清单版本、平台及完整备份一致。当前、上一回滚版本和 `frontend-previous` 兼容资源版本受到保护；运行进程的可执行文件、打开文件、内存映射以及 systemd 与应用配置中的路径引用也会阻止清退。完整快照应记录文件权限和属主，备份恢复校验通过后才删除原副本；清单身份不一致、引用仍存在或文件发生变化时保留目录，并保存逐步清退审计。

清退引用检查包含目录自身和子路径，既保护 `WorkingDirectory` 等不带尾部斜杠的配置，也保护进程的工作目录及根目录；按目录名边界匹配，避免将另一个相似版本名误当成引用。

2026-10-05 的 30 机器存储恢复另有 ext4 预留调整审计：根卷 `/dev/mapper/openeuler-root`，UUID `e9abf31e-5ab4-4c0e-892f-3d6c051adc76`，4096 字节块、58056704 个块。预留由 2902835 块降至 1161135 块，保留约 4.43GiB（2%）系统应急空间，普通用户可用容量增加 7134003200 字节。此项是已有空闲容量的重新分配，不是数据库文件缩减；恢复原值的命令为 `tune2fs -r 2902835 /dev/mapper/openeuler-root`，只能在核对同一卷身份和当时余量后使用。原值、新值、文件系统身份及验证结果存于 `/opt/proxy-sentinel/data/incident-audit/20261005/root-reserve-adjustment.json`。

同次恢复清退 44 份完整验证的旧应用目录：删除原副本文件合计 1484713591 字节，同时在根卷保留 545103101 字节的完整恢复压缩包，因此两者的净差约 896MiB；本地另有独立备份。当前、回滚和旧前端兼容版本受到保护，两份清单身份冲突的目录继续保留。磁盘仍有持续写入，实际可用容量以复验时的 `df` 为准，不能把上述容量相加后宣称长期存储问题已经解决。


## 当前库存与独立身份任务

081 迁移增加 `device_inventory_current`，按传感器、窗口和 IP 覆盖保存当前库存。设备列表、IP 详情和风险设备摘要读取这个模型，旧设备历史快照不再追加；原始事件、信号事实、案件证据和审计继续分别保存。重复事件 ID 列表缩成最多 16 个示例引用，候选和信号均保留。旧影子采集任务保持停用。

`proxy-sentinel-identity-materializer.service` 消费独立标准身份/设备事件流，按接收时间推进实时游标，并用独立游标回填七天保留期内的事件。身份与进度原子提交，失败重放不推进游标；历史事件不以处理时间续期租约。该任务也更新当前库存和账号快照读取投影。`/api/v1/integrations/identity/status` 返回任务状态、游标和待处理快照数。账号投影按来源范围、会话代次和地址分别保存，策略仍读取原权威事件与完整快照。

2026-10-06 用户明确要求删除全部设备历史快照，30 上仅清空 `device_inventory_snapshots`，采用单表 `TRUNCATE RESTRICT`，保留案件证据、认证快照、审计和原始事件。清空前后容量及实际余量记在本次发布审计中。维护定时器停用；不要重新启用旧影子采集作为身份更新入口。
