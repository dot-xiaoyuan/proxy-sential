# openEuler x86_64 一键部署

生产部署只支持 openEuler x86_64。目标机不需要 Git、Go、Node.js、项目源码或 Docker Compose。联网模式由开发机生成不可变发布包，目标机只访问 Coding 镜像仓库和本机服务；全离线模式把系统 RPM、Docker/containerd、Suricata、Zeek、数据库镜像和应用一起装入一个带校验清单的安装包。安装器优先使用 Docker Compose v2，在 Compose 不可用时自动使用等价的单机 Docker 容器配置。

## 首次准备

复制环境模板并设置权限：

```bash
cp deploy/compose/storage.env.example deploy/compose/storage.env
chmod 0600 deploy/compose/storage.env
```

必须修改数据库密码、DSN、身份接入密钥、处置主密钥及 Coding 凭据。`POSTGRES_IMAGE` 和 `CLICKHOUSE_IMAGE` 必须是 `srun-docker.pkg.coding.net/...@sha256:<digest>`；安装器拒绝 `latest`、仅 tag 或非 Coding 镜像。

首次部署创建管理员 `admin`，初始密码固定为 `Srun@4000`。登录后应立即进入“权限与校园例外 → 本地用户”修改密码；管理端要求新密码至少 12 位，修改后会使该账号已有会话失效。安装器只通过权限为 `0600` 的临时文件把初始密码交给引导命令，创建账号后立即删除，不在服务器保存密码文件。联网部署如确需覆盖初始密码，可临时设置至少 12 位的 `PROXY_SENTINEL_INITIAL_ADMIN_PASSWORD`。

## 单命令安装或升级

```bash
make deploy \
  TARGET=root@192.168.0.30 \
  VERSION=2026.09.01-1 \
  ENV_FILE=deploy/compose/storage.env
```

命令依次完成：本地 Linux amd64 二进制和前端构建、发布包 SHA-256、目标机平台/磁盘/端口/内核/网卡预检、Coding 登录、digest 校验、升级前逻辑备份、存储启动、带校验台账的 PostgreSQL/ClickHouse 迁移、systemd 安装、`current` 原子切换和 `/readyz` 健康检查。

安装结果始终是完整单机拓扑：Suricata、实时 Ingest Worker、PostgreSQL、ClickHouse、影子任务和控制面都由同一台主机承载。虚拟机没有镜像口时，可设置 `PROXY_SENTINEL_MANAGE_SURICATA=false`，并将 `PROXY_SENTINEL_EVE_PATH` 指向本机回放文件；这只改变输入来源，不会把系统部署成分布式架构。

Zeek 同机日志可通过 `PROXY_SENTINEL_ZEEK_DHCP_PATH`、`PROXY_SENTINEL_ZEEK_SOFTWARE_PATH`、`PROXY_SENTINEL_ZEEK_MDNS_PATH`、`PROXY_SENTINEL_ZEEK_NBNS_PATH`、`PROXY_SENTINEL_ZEEK_LLMNR_PATH` 和 `PROXY_SENTINEL_ZEEK_TTL_PATH` 按需启用。所有路径都由同一个 Ingest Worker 转换为标准事件；风险规则不会读取采集器原始字段。

任何预检失败都不会改动当前版本。迁移失败不会切换应用；迁移只允许增量、向前兼容。应用健康检查失败会恢复原 systemd 单元和 `current` 链接，但不会自动恢复数据库。

## 全离线一键安装

先在一台与目标机相同的 openEuler x86_64 依赖机上生成离线包。依赖机需要已经安装目标版本的 Docker、Suricata 和 Zeek，并且已经持有固定 digest 的 PostgreSQL、ClickHouse 镜像：

```bash
make package-airgap \
  VERSION=2026.09.04-1 \
  DEPENDENCY_HOST=root@192.168.0.30
```

生成物为 `dist/proxy-sentinel-airgap-<version>.tar.gz` 和同名 `.sha256`。部署时，目标机可以没有 Docker、containerd、Compose、Suricata、Zeek、Go、Node.js 和项目源码，也不需要访问软件仓库或镜像仓库：

```bash
make deploy-airgap \
  TARGET=root@192.168.0.30 \
  BUNDLE=dist/proxy-sentinel-airgap-2026.09.04-1.tar.gz \
  INTERFACE=ens1f1 \
  SENSOR_ID=office-30
```

部署命令会先在本地校验外层 SHA-256，再上传并在目标机校验包内每个文件。目标安装器显示 10 个阶段及百分比；发生错误时输出失败阶段、脚本行号、退出码、失败命令和 `/var/log/proxy-sentinel-install/` 下的完整日志。数据库镜像同时校验来源 digest 和导出时记录的内容 ID，载入后使用经过内容 ID 验证的本地 airgap tag，避免把同名浮动镜像当成离线包内容。

安装完成后随机生成数据库、身份接入和处置密钥。首次管理员为 `admin`，初始密码为 `Srun@4000`；服务器不保存管理员明文密码文件。控制面默认地址为 `http://<目标机管理IP>:18080/`。

如需重做“空机安装”验收，应先执行 `scripts/deploy/reset-openeuler.sh --confirm-host <目标机IP>`。该命令会删除 Proxy Sentinel 应用、数据、采集日志、采集器、专属数据库容器和相关 Docker 软件包，属于不可恢复操作。共享 Docker 主机只有在确认要保留其他业务容器数据时才增加 `--preserve-docker-data`；这会保留 `/var/lib/docker`，但仍会停止并卸载 Docker，其他容器会短暂中断。

## 目录布局

```text
/opt/proxy-sentinel/
  releases/<version>/       不可变应用版本
  current -> releases/...   当前版本
  previous -> releases/...  可回滚版本
  config/runtime.env        0600 运行配置，不含 Coding 登录凭据
  data/                     PostgreSQL、ClickHouse、影子运行和离线特征库
  backups/<timestamp>/      升级前及人工逻辑备份
```

30 机器始终使用 `--device-fingerprint-auto-update=false`，设备特征包只能离线导入。

## 统一运维命令

```bash
proxy-sentinelctl status
proxy-sentinelctl doctor
proxy-sentinelctl logs -n 300
proxy-sentinelctl backup
proxy-sentinelctl rollback
proxy-sentinelctl restore /opt/proxy-sentinel/backups/<timestamp> --yes
```

`restore` 会清理并覆盖现场数据库，必须显式提供 `--yes`，部署或回滚永远不会自动调用。`rollback` 只回切应用版本，因此所有数据库迁移都必须向前兼容。

健康接口分工：`/healthz` 只表示进程存活，`/readyz` 校验业务存储、认证、身份接入和采集状态，`/api/v1/system/status` 在登录后展示采集、存储、身份、只读开关和离线特征库状态。

## 路由识别影子验证

一键安装器只支持 openEuler x86_64；其他发行版可手工运行二进制和容器，但不在一键安装支持范围内。路由识别首次验证应部署到新机器，使用独立镜像网卡、独立 PostgreSQL/ClickHouse 数据目录和独立控制面端口，不连接或修改现有 dpi-analyze 服务器。

Zeek 和 Suricata 只能读取交换机镜像流量。控制面保持 `--read-only`，路由聚合保持 shadow mode，所有真实处置 connector 禁用。部署和验证不得修改现有服务器的 systemd、DPI、MongoDB、Redis 或代理配置。

需要先验证流量与字段链路时，使用不会入库或安装服务的限时采样命令：

```bash
/opt/proxy-sentinel/current/bin/proxy-sentinel router sample \
  --interface ens1f1 \
  --duration 5m \
  --work-dir /opt/proxy-sentinel/data/router-samples/first-check
```

采样目录包含 Zeek 原始日志、标准事件、`router-evidence.json`、`router-assessments.json` 和统计摘要。命令到期后自动停止临时 Zeek 进程。完整规则、查询、回放和验收说明见 [Huawei/H3C 路由器被动识别](router-passive-identification.md)。
