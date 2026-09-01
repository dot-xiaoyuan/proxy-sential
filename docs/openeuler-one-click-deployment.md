# openEuler x86_64 一键部署

生产部署只支持 openEuler x86_64。目标机不需要 Git、Go、Node.js 或项目源码；开发机生成不可变发布包，通过 SSH/SCP 上传，目标机只访问 Coding 镜像仓库和本机服务。

## 首次准备

复制环境模板并设置权限：

```bash
cp deploy/compose/storage.env.example deploy/compose/storage.env
chmod 0600 deploy/compose/storage.env
```

必须修改数据库密码、DSN、身份接入密钥、处置主密钥及 Coding 凭据。`POSTGRES_IMAGE` 和 `CLICKHOUSE_IMAGE` 必须是 `srun-docker.pkg.coding.net/...@sha256:<digest>`；安装器拒绝 `latest`、仅 tag 或非 Coding 镜像。

首次部署会在终端隐藏询问管理员密码。密码通过权限为 `0600` 的临时文件传输，创建 PostgreSQL 管理员后立即删除，不进入命令历史、systemd 参数和普通日志。非交互环境可临时设置 `PROXY_SENTINEL_INITIAL_ADMIN_PASSWORD`，脚本读取后会立即清除当前进程变量。

## 单命令安装或升级

```bash
make deploy \
  TARGET=root@192.168.0.30 \
  VERSION=2026.09.01-1 \
  ENV_FILE=deploy/compose/storage.env
```

命令依次完成：本地 Linux amd64 二进制和前端构建、发布包 SHA-256、目标机平台/磁盘/端口/内核/网卡预检、Coding 登录、digest 校验、升级前逻辑备份、存储启动、带校验台账的 PostgreSQL/ClickHouse 迁移、systemd 安装、`current` 原子切换和 `/readyz` 健康检查。

任何预检失败都不会改动当前版本。迁移失败不会切换应用；迁移只允许增量、向前兼容。应用健康检查失败会恢复原 systemd 单元和 `current` 链接，但不会自动恢复数据库。

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
