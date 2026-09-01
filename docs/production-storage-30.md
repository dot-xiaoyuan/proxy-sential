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

systemd 中 shadow/control-plane 使用生产 `db` 模式，不允许 JSON 文件产生多实例数据分叉：

```text
PROXY_SENTINEL_STORAGE_MODE=db
PROXY_SENTINEL_POSTGRES_DSN='postgres://...'
PROXY_SENTINEL_CLICKHOUSE_DSN='http://...?database=proxy_sentinel'
```

完整的一键部署、回滚、备份和恢复说明见 `docs/openeuler-one-click-deployment.md`。
