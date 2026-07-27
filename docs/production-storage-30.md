# 30 机器生产存储编排

30 机器使用 `deploy/compose/storage.yml` 启动 Proxy Sentinel 控制面存储。

默认只绑定本机端口，避免和已有服务冲突或对外暴露：

- PostgreSQL：`127.0.0.1:25432 -> 5432`
- ClickHouse HTTP：`127.0.0.1:28123 -> 8123`
- ClickHouse native：`127.0.0.1:29000 -> 9000`

镜像：

- `srun-docker.pkg.coding.net/dpi/image/postgres:latest`
- `srun-docker.pkg.coding.net/dpi/image/clickhouse:latest`

## 启动

复制环境文件并修改密码：

```bash
cd /opt/proxy-sentinel
cp deploy/compose/storage.env.example deploy/compose/storage.env
chmod 0600 deploy/compose/storage.env
docker compose --env-file deploy/compose/storage.env -f deploy/compose/storage.yml up -d
```

## 初始化 schema

PostgreSQL：

```bash
docker compose --env-file deploy/compose/storage.env -f deploy/compose/storage.yml \
  exec -T postgres psql -U proxy_sentinel -d proxy_sentinel \
  < migrations/postgres/001_production_schema.sql
```

ClickHouse：

```bash
docker compose --env-file deploy/compose/storage.env -f deploy/compose/storage.yml \
  exec -T clickhouse clickhouse-client \
  --user proxy_sentinel --password "$CLICKHOUSE_PASSWORD" \
  --database proxy_sentinel --multiquery \
  < migrations/clickhouse/001_production_schema.sql
```

## Proxy Sentinel DSN

systemd 中 shadow/control-plane 使用 `dual` 模式接入 DB，同时保留文件兜底：

```text
--storage-mode dual
--postgres-dsn postgres://proxy_sentinel:<password>@127.0.0.1:25432/proxy_sentinel?sslmode=disable
--clickhouse-dsn http://proxy_sentinel:<password>@127.0.0.1:28123/?database=proxy_sentinel
```
