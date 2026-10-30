# Event bus Redis hot state

This is a test-only cache for the Phase 2 shadow current state. PostgreSQL
`discovery_service_facts_shadow` / `discovery_device_current_shadow` remain the
durable source of truth; Redis can be flushed and rebuilt by restarting the
current-shadow aggregator.

## Provenance

- Source image: `srun-docker.pkg.coding.net/dpi/image/redis:amd`
- Runtime: Redis 8.0.2, host binary at `/opt/redis/redis-server`
- Libraries: `/opt/redis/lib/libssl.so.3`, `libcrypto.so.3`
- Config: `/etc/redis-eventbus.conf`
- Service: `proxy-sentinel-eventbus-redis.service`
- Bind: `127.0.0.1:16401`, database 15, no RDB/AOF, 512 MB, allkeys-lru

The 184 Docker daemon cannot create or copy containers reliably (18.09 create
hangs), so the binary and libraries are copied from the pinned image to the
host. This is an operational workaround for the test host, not a production
packaging recommendation.

## Install

```bash
mkdir -p /opt/redis/lib
# copy redis-server, redis-cli to /opt/redis
# copy libssl.so.3 and libcrypto.so.3 to /opt/redis/lib
chmod 755 /opt/redis/redis-server /opt/redis/redis-cli /opt/redis/lib/*
install -m 0644 redis-eventbus.conf /etc/redis-eventbus.conf
install -m 0644 ../systemd/proxy-sentinel-eventbus-redis.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now proxy-sentinel-eventbus-redis.service
LD_LIBRARY_PATH=/opt/redis/lib /opt/redis/redis-cli -p 16401 ping
```

## Operate

```bash
systemctl status proxy-sentinel-eventbus-redis.service
journalctl -u proxy-sentinel-eventbus-redis.service -n 50 --no-pager
LD_LIBRARY_PATH=/opt/redis/lib /opt/redis/redis-cli -p 16401 -n 15 dbsize
LD_LIBRARY_PATH=/opt/redis/lib /opt/redis/redis-cli -p 16401 -n 15 --scan --pattern 'ps:disc:current:*' | head
```

The aggregator warms all current devices at startup and then updates changed
devices. If Redis is restarted, restart `proxy-sentinel-eventbus-current-shadow`
to rebuild the cache.
