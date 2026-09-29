# HTTP 接口性能盘点

只依赖 Python 标准库；OpenAPI 转换工具使用前端已安装的 js-yaml。结果保存每次响应状态、端到端耗时和响应字节数，不保存业务响应、口令或 Cookie。

```sh
node scripts/benchmark/openapi-to-json.cjs /tmp/sentinel-openapi.json
python3 scripts/benchmark/api-benchmark.py --spec /tmp/sentinel-openapi.json --base http://192.168.0.30:18080/api/v1 --cookies /tmp/benchmark.cookies --output /tmp/benchmark-read --samples 3
```

Cookie 文件使用 Mozilla/Netscape 格式，必须是自己创建的已登录管理员测试会话，设置权限 600。脚本先读取 session 的 CSRF，再通过只读列表寻找资源 ID。测试结束后注销测试会话并删除 Cookie 文件。默认仅测 GET。`--only` 按 `METHOD /OpenAPI路径` 正则选择，但资源发现仍执行。不要使用生产转发地址运行任何写入测试。

`report.json` 包含完整 OpenAPI 操作清单及统计，`samples.jsonl` 增量保存已完成的请求。每次使用新输出目录，避免 JSONL 混入旧运行。默认串行、每接口 3 次；这里的 p95 等于三次中的最大值，仅用于初步定位，不能作为稳定 SLA、最大吞吐量或持续压测结论。HTTP 2xx 也只代表请求成功，不代表空数据列表覆盖了生产数据量。

`business_success` 表示全部样本为 2xx 且通过正常业务断言；仅有 2xx 而未验证业务结果归为未验证。它不等于性能达标。报告分别记录 `latency_gate_pass`（默认 p95 ≤500ms、p99 <1000ms）、`concurrent_sample_requirement_met`（至少 200 个有效正常样本、20 并发）和 `concurrent_scenario_pass`，场景通过也不代表完整接口验收。`mixed_or_error` 表示存在 HTTP 失败，其时间包括失败响应，不能当作成功业务性能。未启用 OIDC、缺少历史执行/事件样本、外部连接器、离线包上传、集成鉴权等必须补齐夹具才能测正常业务路径。当前自动生成的请求不能覆盖所有校验条件；400/401/404/409 需对照原始错误码检查，不能直接归因接口故障。登录和注销需使用独立测试会话单测，避免影响后续测试。

## 本地隔离写入测试

仅使用一次性 Docker PostgreSQL、ClickHouse，端口绑定 127.0.0.1；PostgreSQL 数据库名必须为 `sentinel_benchmark`。测试数据为合成数据，不复制生产库。

准备全新的本地数据库后，通过三个环境变量显式启动夹具：

```sh
PROXY_SENTINEL_BENCHMARK_ADDR=127.0.0.1:28081 \
PROXY_SENTINEL_BENCHMARK_PG='postgres://postgres:本地测试口令@127.0.0.1:25439/sentinel_benchmark?sslmode=disable' \
PROXY_SENTINEL_BENCHMARK_CH='http://127.0.0.1:28129?user=benchmark&password=本地测试口令' \
go test ./internal/controlplane -run '^TestAPIBenchmarkFixtureServer$' -v -timeout 30m
```

夹具自动迁移一次性测试库并初始化管理员，暂停后台 worker，只启用请求触发的写入。已有管理员的旧数据库不适用于初始化；使用新的空库。登录默认开发管理员后，保存自己的测试 Cookie，再运行：

```sh
python3 scripts/benchmark/api-benchmark.py --spec /tmp/sentinel-openapi.json --base http://127.0.0.1:28081/api/v1 --cookies /tmp/local-benchmark.cookies --output /tmp/benchmark-isolated --isolated-writes
python3 scripts/benchmark/organization-benchmark.py --cookies /tmp/local-benchmark.cookies --output /tmp/organization-c4.json --samples 8 --concurrency 4
```

`organization-benchmark.py` 包含校区写入，仅允许明确隔离的本地夹具。对照空历史与大历史数据，用同一套测量参数；单独组织查询与全量运营数据读取的 Go benchmark：

```sh
PROXY_SENTINEL_BENCHMARK_PG='postgres://postgres:本地测试口令@127.0.0.1:25439/sentinel_benchmark?sslmode=disable' \
go test ./internal/controlplane -run '^$' -bench BenchmarkOperationsLoadScopes -benchtime 3x -benchmem
```

结束后停止夹具并删除自己创建的一次性容器。此次测量数据及覆盖限制见 `docs/api-performance-benchmark-20260917.md`。

隔离数据因七天 TTL 降到不足一千万条时，可运行 `seed-scale.py --replenish`：只追加带唯一批次前缀的观测及对应标准事件，不删除、改写或重复使用旧事件 ID；旧数据超过目标时拒绝追加。追加后须等待新读模型回填和追平，再进行性能复测。
