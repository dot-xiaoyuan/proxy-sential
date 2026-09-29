# 设备域名与推测品牌

## 结果含义

设备列表中的高置信度品牌与 `brand_inference` 是独立结果。后者只说明最近七天观察到符合规则的设备服务，不能确认具体型号，也不参与风险分数、设备数量或处罚。未审核的厂商追踪域名只生成生态线索。

同一品牌命中两个不同服务，或一个服务至少三次且跨度达到十分钟，才显示推测；随机子域名和 DNS/TLS/HTTP/QUIC 对同一服务的观察不会增加独立服务数。评分最高 0.70，不是统计概率。多个品牌达到门槛或与已有高置信度品牌冲突时保留证据并显示冲突。

## 规则与接口

- NextDNS：固定 Git 提交，保留 MIT 许可，作为生态线索。
- HaGeZi：仅导入 Apple、Huawei、Samsung、Xiaomi、Vivo、OPPO/Realme 分类，固定 Git 提交，保留 GPL-3.0 许可和原始清单。OPPO/Realme 共用清单不拆分品牌。
- Apple 官方网络文档：首批审核 `albert.apple.com`、`*.push.apple.com`、`deviceenrollment.apple.com`，分别用于激活、推送和设备注册。来源为 https://support.apple.com/en-ie/101555 ，审核版本 `reviewed-2026-09-08`。

规则新增 `source_url`、`source_version`、`sources`、`service`、`purpose`、`os_families`、`brand_eligible`。只有明确审核且具备用途与来源的规则可设置 `brand_eligible=true`，旧规则默认 false。`os_families` 描述服务适用范围，不会写入终端操作系统。

列表与终端详情新增 `brand_inference`；详情提供统一计算的 `recognition`。候选包括状态、评分、规则版本、时间窗口、解释及事件引用。覆盖率接口新增 `coverage.brand_inferred`、`brand_inference_conflicts` 和明确的 `domain_window=7d`；一般事件归属率仍为 24 小时指标。规则库状态提供可用性、各来源数量、可推断规则数、生效／待回填版本和后台错误。

## 存储与恢复

迁移 `017_device_brand_inference.sql` 增加事件级规则元数据、版本化候选、规则快照、生效版本和补扫游标。实际计算按生效版本读取七天去重事件，不使用累计计数或页面 200 条证据上限；每次读取重新计算窗口，因此静默终端的旧证据也会失效。

新包回填固定不可变快照，完成后切换域名生效版本。失败保留旧结果；后台会同时更新仍在生效的旧快照。读取从独立设备字段重新融合，避免把上一次融合分值继续当作输入。

实时事件写入 ClickHouse 后进入容量 32 的非阻塞后台队列，单 worker，失败重试三次。满队列与失败批次由 ClickHouse 持久事件恢复。五分钟触发一次带十分钟重叠的增量补扫，并运行每天一次、可续跑的七天修复扫描；游标仅在批次两库写入成功后推进。跨进程用数据库 advisory lock 限制重复扫描。历史回填每批最多 100,000 条，增量补扫每批 10,000 条；传输失败保留错误原因但不输出带认证参数的连接 URL。

## 基线与诊断

2026-09-08 检查 192.168.0.30：规则版本 `offline-2026.09.07-detection7-r2`，域名规则 0，域名回填 `not_required`；63 个终端，高置信度品牌 0，近七天域名证据 0。近七天 DNS/TLS/HTTP/QUIC 事件 4,599,445 条，直接携带终端 ID 的事件 0 条。原始指标保存在 `artifacts/device-brand-inference/baseline.json`。

因此规则缺失已经确认，但补规则不能保证所有终端得到品牌。还应依次检查：域名是否可见、规则是否命中、事件时间是否能唯一对应身份历史、设备服务是否达到展示门槛。未归属命中保留在生态统计中，不按 IP 猜测终端；无域名的加密事件不会补造域名。

## 上线与回滚

1. 保存当前发布目录和设备规则包。先在隔离 PostgreSQL／ClickHouse 上应用迁移，运行回放和跨库集成测试，再完成前端类型、构建和三视口检查。
2. 用 `scripts/device-fingerprint/build-offline-bundle.sh` 构建 v4 完整包。校验失败或上游空清单会中止，已有输出不会被覆盖。
3. 按现有发布流程更新兼容 v4 的程序、前端与迁移，随后通过管理员导入接口上传完整包。离线维护也可执行 `proxy-sentinel device-fingerprint install --bundle <包路径> --dir /opt/proxy-sentinel/data/device-fingerprints`，然后重启控制面，让它恢复版本化回填。
4. 检查规则状态中域名数量与可推断数量，等待域名回填完成、生效版本切换；再检查设备列表、详情、覆盖率及未归属统计。分别抽样核实推测、冲突、未知，不以覆盖率增长代替准确性验收。
5. 临时隐藏推测展示：为控制面设置 `PROXY_SENTINEL_BRAND_INFERENCE_ENABLED=false` 并重启。保留后台证据，不影响现有高置信度品牌。
6. 规则回滚：重新导入上一有效包，确认回填完成且生效版本恢复。回滚到没有域名规则的旧包会清空生效推测。程序回滚使用原发布目录；增量表可保留，不删除原始事件。

## 本地验收命令

```bash
go test ./...
PROXY_SENTINEL_TEST_POSTGRES_DSN='<隔离测试库>' \
PROXY_SENTINEL_TEST_CLICKHOUSE_DSN='<隔离测试库>' \
go test ./internal/store -run 'TestDBBrand|TestPostgresBrand|TestPostgresDomain|TestClickHouse' -v
cd frontend
npx tsc --noEmit
pnpm build
pnpm test
pnpm exec playwright test tests/e2e/brand-inference.spec.ts --workers=1 --output ../artifacts/device-brand-inference/ui
```

回放样本：`examples/replay/device-brand-domain-inference.jsonl`。集成测试将样本时间调整到当前七天窗口，验证去重、超过 200 条证据、窗口过期、列表／详情／统计一致性、失败保留旧版和空规则回滚。

最终现场部署及回填结果见 [2026-09-08 验收记录](device-brand-inference-acceptance-20260908.md)。
