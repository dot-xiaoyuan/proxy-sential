# Fingerbank 快照接入与识别效果对比（2026-11-03）

本文记录在本机独立 worktree `codex/fingerbank-snapshot-20261103` 中完成的 Fingerbank 接入测试。所有现场数据读取均为只读，184 未发生任何写入；Fingerbank 数据只在构建机使用，不进入仓库、不进入发布包。

## 1. 凭据与接口探测

- 使用用户提供的 community key（level 0，月度软上限 1,000,000），不在仓库与日志中记录密钥。
- `GET /api/v2/users/account_info/:key`：可用，返回 `level=0`、`monthly_limit=1000000`。
- `GET /api/v2/download/db`：可用，`Content-Range: bytes 0-0/1542542336`（约 1.44 GiB），`Last-Modified: 2026-11-02T03:02:58Z`，支持 Range；HEAD 返回 404，探测必须用 GET + Range。
- `GET /api/v2/download/on-prem-db`：403，需要授权。
- `POST /api/v2/combinations/interrogate`：可用，样例（Windows 指纹 + `MSFT 5.0`）返回 `score=88`、`device_name=Operating System/Windows OS`。

## 2. 整库下载的每日限制（本次未取得整库）

整库下载有**每资源每日一次**的限制。分段续传时第 4 个分段收到 142 字节正文：

```
The download of this resource is daily limited. This is only updated once per day
so there is no need to download this multiple times per day.
```

已完成的下载尝试因此无法继续；本次不重试，避免继续消耗额度。整库路线留待次日或取得 on-prem 授权后重跑，命令与校验方式不变（`curl -C -` + SHA256 + `sqlite3 .schema`）。整库的 SQLite 抽取脚本尚未编写：拿到 schema 后再补，避免对未知表结构做猜测。

## 3. 现场回放语料

- 来源：`/opt/proxy-sentinel/data/zeek/logs/current/device_dhcp_binding.log` 与 2026-11-02、2026-11-03 的小时轮转日志，共 36 个文件、542,404 行。
- 只保留 `requested_options`（DHCP option 55）与 `vendor_class`（option 60），丢弃 MAC、主机名与 UA。
- 去重后 **577 个不同组合**；取观测次数最多的前 200 个，覆盖 **97.9%** 的观测。
- 语料在构建机保存为 `dhcp-pairs.jsonl`，不写回现场。

## 4. 采用的取数方式：按现场指纹逐个 interrogate

由于整库下载当日不可用，本次改为对前 200 个现场指纹逐个 interrogate（含 vendor class）：

- 脚本：`scripts/fingerprints/interrogate_fingerbank.py`（密钥只从环境变量读取）。
- 频率限制：免费额度 600 次/小时；脚本按每 10 秒 1 次（约 360 次/小时）执行，约 33 分钟完成。
- 每个响应写入本地缓存 `fb-cache.jsonl`，中断可续跑，不重复查询。
- 404（无匹配）记录但不生成规则；401/403 立即终止；429 退避 60 秒重试。
- 该方式只发送两个 DHCP 字段，不发送 MAC/主机名/UA；响应结果只用于本次评估。

## 5. 转换语义

`CompileFingerbankSnapshot` 把原始记录编译为与既有 `fingerbank-dhcp.json` 同构的规则：

| 输入 | 输出 |
|---|---|
| `fingerprints[]` | `requested_options`（归一化为逗号分隔） |
| `vendor_classes[]` | `vendor_classes`（同指纹多来源时取并集） |
| `device_path` | `device_type` / `os_family`，复用 `normalizeFingerbankClass`，补充 camera→iot、tablet、TV/console→media 等保守映射 |
| `score` | 规则置信度：`score/100` 截断到 `[0.5, 0.9]`；`score < 30` 直接丢弃 |
| 无 score（整库快照） | 沿用 0.84 |

同一 option 组合只产出一条规则：优先高分设备路径，其次更深层级；避免多个候选让 `bestDHCPFingerprint` 拒绝匹配。

护栏：规则数少于 100 或“无法映射到 device_type/os_family”的比例超过 20% 时构建失败。

## 6. 代码改动（worktree 内）

- `scripts/fingerprints/interrogate_fingerbank.py`：按现场指纹逐个查询并缓存，可断点续跑。
- `internal/fingerprint/fingerbank_snapshot.go`：原始记录 → `fingerbank-dhcp.json` 编译与统计。
- `internal/fingerprint/bundle_fingerbank.go`：只替换 `fingerbank-dhcp.json` 与 Fingerbank 源声明，其余载荷逐字节保持；重建 manifest 后重新校验。
- `cmd/proxy-sentinel/main.go`：新增 `device-fingerprint fingerbank-refresh`（编译 + 可选重打包）。
- `cmd/fingerprint-replay/main.go`：支持基线库与替换库对比，输出识别率、OS 分布、冲突数与吞吐；输入支持 `weight` 以按观测次数加权。

## 7. 结果

见同目录回放报告与 `artifacts/fingerbank-20261103/`。整库快照与现场 A/B 尚未执行。
