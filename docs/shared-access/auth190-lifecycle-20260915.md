# 190 认证身份实接与恢复验证（2026-09-15）

## 本轮结果

190 原始在线 Redis → 190 上的采集程序 → SSH 回环转发 → 独立 Sentinel 测试实例 → 独立 PostgreSQL 数据库，完整路径已经验证。未接入生产 Sentinel、未改生产数据库或认证系统配置。

使用用户指定测试账号 `yuantong` 完成真实门户登录与自行下线，未保存浏览器密码。登录页进入成功页后，完整清单从 81 条变为 82 条；下线后回到 81 条。Sentinel 收到真实账号会话，并在后续完整对账中记录结束时间，历史事件时点仍可归责，结束后的流量不再归到旧会话。测试账号最后保持退出状态。

清单中 80 条具有 seed_tag，因此不能把这批数据当作真实校园用户或处置准确率样本。真实测试会话没有 MAC 或稳定 endpoint_id，设备配额正确保持未知，未用账号或会话数虚构已确认设备数。

## 修复的实际缺陷

常驻 `srun-identity-snapshot` 在首次发送失败后，保留了待发送清单，但下一轮沿用上一轮 error，导致跳过重发。原实现需要重启进程才能继续；现改为每轮独立错误状态。

受控故障代理首次返回 503，10 秒后相同进程自动重发成功返回 202。两次请求内容 SHA-256 与幂等批次 ID 完全一致，数据库完成提交，待提交文件清除。新增子进程回归测试不依赖 Redis 在线：预置待提交清单、使用不可用 Redis 地址，验证失败后的同份清单确实能自动重发，而不是重新读取来源掩盖问题。相关竞态测试通过。

生产/原默认采集二进制没有替换。本轮验证的修复候选为 190 上 `/opt/proxy-sentinel-bridge/srun-identity-snapshot-lab`，仅执行有时限的测试进程，未安装常驻服务。

## 时钟问题

新采集清单首次提交多次收到 400，稍后用相同清单重试成功。新增有限的错误分类，仅识别服务端固定的 observed_at 拒绝原因，不记录任意远端响应内容或身份数据。测得 190 时钟比本机快约 0.088～0.119 秒；时钟未修改，未来时间校验未放宽。上线前需要核对两端时钟同步，避免每次新批次都依赖延迟重试。

## 测试环境

- Sentinel API：本机 `127.0.0.1:28080`，通过 SSH 映射至 190 回环地址；不开放公网或校园网监听。
- PostgreSQL：本机已有测试 PostgreSQL 容器中新建 `sentinel_auth190` 数据库。
- ClickHouse：独立 `sentinel-auth190-ch` 容器，本机 `127.0.0.1:28123`，数据库 `sentinel_auth190`。
- 来源：source=srun190、sensor=auth190、campus=test190、access_domain=srun190，周期 60 秒。
- 密钥仅保存在本地和 190 权限受限文件，不写入报告。测试库管理员与生产账户隔离。

## 验证证据

`artifacts/shared-access-auth190/` 保存：

- `first-commit-database.txt`：第一批完整清单落库。
- `fault-retry-http.jsonl`、`fault-retry-collector.jsonl`：503 → 原批次 202 的恢复。
- `login-snapshot.jsonl`、`logout-snapshot.jsonl`、`lifecycle-database.txt`：81 → 82 → 81 会话变化。
- `test-account-quota.json`、`test-account-after-logout.json`：仅指定测试账号的 API 结果。
- `identity-lifecycle-test.txt`：读取上述实接结果，验证历史归责、下线边界和设备未知，竞态测试通过。
- `retry-tests.txt`：采集进程重试及 legacy4k 测试通过。
- `clock-offset.json`、`clock-retry.jsonl`：时钟偏差与固定错误分类。

## 仍未完成

这次下线来自认证门户自助操作，不是 Sentinel 控制器动作，不能标记 P2 控制器下线/限速/解除通过。仍需：

1. 控制器原生 API 能力与参数映射、管理员认证接入和动作沙箱。
2. 指定测试账号的 Sentinel 人工动作、执行前归属复核、部分成功、限速叠加与对应解除。
3. 来源常驻服务、启动后异常状态展示及现场受控范围配置。
4. 将真实认证身份和对应真实采集范围串成共享案件链路；实验 NAT 流量不能直接改 IP 或园区归到该测试账号。
5. 双栈记录、用户组/产品完整字段核验，持续运行与故障场景、影子准入验收。

自动共享处罚仍关闭，整体目标未完成。
