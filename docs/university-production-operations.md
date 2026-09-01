# 高校生产版运维说明

## 首次启用本地 RBAC

生产模式将用户和会话保存在 PostgreSQL。密码通过环境变量传入，命令不会覆盖已有账号：

```bash
export PROXY_SENTINEL_ADMIN_PASSWORD='请替换为至少 12 位的独立密码'
/opt/proxy-sentinel/bin/proxy-sentinel control-plane bootstrap-admin \
  --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --username admin \
  --name 系统管理员
unset PROXY_SENTINEL_ADMIN_PASSWORD
```

文件用户库仅供显式 `storage-mode=file` 的开发环境使用。生产 HTTPS 入口必须启用 `--auth-cookie-secure=true`。全局 `--read-only` 仍是紧急只读熔断，优先级高于角色权限。

## 风险规则重算

先生成最近七天的新旧规则对比报告，人工确认后再加 `--apply`。应用前会把当前快照归档到历史表，人工结论不会被重算覆盖。

```bash
proxy-sentinel risk recalculate --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --window 168h --ruleset-version university-v2 --output risk-comparison.json
proxy-sentinel risk recalculate --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --window 168h --ruleset-version university-v2 --apply --output risk-applied.json
```

## 身份接入凭据与处置主密钥

不要把身份接入凭据或处置主密钥写在命令行参数中。使用权限为 `0600` 的 systemd EnvironmentFile：

```ini
PROXY_SENTINEL_IDENTITY_INGEST_KEY=<独立随机凭据>
PROXY_SENTINEL_ACTION_MASTER_KEY=<至少 32 字节随机主密钥>
```

身份批次调用 `/api/v1/integrations/identity/events`，同时携带 `Authorization: Bearer ...` 和稳定的 `Idempotency-Key`。主密钥只用于本地加密北向连接器凭据；丢失后旧凭据不可解密，需要重新录入。

管理端可通过 `GET /api/v1/integrations/identity/batches` 查看每个批次的处理状态、错误明细与重试次数；修复数据源或存储故障后，管理员调用 `POST /api/v1/integrations/identity/batches/{batch_id}/replay` 重放服务端保留的标准事件。重放沿用原事件 ID，不要求上游再次发送原始厂商字段。

## 上线门槛

北向连接器默认保持影子模式。真实模式启用前必须满足至少 7 天影子验证、自动候选人工准确率不低于 95%、无校园 VPN/教学科研/基础设施误处置样本，并验证冷却、熔断、失败回退及人工撤销。身份数据中断时动作硬门槛自动阻断。

30 机器继续使用 `--device-fingerprint-auto-update=false`，仅导入本地校验通过的离线特征包，不主动访问 IEEE、GitHub 或 Fingerbank。

## 本地权限矩阵

| 能力 | viewer | reviewer | operator | admin |
| --- | --- | --- | --- | --- |
| 风险、证据、事件、终端、态势、案件、审计只读 | 是 | 是 | 是 | 是 |
| 案件分派、评论、状态与结论 | 否 | 是 | 是 | 是 |
| 终端登记 | 否 | 否 | 是 | 是 |
| 影子动作执行与人工撤销 | 否 | 否 | 是 | 是 |
| 校区、区域、接入点维护 | 否 | 否 | 否 | 是 |
| 身份接入、北向连接器、规则与特征库管理 | 否 | 否 | 否 | 是 |
| 用户管理 | 否 | 否 | 否 | 是 |

前端隐藏无权入口仅用于减少误操作；服务端中间件是权限边界，越权统一返回 `403 permission_denied`。写请求在启用本地登录后还必须携带当前会话的 CSRF Token。
