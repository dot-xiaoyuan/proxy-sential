# Proxy Sentinel Frontend

Proxy Sentinel 检测运营台前端。第一阶段使用 mock-first 控制面 API，服务风险列表、IP 详情、人工复核、影子运行、审计和规则 reload 占位。

## Commands

```bash
pnpm install
pnpm generate:api
pnpm dev
pnpm typecheck
pnpm lint
pnpm test
pnpm e2e
pnpm build
```

## Notes

开发阶段更新 30 的前端，在项目根目录执行 `make deploy-ui`。
命令自动构建真实 API 模式的前端并通过 SSH 直接覆盖服务器静态文件，不备份、不重启、不迁移数据库。
其他目标可使用 `make deploy-ui TARGET=root@其他IP`。更新后强制刷新浏览器。

后端快捷更新使用 `make deploy-backend`；前后端一起更新使用 `make deploy-dev`。默认目标为 30，可通过 TARGET 覆盖。
后端命令构建 Linux amd64 程序，替换服务器二进制，重启当前正在运行的四个常驻 Sentinel 服务并检查 /healthz。不备份、不执行数据库迁移；保留配置与数据。仅适用于已经安装、数据库结构兼容的开发环境更新。

- API types are generated from `../schemas/control-plane-v1.openapi.yaml`.
- MSW is enabled by default in development and tests. Set `VITE_ENABLE_MOCKS=false` to call a real backend.
- For the 30-machine shadow environment, set `VITE_API_BASE=http://192.168.0.30:18080/api/v1`; `localhost:8080` may point to an old local shadow directory without Zeek device events.
- UI must not depend on Suricata raw fields; use Normalized Event, Evidence, RiskSnapshot, Label, ShadowRun, AuditLog, and Session.
