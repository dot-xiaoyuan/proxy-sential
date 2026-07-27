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

- API types are generated from `../schemas/control-plane-v1.openapi.yaml`.
- MSW is enabled by default in development and tests. Set `VITE_ENABLE_MOCKS=false` to call a real backend.
- UI must not depend on Suricata raw fields; use Normalized Event, Evidence, RiskSnapshot, Label, ShadowRun, AuditLog, and Session.
