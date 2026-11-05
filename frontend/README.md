# Proxy Sentinel 前端

## 本地开发

```bash
pnpm install
VITE_ENABLE_MOCKS=true pnpm dev
pnpm test
pnpm typecheck
pnpm build
```

API 类型由 `../schemas/control-plane-v1.openapi.yaml` 生成。默认本地演示使用 MSW；连接真实后端时设置 `VITE_ENABLE_MOCKS=false` 并指定对应 API 地址。

前端发布随统一应用包进行，见[应用更新流程](../docs/application-only-upgrade.md)。不要使用旧开发快捷命令覆盖 184 的静态文件。界面调整按根目录 `AGENTS.md` 完成三视口检查。
