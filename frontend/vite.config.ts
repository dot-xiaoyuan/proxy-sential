import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// https://vite.dev/config/
// VITE_DEV_PROXY_TARGET：把 /api 反向代理到远端后端（例如 http://192.168.0.30:18080）。
// 必须同源代理而不是直连跨域：会话 cookie 是 SameSite=Strict，跨站请求不会携带，
// 直连会出现“登录成功后立刻又回到登录页”。配合 VITE_API_BASE=/api/v1 使用。
const devProxyTarget = process.env.VITE_DEV_PROXY_TARGET

export default defineConfig({
  server: devProxyTarget
    ? {
        proxy: {
          '/api': { target: devProxyTarget, changeOrigin: true, secure: false },
        },
      }
    : undefined,
  build: {
    chunkSizeWarningLimit: 1300,
  },
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    exclude: ['tests/e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    globals: true,
  },
})
