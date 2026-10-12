import { afterEach, expect, test } from 'vitest'
import { writeFileSync, rmSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import path from 'node:path'

const mode = `proxy-config-test-${process.pid}`
const envPath = path.resolve(process.cwd(), `.env.${mode}.local`)
afterEach(() => rmSync(envPath, { force: true }))

function loadConfig(target?: string) {
  const env = { ...process.env }
  delete env.VITE_DEV_PROXY_TARGET
  if (target !== undefined) env.VITE_DEV_PROXY_TARGET = target
  // Use Vite's real Node loader, outside Vitest's transformed module runtime.
  const script = `import {loadConfigFromFile} from 'vite'; const r=await loadConfigFromFile({mode:${JSON.stringify(mode)},command:'serve'}); console.log(JSON.stringify(r.config.server ?? null));`
  return JSON.parse(execFileSync('node', ['--input-type=module', '-e', script], { env, encoding: 'utf8' }))
}

test('代理读取模式环境文件，命令行显式设置保持优先', () => {
  writeFileSync(envPath, 'VITE_DEV_PROXY_TARGET=http://127.0.0.1:18084\n')
  expect(loadConfig().proxy['/api']).toMatchObject({ target: 'http://127.0.0.1:18084' })
  expect(loadConfig('http://127.0.0.1:19000').proxy['/api']).toMatchObject({ target: 'http://127.0.0.1:19000' })
  expect(loadConfig('')).toBeNull()
})
