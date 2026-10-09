import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, existsSync, unlinkSync, rmdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const work = mkdtempSync(path.join(tmpdir(), 'proxy-sentinel-api-contract-'))
const output = path.join(work, 'generated.ts')
try {
  const result = spawnSync('pnpm', ['exec', 'openapi-typescript', path.join(root, 'schemas/control-plane-v1.openapi.yaml'), '-o', output], {
    cwd: path.join(root, 'frontend'),
    encoding: 'utf8',
    timeout: 30_000,
  })
  if (result.error || result.status !== 0) {
    process.stderr.write('API 契约类型生成失败。请确认前端依赖已安装。\n')
    if (result.stderr) process.stderr.write(result.stderr)
    process.exitCode = 1
  } else if (!readFileSync(output).equals(readFileSync(path.join(root, 'frontend/src/shared/api/generated.ts')))) {
    process.stderr.write('API 契约与前端生成类型不同步。请在 frontend 中执行 pnpm generate:api，并检查生成差异。\n')
    process.exitCode = 1
  } else {
    process.stdout.write('API 契约与前端生成类型一致。\n')
  }
} finally {
  if (existsSync(output)) unlinkSync(output)
  rmdirSync(work)
}
