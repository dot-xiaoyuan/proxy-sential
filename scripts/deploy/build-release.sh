#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: build-release.sh --version VERSION --output FILE" >&2
}

version=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "invalid release version" >&2; exit 2; }
[[ -n "$output" ]] || { usage; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_root="$(mktemp -d "${TMPDIR:-/tmp}/proxy-sentinel-release.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT
release_dir="$build_root/release"
  mkdir -p "$release_dir/bin" "$release_dir/frontend" "$release_dir/scripts" "$release_dir/deploy/compose" "$release_dir/deploy/logrotate" "$release_dir/assets/device-fingerprints" "$release_dir/assets/applications"

(
  cd "$repo_root"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$release_dir/bin/proxy-sentinel" ./cmd/proxy-sentinel
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/discovery-worker" ./cmd/discovery-worker
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/device-retention" ./cmd/device-retention
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/srun-identity-snapshot" ./cmd/srun-identity-snapshot
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/legacy-4k-identity-bridge" ./cmd/legacy-4k-identity-bridge
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/srun-policy-snapshot" ./cmd/srun-policy-snapshot
  (cd frontend && VITE_ENABLE_MOCKS=false VITE_API_BASE=/api/v1 pnpm build)
  cp -R frontend/dist "$release_dir/frontend/dist"
  node --input-type=module - "$release_dir/frontend/dist/assets" <<'JS'
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';
const directory = process.argv[2];
for (const name of await readdir(directory)) {
  if (!/\.(js|css)$/.test(name)) continue;
  const raw = await readFile(join(directory, name));
  if (raw.length < 1024) continue;
  const compressed = gzipSync(raw, { level: 9 });
  if (compressed.length < raw.length) await writeFile(join(directory, name + '.gz'), compressed);
}
JS
  cp -R migrations "$release_dir/migrations"
  cp -R assets/suricata "$release_dir/assets/suricata"
  cp -R assets/zeek "$release_dir/assets/zeek"
  mkdir -p "$release_dir/collectors"
  cp -R collectors/zeek "$release_dir/collectors/zeek"
  go run ./cmd/proxy-sentinel device-fingerprint build-embedded --version "offline-$version" --output "$release_dir/assets/device-fingerprints/bootstrap.tar.gz"
  cp examples/application-domain/contract-fixture.tar.gz "$release_dir/assets/applications/bootstrap.tar.gz"
  cp deploy/compose/storage.yml "$release_dir/deploy/compose/storage.yml"
  cp deploy/logrotate/proxy-sentinel-shared-signals "$release_dir/deploy/logrotate/proxy-sentinel-shared-signals"
  cp -R deploy/systemd "$release_dir/deploy/systemd"
  cp scripts/deploy/proxy-sentinelctl "$release_dir/scripts/proxy-sentinelctl"
  cp scripts/deploy/refresh-proxy-sources.py "$release_dir/scripts/refresh-proxy-sources.py"
  cp scripts/deploy/activate-zeek-socks-stream.py "$release_dir/scripts/activate-zeek-socks-stream.py"
  cp scripts/deploy/router-pilot-watchdog.sh scripts/deploy/router-pilot-snmp-rollback.sh scripts/deploy/router-pilot-shared-rollback.sh "$release_dir/scripts/"
  cp scripts/deploy/ncu-identity-sync-rollback.sh "$release_dir/scripts/ncu-identity-sync-rollback.sh"
  cp scripts/deploy/upgrade-application.sh scripts/deploy/manage-frontend-previous.py scripts/deploy/verify-applied-migrations.py scripts/deploy/validate-release-archive.py scripts/deploy/verify-application-runtime.py scripts/deploy/retire-releases.py scripts/deploy/retire-acceptance-artifacts.py "$release_dir/scripts/"
)

commit="$(git -C "$repo_root" rev-parse HEAD)"
worktree_modified=false
if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=normal)" ]]; then worktree_modified=true; fi
built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$release_dir/release-manifest.json" <<EOF
{"version":"$version","git_commit":"$commit","git_worktree_modified":$worktree_modified,"built_at":"$built_at","os":"linux","arch":"amd64"}
EOF
(
  cd "$release_dir"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
mkdir -p "$(dirname "$output")"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$release_dir" -czf "$output" .
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
echo "release built: $output"
