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
mkdir -p "$release_dir/bin" "$release_dir/frontend" "$release_dir/scripts" "$release_dir/deploy/compose" "$release_dir/assets/device-fingerprints" "$release_dir/assets/applications"

(
  cd "$repo_root"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$release_dir/bin/proxy-sentinel" ./cmd/proxy-sentinel
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/discovery-worker" ./cmd/discovery-worker
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/device-retention" ./cmd/device-retention
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$release_dir/bin/srun-identity-snapshot" ./cmd/srun-identity-snapshot
  (cd frontend && pnpm build)
  cp -R frontend/dist "$release_dir/frontend/dist"
  cp -R migrations "$release_dir/migrations"
  cp -R assets/suricata "$release_dir/assets/suricata"
  cp -R assets/zeek "$release_dir/assets/zeek"
  go run ./cmd/proxy-sentinel device-fingerprint build-embedded --version "offline-$version" --output "$release_dir/assets/device-fingerprints/bootstrap.tar.gz"
  cp examples/application-domain/contract-fixture.tar.gz "$release_dir/assets/applications/bootstrap.tar.gz"
  cp deploy/compose/storage.yml "$release_dir/deploy/compose/storage.yml"
  cp -R deploy/systemd "$release_dir/deploy/systemd"
  cp scripts/deploy/proxy-sentinelctl "$release_dir/scripts/proxy-sentinelctl"
)

commit="$(git -C "$repo_root" rev-parse HEAD)"
built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$release_dir/release-manifest.json" <<EOF
{"version":"$version","git_commit":"$commit","built_at":"$built_at","os":"linux","arch":"amd64"}
EOF
(
  cd "$release_dir"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
mkdir -p "$(dirname "$output")"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$release_dir" -czf "$output" .
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
echo "release built: $output"
