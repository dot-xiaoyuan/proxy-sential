#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: deploy-airgap-openeuler.sh --target user@host --bundle FILE --interface IFACE [--sensor-id ID]" >&2
}

target=""; bundle=""; interface=""; sensor_id="office-30"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --bundle) bundle="${2:-}"; shift 2 ;;
    --interface) interface="${2:-}"; shift 2 ;;
    --sensor-id) sensor_id="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$target" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || { echo "invalid deployment target" >&2; exit 2; }
[[ "$interface" =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "invalid capture interface" >&2; exit 2; }
[[ "$sensor_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid sensor id" >&2; exit 2; }
[[ -f "$bundle" && -f "$bundle.sha256" ]] || { echo "bundle or checksum is missing" >&2; exit 2; }
(cd "$(dirname "$bundle")" && sha256sum -c "$(basename "$bundle").sha256")

remote_dir="$(ssh -o BatchMode=yes "$target" 'mktemp -d /tmp/proxy-sentinel-airgap-install.XXXXXX')"
[[ "$remote_dir" == /tmp/proxy-sentinel-airgap-install.* ]] || { echo "unsafe remote staging directory" >&2; exit 1; }
cleanup() { ssh -o BatchMode=yes "$target" "find '$remote_dir' -mindepth 1 -delete; rmdir '$remote_dir'" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[上传] $(basename "$bundle") -> $target:$remote_dir/"
scp "$bundle" "$bundle.sha256" "$target:$remote_dir/"
echo "[展开] 在目标机校验并展开离线包"
ssh -tt -o BatchMode=yes "$target" "set -e; cd '$remote_dir'; sha256sum -c '$(basename "$bundle").sha256'; mkdir payload; tar -C payload -xzf '$(basename "$bundle")'; exec bash payload/install.sh --interface '$interface' --sensor-id '$sensor_id'"
