#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: build-airgap-bundle.sh --version VERSION --dependency-host user@host --output FILE" >&2
}

version=""; dependency_host=""; output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --dependency-host) dependency_host="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "invalid version" >&2; exit 2; }
[[ "$dependency_host" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || { echo "invalid dependency host" >&2; exit 2; }
[[ -n "$output" ]] || { usage; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
stage="$(mktemp -d "${TMPDIR:-/tmp}/proxy-sentinel-airgap.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
postgres_image="${POSTGRES_IMAGE:-srun-docker.pkg.coding.net/dpi/image/postgres@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a}"
clickhouse_image="${CLICKHOUSE_IMAGE:-srun-docker.pkg.coding.net/dpi/image/clickhouse@sha256:bca6494fa85aea382ddf69e8b9e8b481d2f06603b083e3dd705013a8c260e91f}"
ssh_options=(-o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
postgres_local_image="$postgres_image"
clickhouse_local_image="$clickhouse_image"
if ! ssh "${ssh_options[@]}" "$dependency_host" "docker image inspect '$postgres_local_image' >/dev/null 2>&1"; then
  postgres_local_image="${postgres_image%@*}:airgap-${postgres_image##*sha256:}"
fi
if ! ssh "${ssh_options[@]}" "$dependency_host" "docker image inspect '$clickhouse_local_image' >/dev/null 2>&1"; then
  clickhouse_local_image="${clickhouse_image%@*}:airgap-${clickhouse_image##*sha256:}"
fi
postgres_image_id="$(ssh "${ssh_options[@]}" "$dependency_host" "docker image inspect '$postgres_local_image' --format '{{.Id}}'")"
clickhouse_image_id="$(ssh "${ssh_options[@]}" "$dependency_host" "docker image inspect '$clickhouse_local_image' --format '{{.Id}}'")"
[[ "$postgres_image_id" =~ ^sha256:[a-f0-9]{64}$ && "$clickhouse_image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "cannot resolve immutable storage image IDs" >&2; exit 1; }

step=0
progress() { step=$((step + 1)); printf '\n[%d/6] %s\n' "$step" "$*"; }

mkdir -p "$stage/rpms"
progress "构建 Linux amd64 应用与前端发布包"
"$repo_root/scripts/deploy/build-release.sh" --version "$version" --output "$stage/proxy-sentinel-$version.tar.gz"

progress "从 openEuler 依赖机收集精确版本 RPM"
ssh "${ssh_options[@]}" "$dependency_host" bash -s > "$stage/runtime-rpms.tar.gz" <<'REMOTE'
set -euo pipefail
packages=(
  docker-ce docker-ce-cli docker-ce-rootless-extras containerd.io docker-compose-plugin container-selinux
  iptables iptables-libs libseccomp device-mapper logrotate
  jansson libyaml pcre zlib libpcap openssl-libs libmaxminddb krb5-libs zeromq libsodium libunwind libstdc++
  nss nss-softokn nss-util nspr
  tcpdump jq
)
work="$(mktemp -d /tmp/proxy-sentinel-airgap-rpms.XXXXXX)"
trap 'rm -rf "$work"' EXIT
specs=()
for package in "${packages[@]}"; do
  rpm -q "$package" >/dev/null 2>&1 || { echo "required package is not installed on dependency host: $package" >&2; exit 1; }
  specs+=("$(rpm -q "$package")")
done
dnf download --destdir "$work" "${specs[@]}" >&2
tar -C "$work" -czf - .
REMOTE
tar -C "$stage/rpms" -xzf "$stage/runtime-rpms.tar.gz"
rm -f "$stage/runtime-rpms.tar.gz"

progress "打包 Suricata、Zeek 与现场验证配置"
ssh "${ssh_options[@]}" "$dependency_host" \
  'test -x /usr/bin/suricata; test -x /usr/local/bin/zeek; tar -C / -czf - usr/bin/suricata usr/lib/libhtp.so usr/lib/libhtp.so.2 usr/lib/libhtp.so.2.0.0 etc/suricata usr/local/zeek usr/local/bin/zeek' \
  > "$stage/collectors.tar.gz"

progress "导出 digest 固定的 PostgreSQL 与 ClickHouse 镜像"
ssh "${ssh_options[@]}" "$dependency_host" "docker image inspect '$postgres_local_image' '$clickhouse_local_image' >/dev/null; docker save '$postgres_local_image' '$clickhouse_local_image'" \
  | gzip -1 > "$stage/storage-images.tar.gz"

progress "写入离线安装器与不可变清单"
cp "$repo_root/scripts/deploy/install-airgap-openeuler.sh" "$stage/install.sh"
cp "$repo_root/scripts/deploy/install-openeuler.sh" "$stage/install-openeuler.sh"
chmod 0755 "$stage/install.sh" "$stage/install-openeuler.sh"
cat > "$stage/bundle.env" <<EOF
BUNDLE_VERSION='$version'
POSTGRES_IMAGE='$postgres_image'
CLICKHOUSE_IMAGE='$clickhouse_image'
POSTGRES_IMAGE_ID='$postgres_image_id'
CLICKHOUSE_IMAGE_ID='$clickhouse_image_id'
DEPENDENCY_PLATFORM='openEuler-x86_64'
EOF
(
  cd "$stage"
  sha256sum bundle.env collectors.tar.gz storage-images.tar.gz proxy-sentinel-"$version".tar.gz proxy-sentinel-"$version".tar.gz.sha256 rpms/*.rpm > SHA256SUMS
)

progress "生成最终离线包并校验"
mkdir -p "$(dirname "$output")"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -czf "$output" .
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
(cd "$(dirname "$output")" && sha256sum -c "$(basename "$output").sha256")
printf '\n离线包已生成：%s\n' "$output"
du -h "$output" | awk '{print "离线包大小：" $1}'
