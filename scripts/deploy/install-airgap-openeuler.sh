#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: install.sh --interface IFACE [--sensor-id ID] [--control-addr ADDR]" >&2
}

interface=""; sensor_id="office-30"; control_addr="0.0.0.0:18080"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) interface="${2:-}"; shift 2 ;;
    --sensor-id) sensor_id="${2:-}"; shift 2 ;;
    --control-addr) control_addr="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$interface" =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "invalid capture interface" >&2; exit 2; }
[[ "$sensor_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid sensor id" >&2; exit 2; }
[[ "$control_addr" =~ ^[A-Za-z0-9.:-]+$ ]] || { echo "invalid control address" >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || { echo "offline installer must run as root" >&2; exit 1; }

bundle_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_dir="/var/log/proxy-sentinel-install"
mkdir -p "$log_dir"
log_file="$log_dir/$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$log_file") 2>&1
started_at="$(date +%s)"
current_stage="初始化"
on_error() {
  local status=$? line="${BASH_LINENO[0]:-unknown}" command="${BASH_COMMAND:-unknown}"
  printf '\n[失败] 阶段：%s\n' "$current_stage" >&2
  printf '[失败] 行号：%s，退出码：%s\n' "$line" "$status" >&2
  printf '[失败] 命令：%s\n' "$command" >&2
  printf '[失败] 完整日志：%s\n' "$log_file" >&2
  exit "$status"
}
trap on_error ERR
stage_index=0
stage() {
  stage_index=$((stage_index + 1)); current_stage="$*"
  local percent=$((stage_index * 100 / 10))
  printf '\n[%d/10 %3d%%] %s\n' "$stage_index" "$percent" "$current_stage"
}
random_secret() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

stage "校验平台、网卡和离线包完整性"
. /etc/os-release
[[ "$ID" == openEuler && "$(uname -m)" == x86_64 ]] || { echo "仅支持 openEuler x86_64，当前为 ${ID:-unknown} $(uname -m)" >&2; exit 1; }
ip link show "$interface" >/dev/null || { echo "采集网卡不存在：$interface" >&2; exit 1; }
(cd "$bundle_dir" && sha256sum -c SHA256SUMS)
# shellcheck disable=SC1091
source "$bundle_dir/bundle.env"

stage "从离线包安装 Docker 与采集器运行依赖"
dnf install -y --disablerepo='*' "$bundle_dir"/rpms/*.rpm

stage "安装并验证 Suricata 与 Zeek"
tar -C / -xzf "$bundle_dir/collectors.tar.gz"
ldconfig
suricata --build-info | sed -n '1,5p'
zeek --version

stage "启动本机 Docker 运行时"
systemctl daemon-reload
systemctl enable --now containerd.service docker.service
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null || { echo "Docker 在 30 秒内未就绪" >&2; exit 1; }

stage "从离线包载入数据库镜像"
gzip -dc "$bundle_dir/storage-images.tar.gz" | docker load
docker image inspect "$POSTGRES_IMAGE_ID" "$CLICKHOUSE_IMAGE_ID" >/dev/null
postgres_source_image="$POSTGRES_IMAGE"
clickhouse_source_image="$CLICKHOUSE_IMAGE"
postgres_source_digest="${postgres_source_image##*@}"
clickhouse_source_digest="${clickhouse_source_image##*@}"
POSTGRES_IMAGE="${postgres_source_image%@*}:airgap-${postgres_source_digest#sha256:}"
CLICKHOUSE_IMAGE="${clickhouse_source_image%@*}:airgap-${clickhouse_source_digest#sha256:}"
docker tag "$POSTGRES_IMAGE_ID" "$POSTGRES_IMAGE"
docker tag "$CLICKHOUSE_IMAGE_ID" "$CLICKHOUSE_IMAGE"
export POSTGRES_IMAGE CLICKHOUSE_IMAGE POSTGRES_IMAGE_ID CLICKHOUSE_IMAGE_ID

stage "生成本机密钥和运行配置"
umask 077
runtime_input="$(mktemp /run/proxy-sentinel-airgap-env.XXXXXX)"
admin_secret="$(mktemp /run/proxy-sentinel-admin.XXXXXX)"
cleanup() { rm -f "$runtime_input" "$admin_secret"; }
trap cleanup EXIT
postgres_password="$(random_secret)"
clickhouse_password="$(random_secret)"
identity_key="$(random_secret)"
action_key="$(random_secret)"
admin_password='Srun@4000'
printf '%s\n' "$admin_password" > "$admin_secret"
cat > "$runtime_input" <<EOF
POSTGRES_IMAGE='$POSTGRES_IMAGE'
CLICKHOUSE_IMAGE='$CLICKHOUSE_IMAGE'
POSTGRES_IMAGE_ID='$POSTGRES_IMAGE_ID'
CLICKHOUSE_IMAGE_ID='$CLICKHOUSE_IMAGE_ID'
POSTGRES_IMAGE_SOURCE_DIGEST='$postgres_source_digest'
CLICKHOUSE_IMAGE_SOURCE_DIGEST='$clickhouse_source_digest'
PROXY_SENTINEL_ROOT='/opt/proxy-sentinel'
PROXY_SENTINEL_DATA_DIR='/opt/proxy-sentinel/data/db'
PROXY_SENTINEL_STORAGE_MODE='db'
PROXY_SENTINEL_CONTROL_ADDR='$control_addr'
PROXY_SENTINEL_HEALTH_URL='http://127.0.0.1:18080/readyz'
PROXY_SENTINEL_SENSOR_ID='$sensor_id'
PROXY_SENTINEL_MIRROR_INTERFACE='$interface'
PROXY_SENTINEL_READ_ONLY='false'
PROXY_SENTINEL_MANAGE_SURICATA='true'
PROXY_SENTINEL_MANAGE_ZEEK='true'
PROXY_SENTINEL_MANAGE_DEVICE_SIGNALS='true'
PROXY_SENTINEL_INGEST_ENABLED='true'
PROXY_SENTINEL_EVE_PATH='/var/log/suricata/eve.json'
PROXY_SENTINEL_ZEEK_LOG_DIR='/opt/proxy-sentinel/data/zeek/logs/current'
PROXY_SENTINEL_ZEEK_DHCP_PATH='/opt/proxy-sentinel/data/zeek/logs/current/dhcp.log'
PROXY_SENTINEL_ZEEK_SOFTWARE_PATH='/opt/proxy-sentinel/data/zeek/logs/current/software.log'
PROXY_SENTINEL_OFFLINE='true'
POSTGRES_HOST_PORT='25432'
POSTGRES_DB='proxy_sentinel'
POSTGRES_USER='proxy_sentinel'
POSTGRES_PASSWORD='$postgres_password'
PROXY_SENTINEL_POSTGRES_DSN='postgres://proxy_sentinel:$postgres_password@127.0.0.1:25432/proxy_sentinel?sslmode=disable'
CLICKHOUSE_HTTP_HOST_PORT='28123'
CLICKHOUSE_NATIVE_HOST_PORT='29000'
CLICKHOUSE_DB='proxy_sentinel'
CLICKHOUSE_USER='proxy_sentinel'
CLICKHOUSE_PASSWORD='$clickhouse_password'
PROXY_SENTINEL_CLICKHOUSE_DSN='http://127.0.0.1:28123/?user=proxy_sentinel&password=$clickhouse_password&database=proxy_sentinel'
PROXY_SENTINEL_IDENTITY_INGEST_KEY='$identity_key'
PROXY_SENTINEL_ACTION_MASTER_KEY='$action_key'
PROXY_SENTINEL_ADMIN_USERNAME='admin'
PROXY_SENTINEL_ADMIN_DISPLAY_NAME='系统管理员'
PROXY_SENTINEL_MIN_FREE_KB='5242880'
EOF

stage "安装 Proxy Sentinel、数据库和 systemd 服务"
PROXY_SENTINEL_OFFLINE=true "$bundle_dir/install-openeuler.sh" \
  --version "$BUNDLE_VERSION" \
  --archive "$bundle_dir/proxy-sentinel-$BUNDLE_VERSION.tar.gz" \
  --checksum "$bundle_dir/proxy-sentinel-$BUNDLE_VERSION.tar.gz.sha256" \
  --env-file "$runtime_input" \
  --admin-secret "$admin_secret"

stage "配置防火墙与本机访问边界"
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port="${control_addr##*:}/tcp"
  firewall-cmd --reload
fi

stage "验证采集器、存储、控制面和定时任务"
proxy-sentinelctl doctor
for unit in proxy-sentinel-suricata.service proxy-sentinel-zeek.service proxy-sentinel-device-signal.service proxy-sentinel-ingest.service proxy-sentinel-risk-materializer.service proxy-sentinel-control-plane.service proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.timer proxy-sentinel-logrotate.timer; do
  systemctl is-active --quiet "$unit" || { systemctl --no-pager --full status "$unit"; exit 1; }
done
curl -fsS "http://127.0.0.1:${control_addr##*:}/readyz"

stage "完成安装并输出首次登录信息"
elapsed=$(( $(date +%s) - started_at ))
display_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i == "src") {print $(i+1); exit}}')"
[[ -n "$display_ip" ]] || display_ip="$(hostname -I | awk '{print $1}')"
printf '\n安装成功，耗时 %d 秒。\n' "$elapsed"
printf '控制面：http://%s:%s/\n' "$display_ip" "${control_addr##*:}"
printf '管理员：admin\n初始密码：Srun@4000（请登录后立即在“权限与校园例外”中修改）\n'
printf '安装日志：%s\n' "$log_file"
