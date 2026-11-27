#!/usr/bin/env bash
# Proxy Sentinel 防代理离线全量一键安装器（支持 openEuler x86_64 单机 HDD 交付）
# 核心特性：
# 1. 零外网依赖：自动载入离线 PG/CH 镜像与 RPM 依赖；
# 2. Docker 网段自避让：自动探测校方 4K 地址或宿主机路由是否与 172.17.0.0/16 冲突并自动改写 daemon.json；
# 3. 防代理单机 HDD 默认调优：默认关闭 204 被动发现与重型 Suricata/Zeek，开启紧凑策略落库与 CH system.query_log 3 天 TTL；
# 4. 4K 认证桥与服务端证书固定校验支持。
set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
用法:
  install.sh --interface IFACE [选项]

选项:
  --interface IFACE         镜像采集网卡（必填）
  --sensor-id ID            传感器标识（默认：anti-proxy-node）
  --control-addr ADDR       控制面监听地址（默认：0.0.0.0:80）
  --profile MODE            部署档位：anti-proxy-hdd（默认，轻量单机机械盘）| full（含 Suricata/Zeek）
  --docker-bip CIDR         自定义 docker0 网桥地址（冲突时默认自动切至 172.30.0.1/24）
  --srun4k-api-host HOST    校方 4K 北向 API/Redis 主机 IP（可选，用于网段冲突检测与配置预写入）
  --srun4k-db-host HOST     校方 4K 授权数据库主机 IP（可选）
  --srun4k-cert-file FILE   校方 4K 服务端固定校验 PEM 证书路径（可选）
  --read-only true|false    控制面只读观察模式（默认：true）
EOF
}

interface=""
sensor_id="anti-proxy-node"
control_addr="0.0.0.0:80"
profile="anti-proxy-hdd"
docker_bip=""
srun4k_api_host=""
srun4k_db_host=""
srun4k_cert_file=""
read_only="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) interface="${2:-}"; shift 2 ;;
    --sensor-id) sensor_id="${2:-}"; shift 2 ;;
    --control-addr) control_addr="${2:-}"; shift 2 ;;
    --profile) profile="${2:-}"; shift 2 ;;
    --docker-bip) docker_bip="${2:-}"; shift 2 ;;
    --srun4k-api-host) srun4k_api_host="${2:-}"; shift 2 ;;
    --srun4k-db-host) srun4k_db_host="${2:-}"; shift 2 ;;
    --srun4k-cert-file) srun4k_cert_file="${2:-}"; shift 2 ;;
    --read-only) read_only="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ "$interface" =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "invalid capture interface" >&2; exit 2; }
[[ "$sensor_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid sensor id" >&2; exit 2; }
[[ "$control_addr" =~ ^[A-Za-z0-9.:-]+$ ]] || { echo "invalid control address" >&2; exit 2; }
[[ "$profile" == "anti-proxy-hdd" || "$profile" == "full" ]] || { echo "invalid profile: $profile" >&2; exit 2; }
[[ "$read_only" == "true" || "$read_only" == "false" ]] || { echo "invalid read-only: $read_only" >&2; exit 2; }
[[ -z "$srun4k_cert_file" || -f "$srun4k_cert_file" ]] || { echo "4K certificate file not found: $srun4k_cert_file" >&2; exit 2; }
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
  local percent=$((stage_index * 100 / 11))
  printf '\n[%d/11 %3d%%] %s\n' "$stage_index" "$percent" "$current_stage"
}
random_secret() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

ip_in_172_17() {
  local target="${1:-}"
  [[ "$target" =~ ^172\.17\. ]] && return 0
  return 1
}

configure_docker_subnet_if_needed() {
  local need_remap="false"
  if [[ -n "$docker_bip" ]]; then
    need_remap="true"
  elif ip_in_172_17 "$srun4k_api_host" || ip_in_172_17 "$srun4k_db_host"; then
    need_remap="true"
    docker_bip="172.30.0.1/24"
  elif ip -4 route show | grep -qE '^172\.17\.' && ! ip -4 route show | grep -qE '^172\.17\.0\.0/16 dev docker0'; then
    need_remap="true"
    docker_bip="172.30.0.1/24"
  fi
  if [[ "$need_remap" == "true" ]]; then
    echo "检测到 172.17.0.0/16 路由/4K 网段冲突，自动将 docker0 切至 ${docker_bip}"
    mkdir -p /etc/docker
    python3 - "$docker_bip" <<'PY'
import json, pathlib, sys
bip = sys.argv[1]
path = pathlib.Path("/etc/docker/daemon.json")
data = {}
if path.exists():
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
data["bip"] = bip
data.setdefault("default-address-pools", [{"base": "172.31.0.0/16", "size": 24}])
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
  fi
}

stage "校验平台、网卡、磁盘和离线包完整性"
. /etc/os-release
[[ "$ID" == openEuler && "$(uname -m)" == x86_64 ]] || { echo "仅支持 openEuler x86_64，当前为 ${ID:-unknown} $(uname -m)" >&2; exit 1; }
ip link show "$interface" >/dev/null || { echo "采集网卡不存在：$interface" >&2; exit 1; }
avail_kb="$(df -Pk / | awk 'NR==2{print $4}')"
echo "根分区可用空间：$((avail_kb / 1024 / 1024)) GiB"
(cd "$bundle_dir" && sha256sum -c SHA256SUMS)
# shellcheck disable=SC1091
source "$bundle_dir/bundle.env"

stage "从离线包安装 Docker 与基础运行依赖"
if compgen -G "$bundle_dir/rpms/*.rpm" >/dev/null; then
  dnf install -y --disablerepo='*' "$bundle_dir"/rpms/*.rpm
else
  echo "离线包未包含 RPM 目录，校验宿主已安装 Docker"
  command -v docker >/dev/null || { echo "宿主缺少 docker" >&2; exit 1; }
fi

stage "按部署档位安装采集器（profile=${profile}）"
if [[ "$profile" == "full" && -f "$bundle_dir/collectors.tar.gz" ]]; then
  tar -C / -xzf "$bundle_dir/collectors.tar.gz"
  ldconfig
  suricata --build-info | sed -n '1,5p'
  zeek --version
else
  echo "防代理单机 HDD 轻量档位：跳过 Suricata/Zeek，仅启用内置 device-signal 镜像采集"
fi

stage "检测 Docker 网段冲突并启动容器运行时"
configure_docker_subnet_if_needed
systemctl daemon-reload
systemctl enable --now containerd.service docker.service
if [[ -n "$docker_bip" ]]; then
  systemctl restart docker.service
fi
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null || { echo "Docker 在 30 秒内未就绪" >&2; exit 1; }

stage "从离线包载入 PostgreSQL 与 ClickHouse 镜像"
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

stage "生成单机 HDD 调优配置、密钥与 4K 证书固定校验"
umask 077
runtime_input="$(mktemp /run/proxy-sentinel-airgap-env.XXXXXX)"
admin_secret="$(mktemp /run/proxy-sentinel-admin.XXXXXX)"
cleanup() { rm -f "$runtime_input" "$admin_secret"; }
trap cleanup EXIT
postgres_password="$(random_secret)"
clickhouse_password="$(random_secret)"
identity_key="$(random_secret)"
action_key="$(random_secret)"
admin_password="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')A1!"
printf '%s\n' "$admin_password" > "$admin_secret"

manage_suricata="false"
manage_zeek="false"
if [[ "$profile" == "full" ]]; then
  manage_suricata="true"
  manage_zeek="true"
fi

pinned_cert_dest=""
if [[ -n "$srun4k_cert_file" ]]; then
  mkdir -p /opt/proxy-sentinel/config
  pinned_cert_dest="/opt/proxy-sentinel/config/srun4k-pinned.pem"
  cp -f "$srun4k_cert_file" "$pinned_cert_dest"
  chmod 0600 "$pinned_cert_dest"
fi

control_port="${control_addr##*:}"
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
PROXY_SENTINEL_HEALTH_URL='http://127.0.0.1:${control_port}/readyz'
PROXY_SENTINEL_SENSOR_ID='$sensor_id'
PROXY_SENTINEL_MIRROR_INTERFACE='$interface'
PROXY_SENTINEL_READ_ONLY='$read_only'
PROXY_SENTINEL_MANAGE_SURICATA='$manage_suricata'
PROXY_SENTINEL_MANAGE_ZEEK='$manage_zeek'
PROXY_SENTINEL_MANAGE_DEVICE_SIGNALS='true'
PROXY_SENTINEL_INGEST_ENABLED='true'
PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3='true'
PROXY_SENTINEL_COMPACT_POLICY_DECISIONS='true'
PROXY_SENTINEL_DISCOVERY_ENABLED='false'
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

if [[ -n "$srun4k_api_host" ]]; then
  printf "PROXY_SENTINEL_SRUN4K_API_HOST='%s'\n" "$srun4k_api_host" >> "$runtime_input"
fi
if [[ -n "$srun4k_db_host" ]]; then
  printf "PROXY_SENTINEL_SRUN4K_DB_HOST='%s'\n" "$srun4k_db_host" >> "$runtime_input"
fi
if [[ -n "$pinned_cert_dest" ]]; then
  printf "PROXY_SENTINEL_SRUN4K_PINNED_CERT='%s'\n" "$pinned_cert_dest" >> "$runtime_input"
fi

stage "安装 Proxy Sentinel、数据库迁移和 systemd 服务"
PROXY_SENTINEL_OFFLINE=true "$bundle_dir/install-openeuler.sh" \
  --version "$BUNDLE_VERSION" \
  --archive "$bundle_dir/proxy-sentinel-$BUNDLE_VERSION.tar.gz" \
  --checksum "$bundle_dir/proxy-sentinel-$BUNDLE_VERSION.tar.gz.sha256" \
  --env-file "$runtime_input" \
  --admin-secret "$admin_secret" \
  --skip-backup

stage "收敛 ClickHouse 运维日志 TTL（防止单机 HDD 膨胀）"
if docker ps --format '{{.Names}}' | grep -qx 'proxy-sentinel-clickhouse'; then
  docker exec proxy-sentinel-clickhouse clickhouse-client --query \
    "ALTER TABLE system.query_log MODIFY TTL event_date + INTERVAL 3 DAY" >/dev/null 2>&1 || true
  docker exec proxy-sentinel-clickhouse clickhouse-client --query \
    "ALTER TABLE system.trace_log MODIFY TTL event_date + INTERVAL 3 DAY" >/dev/null 2>&1 || true
fi

stage "配置防火墙与本机访问边界"
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port="${control_port}/tcp"
  firewall-cmd --reload
fi

stage "验证核心服务、控制面就绪与 4K 网络连通性"
proxy-sentinelctl doctor || true
curl -fsS "http://127.0.0.1:${control_port}/readyz"
echo ""
if [[ -n "$srun4k_api_host" ]]; then
  echo "检查 4K API 主机路由：$(ip -4 route get "$srun4k_api_host" 2>/dev/null | head -n 1 || echo '路由不可达')"
fi
if [[ -n "$srun4k_db_host" ]]; then
  echo "检查 4K 数据库主机路由：$(ip -4 route get "$srun4k_db_host" 2>/dev/null | head -n 1 || echo '路由不可达')"
fi

stage "完成离线一键安装并输出验收摘要"
elapsed=$(( $(date +%s) - started_at ))
display_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i == "src") {print $(i+1); exit}}')"
[[ -n "$display_ip" ]] || display_ip="$(hostname -I | awk '{print $1}')"
printf '\n=== 安装完成（耗时 %ss）===\n' "$elapsed"
printf '访问地址：http://%s:%s\n' "$display_ip" "$control_port"
printf '初始管理员：admin（已生成随机初始口令，请立即登录修改；完整日志：%s）\n' "$log_file"
