#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: install-openeuler.sh --version VERSION --archive FILE --checksum FILE --env-file FILE [--admin-secret FILE]" >&2
}

version=""; archive=""; checksum=""; env_file=""; admin_secret=""; preflight_only=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --archive) archive="${2:-}"; shift 2 ;;
    --checksum) checksum="${2:-}"; shift 2 ;;
    --env-file) env_file="${2:-}"; shift 2 ;;
    --admin-secret) admin_secret="${2:-}"; shift 2 ;;
    --preflight-only) preflight_only=true; shift ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "invalid release version" >&2; exit 2; }
for file in "$archive" "$checksum" "$env_file"; do [[ -f "$file" ]] || { echo "required file is missing: $file" >&2; exit 2; }; done
[[ $(id -u) -eq 0 ]] || { echo "installer must run as root" >&2; exit 1; }

set -a
# shellcheck disable=SC1090
source "$env_file"
if [[ -r /opt/proxy-sentinel/config/control-plane-secrets.env ]]; then
  # shellcheck disable=SC1091
  source /opt/proxy-sentinel/config/control-plane-secrets.env
fi
set +a
root="${PROXY_SENTINEL_ROOT:-/opt/proxy-sentinel}"
[[ "$root" == /opt/* && "$root" != /opt ]] || { echo "unsafe PROXY_SENTINEL_ROOT: $root" >&2; exit 2; }
release_dir="$root/releases/$version"
stage_dir="$root/releases/.staging-$version"
runtime_env="$root/config/runtime.env"
compose_file="$release_dir/deploy/compose/storage.yml"
interface="${PROXY_SENTINEL_MIRROR_INTERFACE:-ens1f1}"
control_addr="${PROXY_SENTINEL_CONTROL_ADDR:-0.0.0.0:18080}"
health_url="${PROXY_SENTINEL_INSTALL_HEALTH_URL:-${PROXY_SENTINEL_HEALTH_URL:-http://127.0.0.1:18080/readyz}}"
sensor_id="${PROXY_SENTINEL_SENSOR_ID:-office-30}"
read_only="${PROXY_SENTINEL_READ_ONLY:-false}"
manage_suricata="${PROXY_SENTINEL_MANAGE_SURICATA:-true}"
manage_zeek="${PROXY_SENTINEL_MANAGE_ZEEK:-false}"
manage_device_signals="${PROXY_SENTINEL_MANAGE_DEVICE_SIGNALS:-$manage_suricata}"
ingest_enabled="${PROXY_SENTINEL_INGEST_ENABLED:-true}"
eve_path="${PROXY_SENTINEL_EVE_PATH:-/var/log/suricata/eve.json}"
zeek_log_dir="${PROXY_SENTINEL_ZEEK_LOG_DIR:-$root/data/zeek/logs/current}"
device_signal_path="${PROXY_SENTINEL_DEVICE_SIGNAL_PATH:-$root/data/device-signals/ttl.jsonl}"
device_signal_bucket="${PROXY_SENTINEL_DEVICE_SIGNAL_BUCKET:-30s}"
capture_scope_path="${PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG:-}"
collector_instance_id="${PROXY_SENTINEL_COLLECTOR_INSTANCE_ID:-}"
offline_install="${PROXY_SENTINEL_OFFLINE:-false}"
if [[ "$manage_zeek" == true ]]; then
  : "${PROXY_SENTINEL_ZEEK_DHCP_PATH:=$zeek_log_dir/dhcp.log}"
  : "${PROXY_SENTINEL_ZEEK_SOFTWARE_PATH:=$zeek_log_dir/software.log}"
  : "${PROXY_SENTINEL_ZEEK_MDNS_PATH:=$zeek_log_dir/mdns.log}"
  : "${PROXY_SENTINEL_ZEEK_NBNS_PATH:=$zeek_log_dir/nbns.log}"
  : "${PROXY_SENTINEL_ZEEK_LLMNR_PATH:=$zeek_log_dir/llmnr.log}"
  PROXY_SENTINEL_ZEEK_CONN_PATH="${PROXY_SENTINEL_ZEEK_CONN_PATH-$zeek_log_dir/conn.log}"
  : "${PROXY_SENTINEL_ZEEK_DNS_PATH:=$zeek_log_dir/dns.log}"
  : "${PROXY_SENTINEL_ZEEK_HTTP_PATH:=$zeek_log_dir/http.log}"
  : "${PROXY_SENTINEL_ZEEK_SSL_PATH:=$zeek_log_dir/ssl.log}"
  : "${PROXY_SENTINEL_ZEEK_X509_PATH:=$zeek_log_dir/x509.log}"
  : "${PROXY_SENTINEL_ZEEK_LLDP_PATH:=$zeek_log_dir/lldp.log}"
  : "${PROXY_SENTINEL_ZEEK_SSDP_PATH:=$zeek_log_dir/ssdp.log}"
  export PROXY_SENTINEL_ZEEK_DHCP_PATH PROXY_SENTINEL_ZEEK_SOFTWARE_PATH PROXY_SENTINEL_ZEEK_MDNS_PATH PROXY_SENTINEL_ZEEK_NBNS_PATH PROXY_SENTINEL_ZEEK_LLMNR_PATH
  export PROXY_SENTINEL_ZEEK_CONN_PATH PROXY_SENTINEL_ZEEK_DNS_PATH PROXY_SENTINEL_ZEEK_HTTP_PATH PROXY_SENTINEL_ZEEK_SSL_PATH PROXY_SENTINEL_ZEEK_X509_PATH PROXY_SENTINEL_ZEEK_LLDP_PATH PROXY_SENTINEL_ZEEK_SSDP_PATH
fi
ingest_source_args="--eve $eve_path"
shadow_zeek_args=""

log() { echo "[proxy-sentinel deploy] $*"; }
die() { echo "[proxy-sentinel deploy] $*" >&2; exit 1; }
on_error() {
  local status=$? line="${BASH_LINENO[0]:-unknown}" command="${BASH_COMMAND:-unknown}"
  trap - ERR
  echo "[proxy-sentinel deploy] failed: line=$line exit=$status command=$command" >&2
  exit "$status"
}
trap on_error ERR
require_value() { [[ -n "${!1:-}" && "${!1}" != replace-* ]] || die "$1 is required"; }
random_secret() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
append_ingest_source() {
  local variable="$1" flag="$2" path="${!1:-}"
  [[ -z "$path" ]] && return
  [[ "$path" =~ ^/[A-Za-z0-9._/:+-]+$ ]] || die "$variable must be a safe absolute path"
  ingest_source_args+=" $flag $path"
}

pin_legacy_image() {
  local variable="$1" container="$2" image="${!1:-}"
  if [[ "$image" == *:latest && -n "$(docker ps -aq -f name="^/$container$")" ]]; then
    local repo digest
    repo="${image%:latest}"
    digest="$(docker image inspect "$(docker inspect -f '{{.Image}}' "$container")" --format '{{join .RepoDigests "\n"}}' | head -n 1)"
    [[ "$digest" == *@sha256:* ]] || die "cannot resolve immutable digest for legacy image $image"
    printf -v "$variable" '%s@%s' "$repo" "${digest##*@}"
    export "$variable"
    log "converted legacy $variable latest reference to its running digest"
  fi
}

preflight() {
  . /etc/os-release
  [[ "$ID" == "openEuler" ]] || die "only openEuler is supported, found $ID"
  [[ "$(uname -m)" == "x86_64" ]] || die "only x86_64 is supported"
  for command in docker systemctl curl ip ss tar gzip sha256sum flock; do command -v "$command" >/dev/null || die "missing command: $command"; done
  docker info >/dev/null || die "Docker daemon is unavailable"
  systemctl --version >/dev/null || die "systemd is unavailable"
  if [[ "$manage_suricata" == true ]]; then
    ip link show "$interface" >/dev/null || die "mirror interface does not exist: $interface"
  fi
  if [[ "$manage_zeek" == true ]]; then
    ip link show "$interface" >/dev/null || die "mirror interface does not exist: $interface"
  fi
  [[ -r /proc/sys/net/core/rmem_max ]] || die "required network kernel sysctls are unavailable"
  pin_legacy_image POSTGRES_IMAGE proxy-sentinel-postgres
  pin_legacy_image CLICKHOUSE_IMAGE proxy-sentinel-clickhouse
  for name in POSTGRES_IMAGE CLICKHOUSE_IMAGE POSTGRES_PASSWORD CLICKHOUSE_PASSWORD PROXY_SENTINEL_POSTGRES_DSN PROXY_SENTINEL_CLICKHOUSE_DSN; do require_value "$name"; done
  if [[ -z "${PROXY_SENTINEL_IDENTITY_INGEST_KEY:-}" ]]; then PROXY_SENTINEL_IDENTITY_INGEST_KEY="$(random_secret)"; export PROXY_SENTINEL_IDENTITY_INGEST_KEY; fi
  if [[ -z "${PROXY_SENTINEL_ACTION_MASTER_KEY:-}" ]]; then PROXY_SENTINEL_ACTION_MASTER_KEY="$(random_secret)"; export PROXY_SENTINEL_ACTION_MASTER_KEY; fi
  if [[ "$offline_install" == true ]]; then
    for name in POSTGRES_IMAGE_ID CLICKHOUSE_IMAGE_ID POSTGRES_IMAGE_SOURCE_DIGEST CLICKHOUSE_IMAGE_SOURCE_DIGEST; do require_value "$name"; done
    [[ "$POSTGRES_IMAGE" =~ ^srun-docker\.pkg\.coding\.net/.+:airgap-[a-f0-9]{64}$ ]] || die "POSTGRES_IMAGE must use the verified airgap digest tag"
    [[ "$CLICKHOUSE_IMAGE" =~ ^srun-docker\.pkg\.coding\.net/.+:airgap-[a-f0-9]{64}$ ]] || die "CLICKHOUSE_IMAGE must use the verified airgap digest tag"
    [[ "$POSTGRES_IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ && "$CLICKHOUSE_IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]] || die "offline image IDs are invalid"
    [[ "$POSTGRES_IMAGE_SOURCE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ && "$CLICKHOUSE_IMAGE_SOURCE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || die "offline source digests are invalid"
  else
    [[ "$POSTGRES_IMAGE" =~ ^srun-docker\.pkg\.coding\.net/.+@sha256:[a-f0-9]{64}$ ]] || die "POSTGRES_IMAGE must be a digest-pinned Coding image"
    [[ "$CLICKHOUSE_IMAGE" =~ ^srun-docker\.pkg\.coding\.net/.+@sha256:[a-f0-9]{64}$ ]] || die "CLICKHOUSE_IMAGE must be a digest-pinned Coding image"
    [[ "$POSTGRES_IMAGE$CLICKHOUSE_IMAGE" != *latest* ]] || die "latest image references are forbidden"
  fi
  [[ "$read_only" == true || "$read_only" == false ]] || die "PROXY_SENTINEL_READ_ONLY must be true or false"
  [[ "$manage_suricata" == true || "$manage_suricata" == false ]] || die "PROXY_SENTINEL_MANAGE_SURICATA must be true or false"
  [[ "$manage_zeek" == true || "$manage_zeek" == false ]] || die "PROXY_SENTINEL_MANAGE_ZEEK must be true or false"
  [[ "$manage_device_signals" == true || "$manage_device_signals" == false ]] || die "PROXY_SENTINEL_MANAGE_DEVICE_SIGNALS must be true or false"
  [[ "$ingest_enabled" == true || "$ingest_enabled" == false ]] || die "PROXY_SENTINEL_INGEST_ENABLED must be true or false"
  [[ "$offline_install" == true || "$offline_install" == false ]] || die "PROXY_SENTINEL_OFFLINE must be true or false"
  [[ "$sensor_id" =~ ^[A-Za-z0-9._-]+$ && "$interface" =~ ^[A-Za-z0-9._:-]+$ ]] || die "unsafe sensor or interface value"
	[[ "$device_signal_bucket" =~ ^[1-9][0-9]*s$ ]] || die "PROXY_SENTINEL_DEVICE_SIGNAL_BUCKET must be a positive second duration"
	[[ -z "$collector_instance_id" || "$collector_instance_id" =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe PROXY_SENTINEL_COLLECTOR_INSTANCE_ID"
	if [[ -n "$capture_scope_path" ]]; then
		[[ "$capture_scope_path" =~ ^/[A-Za-z0-9._/:+-]+$ && -f "$capture_scope_path" ]] || die "PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG must be a readable safe absolute file"
		[[ -n "$collector_instance_id" ]] || die "PROXY_SENTINEL_COLLECTOR_INSTANCE_ID is required with a capture scope"
		ingest_source_args+=" --capture-scope-config $capture_scope_path --collector-instance-id $collector_instance_id"
	fi
  [[ "$control_addr" =~ ^[A-Za-z0-9.:-]+$ ]] || die "unsafe control address"
  [[ "$eve_path" =~ ^/[A-Za-z0-9._/:+-]+$ ]] || die "PROXY_SENTINEL_EVE_PATH must be a safe absolute path"
  append_ingest_source PROXY_SENTINEL_ZEEK_DHCP_PATH --zeek-dhcp
  append_ingest_source PROXY_SENTINEL_ZEEK_SOFTWARE_PATH --zeek-software
  append_ingest_source PROXY_SENTINEL_ZEEK_MDNS_PATH --zeek-mdns
  append_ingest_source PROXY_SENTINEL_ZEEK_NBNS_PATH --zeek-nbns
  append_ingest_source PROXY_SENTINEL_ZEEK_LLMNR_PATH --zeek-llmnr
  append_ingest_source PROXY_SENTINEL_ZEEK_TTL_PATH --zeek-ttl
  append_ingest_source PROXY_SENTINEL_ZEEK_CONN_PATH --zeek-conn
  append_ingest_source PROXY_SENTINEL_ZEEK_DNS_PATH --zeek-dns
  append_ingest_source PROXY_SENTINEL_ZEEK_HTTP_PATH --zeek-http
  append_ingest_source PROXY_SENTINEL_ZEEK_SSL_PATH --zeek-ssl
  append_ingest_source PROXY_SENTINEL_ZEEK_X509_PATH --zeek-x509
  append_ingest_source PROXY_SENTINEL_ZEEK_LLDP_PATH --zeek-lldp
  append_ingest_source PROXY_SENTINEL_ZEEK_SSDP_PATH --zeek-ssdp
  if [[ "$manage_device_signals" == true ]]; then
    PROXY_SENTINEL_DEVICE_SIGNAL_PATH="$device_signal_path"
    export PROXY_SENTINEL_DEVICE_SIGNAL_PATH
    append_ingest_source PROXY_SENTINEL_DEVICE_SIGNAL_PATH --device-signals
  fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_DHCP_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-dhcp $PROXY_SENTINEL_ZEEK_DHCP_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_SOFTWARE_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-software $PROXY_SENTINEL_ZEEK_SOFTWARE_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_CONN_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-conn $PROXY_SENTINEL_ZEEK_CONN_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_DNS_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-dns $PROXY_SENTINEL_ZEEK_DNS_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_HTTP_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-http $PROXY_SENTINEL_ZEEK_HTTP_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_SSL_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-ssl $PROXY_SENTINEL_ZEEK_SSL_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_X509_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-x509 $PROXY_SENTINEL_ZEEK_X509_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_LLDP_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-lldp $PROXY_SENTINEL_ZEEK_LLDP_PATH"; fi
  if [[ -n "${PROXY_SENTINEL_ZEEK_SSDP_PATH:-}" ]]; then shadow_zeek_args+=" --zeek-ssdp $PROXY_SENTINEL_ZEEK_SSDP_PATH"; fi
  (cd "$(dirname "$archive")" && sha256sum -c "$(basename "$checksum")")
  tar -tzf "$archive" >/dev/null
  [[ ! -e "$release_dir" && ! -e "$stage_dir" ]] || die "release version already exists: $version"
  local free_kb database_kb minimum_kb
  if [[ -e "$root" ]]; then
    free_kb="$(df -Pk "$root" | awk 'NR==2 {print $4}')"
  else
    free_kb="$(df -Pk /opt | awk 'NR==2 {print $4}')"
  fi
  database_kb=0
  if [[ -d "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}" ]]; then database_kb="$({ du -sk "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}" 2>/dev/null || true; } | awk 'NR==1 {print $1}')"; fi
  database_kb="${database_kb:-0}"
  minimum_kb="${PROXY_SENTINEL_MIN_FREE_KB:-5242880}"
  (( free_kb > minimum_kb + database_kb )) || die "insufficient disk: free=${free_kb}KB required>$((minimum_kb + database_kb))KB"
  local postgres_port="${POSTGRES_HOST_PORT:-25432}" clickhouse_port="${CLICKHOUSE_HTTP_HOST_PORT:-28123}" control_port="${control_addr##*:}"
  if ss -ltnH "sport = :$postgres_port" | grep -q . && ! docker ps --format '{{.Names}}' | grep -qx proxy-sentinel-postgres; then die "PostgreSQL port $postgres_port is occupied"; fi
  if ss -ltnH "sport = :$clickhouse_port" | grep -q . && ! docker ps --format '{{.Names}}' | grep -qx proxy-sentinel-clickhouse; then die "ClickHouse port $clickhouse_port is occupied"; fi
  if ss -ltnH "sport = :$control_port" | grep -q . && ! systemctl is-active --quiet proxy-sentinel-control-plane.service; then die "control-plane port $control_port is occupied"; fi
}

has_compose() {
  docker compose version >/dev/null 2>&1
}

start_storage_direct() {
  log "Docker Compose v2 is unavailable; using the compatible single-host Docker runtime"
  mkdir -p "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}/postgres" \
    "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}/clickhouse/data" \
    "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}/clickhouse/logs"
  for container in proxy-sentinel-postgres proxy-sentinel-clickhouse; do
    if docker inspect "$container" >/dev/null 2>&1; then docker rm -f "$container" >/dev/null; fi
  done
  docker run -d --name proxy-sentinel-postgres --restart unless-stopped \
    --log-driver json-file --log-opt max-size=20m --log-opt max-file=5 \
    -e POSTGRES_DB -e POSTGRES_USER -e POSTGRES_PASSWORD -e PGDATA=/var/lib/postgresql/data/pgdata \
    -p "127.0.0.1:${POSTGRES_HOST_PORT:-25432}:5432" \
    -v "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}/postgres:/var/lib/postgresql/data" \
    --health-cmd='pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' --health-interval=10s --health-timeout=5s --health-retries=12 \
    "$POSTGRES_IMAGE" >/dev/null
  docker run -d --name proxy-sentinel-clickhouse --restart unless-stopped \
    --log-driver json-file --log-opt max-size=20m --log-opt max-file=5 \
    -e CLICKHOUSE_DB -e CLICKHOUSE_USER -e CLICKHOUSE_PASSWORD -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    -p "127.0.0.1:${CLICKHOUSE_HTTP_HOST_PORT:-28123}:8123" \
    -p "127.0.0.1:${CLICKHOUSE_NATIVE_HOST_PORT:-29000}:9000" \
    -v "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}/clickhouse/data:/var/lib/clickhouse" \
    -v "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}/clickhouse/logs:/var/log/clickhouse-server" \
    --ulimit nofile=262144:262144 \
    --health-cmd='clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT 1"' \
    --health-interval=10s --health-timeout=5s --health-retries=18 \
    "$CLICKHOUSE_IMAGE" >/dev/null
}

start_storage() {
  if has_compose; then
    docker compose --env-file "$runtime_env" -f "$stage_dir/deploy/compose/storage.yml" config --quiet
    docker compose --env-file "$runtime_env" -f "$stage_dir/deploy/compose/storage.yml" up -d
  else
    start_storage_direct
  fi
}

pull_images() {
  if [[ "$offline_install" == true ]]; then
    log "verifying storage images loaded from the offline bundle"
    local actual_id
    actual_id="$(docker image inspect "$POSTGRES_IMAGE" --format '{{.Id}}' 2>/dev/null)" || die "offline PostgreSQL image is missing: $POSTGRES_IMAGE"
    [[ "$actual_id" == "$POSTGRES_IMAGE_ID" ]] || die "offline PostgreSQL image ID mismatch: expected=$POSTGRES_IMAGE_ID actual=$actual_id"
    actual_id="$(docker image inspect "$CLICKHOUSE_IMAGE" --format '{{.Id}}' 2>/dev/null)" || die "offline ClickHouse image is missing: $CLICKHOUSE_IMAGE"
    [[ "$actual_id" == "$CLICKHOUSE_IMAGE_ID" ]] || die "offline ClickHouse image ID mismatch: expected=$CLICKHOUSE_IMAGE_ID actual=$actual_id"
    return
  fi
  log "authenticating and verifying immutable storage images"
  if [[ -n "${CODING_REGISTRY_USERNAME:-}" && -n "${CODING_REGISTRY_PASSWORD:-}" && "$CODING_REGISTRY_USERNAME$CODING_REGISTRY_PASSWORD" != *replace-* ]]; then
    printf '%s' "$CODING_REGISTRY_PASSWORD" | docker login "${CODING_REGISTRY:-srun-docker.pkg.coding.net}" --username "$CODING_REGISTRY_USERNAME" --password-stdin >/dev/null
  fi
  for image in "$POSTGRES_IMAGE" "$CLICKHOUSE_IMAGE"; do
    docker pull "$image" >/dev/null
    local digest="${image##*@}"
    docker image inspect "$image" --format '{{join .RepoDigests "\n"}}' | grep -Fq "@$digest" || die "pulled image digest mismatch: $image"
  done
}

wait_storage() {
  for container in proxy-sentinel-postgres proxy-sentinel-clickhouse; do
    for _ in $(seq 1 45); do
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
      [[ "$status" == healthy || "$status" == running ]] && break
      sleep 2
    done
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
    [[ "$status" == healthy || "$status" == running ]] || die "$container failed to become healthy"
  done
}

preflight
pull_images
if [[ "$preflight_only" == true ]]; then
  log "preflight completed; current release was not modified"
  exit 0
fi
mkdir -p "$root/releases" "$root/config" "$root/data/shadow/evaluation" "$root/data/device-fingerprints" "$root/data/device-signals" "$root/data/applications" "$root/backups"
chmod 0700 "$root/config" "$root/backups"
mkdir "$stage_dir"
trap 'rm -rf "$stage_dir"' EXIT
tar -C "$stage_dir" -xzf "$archive"
(cd "$stage_dir" && sha256sum -c SHA256SUMS >/dev/null)
chmod 0755 "$stage_dir/bin/proxy-sentinel" "$stage_dir/scripts/proxy-sentinelctl"

had_storage=false
if docker inspect proxy-sentinel-postgres proxy-sentinel-clickhouse >/dev/null 2>&1; then had_storage=true; fi
if [[ "$had_storage" == true ]]; then
  log "creating logical database backup before migration"
  PROXY_SENTINEL_ROOT="$root" PROXY_SENTINEL_ENV_FILE="$env_file" PROXY_SENTINEL_COMPOSE_FILE="$stage_dir/deploy/compose/storage.yml" "$stage_dir/scripts/proxy-sentinelctl" backup >/dev/null
fi

grep -Ev '^(CODING_REGISTRY_(USERNAME|PASSWORD)|POSTGRES_IMAGE|CLICKHOUSE_IMAGE|PROXY_SENTINEL_(IDENTITY_INGEST_KEY|ACTION_MASTER_KEY|SENSOR_ID|MIRROR_INTERFACE|CONTROL_ADDR|READ_ONLY|MANAGE_SURICATA|MANAGE_ZEEK|MANAGE_DEVICE_SIGNALS|INGEST_ENABLED|EVE_PATH|ZEEK_LOG_DIR|DEVICE_SIGNAL_PATH|OFFLINE))=' "$env_file" > "$root/config/runtime.env.next"
printf "POSTGRES_IMAGE='%s'\nCLICKHOUSE_IMAGE='%s'\nPROXY_SENTINEL_IDENTITY_INGEST_KEY='%s'\nPROXY_SENTINEL_ACTION_MASTER_KEY='%s'\nPROXY_SENTINEL_SENSOR_ID='%s'\nPROXY_SENTINEL_MIRROR_INTERFACE='%s'\nPROXY_SENTINEL_CONTROL_ADDR='%s'\nPROXY_SENTINEL_READ_ONLY='%s'\nPROXY_SENTINEL_MANAGE_SURICATA='%s'\nPROXY_SENTINEL_MANAGE_ZEEK='%s'\nPROXY_SENTINEL_MANAGE_DEVICE_SIGNALS='%s'\nPROXY_SENTINEL_INGEST_ENABLED='%s'\nPROXY_SENTINEL_EVE_PATH='%s'\nPROXY_SENTINEL_ZEEK_LOG_DIR='%s'\nPROXY_SENTINEL_DEVICE_SIGNAL_PATH='%s'\nPROXY_SENTINEL_OFFLINE='%s'\n" \
  "$POSTGRES_IMAGE" "$CLICKHOUSE_IMAGE" "$PROXY_SENTINEL_IDENTITY_INGEST_KEY" "$PROXY_SENTINEL_ACTION_MASTER_KEY" \
  "$sensor_id" "$interface" "$control_addr" "$read_only" "$manage_suricata" "$manage_zeek" "$manage_device_signals" "$ingest_enabled" "$eve_path" "$zeek_log_dir" "$device_signal_path" "$offline_install" >> "$root/config/runtime.env.next"
chmod 0600 "$root/config/runtime.env.next"
mv -f "$root/config/runtime.env.next" "$runtime_env"

log "starting digest-pinned PostgreSQL and ClickHouse"
start_storage
wait_storage

log "applying forward-compatible migrations before application switch"
PROXY_SENTINEL_STORAGE_MODE=db "$stage_dir/bin/proxy-sentinel" migrate \
  --postgres-dir "$stage_dir/migrations/postgres" \
  --clickhouse-dir "$stage_dir/migrations/clickhouse" \
  --timeout "${PROXY_SENTINEL_MIGRATION_TIMEOUT:-2h}" >/dev/null
completed_backfills="$(docker exec proxy-sentinel-postgres sh -c 'psql -Atq -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT count(*) FROM application_read_model_backfills WHERE status='"'"'completed'"'"' AND name IN ('"'"'latest-observations-v1'"'"','"'"'normalized-event-features-v1'"'"','"'"'activity-chart-buckets-v2'"'"','"'"'application-observation-buckets-v2'"'"')"')"
if [[ "${PROXY_SENTINEL_RUN_LEGACY_BACKFILL:-false}" == true && "$completed_backfills" != 4 ]]; then
  log "preparing historical statistics read models"
  PROXY_SENTINEL_STORAGE_MODE=db "$stage_dir/bin/proxy-sentinel" migrate \
    --postgres-dir "$stage_dir/migrations/postgres" \
    --clickhouse-dir "$stage_dir/migrations/clickhouse" \
    --backfill-application-read-model \
    --timeout "${PROXY_SENTINEL_MIGRATION_TIMEOUT:-2h}" >/dev/null
elif [[ "$completed_backfills" == 4 ]]; then
  log "historical statistics read models are already complete; skipping synchronous backfill"
else
  log "legacy historical backfill is disabled; bounded v3 models start at cutover"
fi

admin_count="$(docker exec proxy-sentinel-postgres sh -c 'psql -Atq -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT count(*) FROM local_users"')"
if [[ "$admin_count" == 0 ]]; then
  [[ -r "$admin_secret" ]] || die "initial administrator secret was not provided"
  admin_password="$(head -n 1 "$admin_secret")"
  [[ "$admin_password" == 'Srun@4000' || ${#admin_password} -ge 12 ]] || die "initial administrator password is invalid"
  PROXY_SENTINEL_ADMIN_PASSWORD="$admin_password" "$stage_dir/bin/proxy-sentinel" control-plane bootstrap-admin --username "${PROXY_SENTINEL_ADMIN_USERNAME:-admin}" --name "${PROXY_SENTINEL_ADMIN_DISPLAY_NAME:-系统管理员}" >/dev/null
  unset admin_password PROXY_SENTINEL_ADMIN_PASSWORD
fi
rm -f "$admin_secret" 2>/dev/null || true

mv "$stage_dir" "$release_dir"
trap - EXIT
cat > "$release_dir/deployment-manifest.json" <<EOF
{"version":"$version","installed_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","postgres_image":"$POSTGRES_IMAGE","postgres_version":"${POSTGRES_IMAGE_VERSION:-unknown}","clickhouse_image":"$CLICKHOUSE_IMAGE","clickhouse_version":"${CLICKHOUSE_IMAGE_VERSION:-unknown}"}
EOF

unit_backup="$(mktemp -d /tmp/proxy-sentinel-units.XXXXXX)"
old_target="$(readlink -f "$root/current" 2>/dev/null || true)"
if [[ "$old_target" == "$root/current" || "$old_target" != "$root/releases/"* || ! -d "$old_target" ]]; then
  old_target=""
fi
for unit in proxy-sentinel-control-plane.service proxy-sentinel-ingest.service proxy-sentinel-risk-materializer.service proxy-sentinel-device-signal.service proxy-sentinel-shadow.service proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.service proxy-sentinel-shadow-evaluation.timer proxy-sentinel-suricata.service proxy-sentinel-zeek.service proxy-sentinel-logrotate.service proxy-sentinel-logrotate.timer proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service proxy-sentinel-application-materializer.service; do
  [[ -f "/etc/systemd/system/$unit" ]] && cp -a "/etc/systemd/system/$unit" "$unit_backup/$unit"
done
rollback_install() {
  log "health check failed; rolling application and systemd units back"
  systemctl stop proxy-sentinel-control-plane.service proxy-sentinel-ingest.service proxy-sentinel-risk-materializer.service \
    proxy-sentinel-device-signal.service proxy-sentinel-suricata.service proxy-sentinel-zeek.service \
    proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service \
    proxy-sentinel-recognition-materializer.service proxy-sentinel-application-materializer.service >/dev/null 2>&1 || true
  if [[ -n "$old_target" ]]; then ln -sfn "$old_target" "$root/current.next"; mv -Tf "$root/current.next" "$root/current"; else rm -f "$root/current"; fi
  for unit in proxy-sentinel-control-plane.service proxy-sentinel-ingest.service proxy-sentinel-risk-materializer.service proxy-sentinel-device-signal.service proxy-sentinel-shadow.service proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.service proxy-sentinel-shadow-evaluation.timer proxy-sentinel-suricata.service proxy-sentinel-zeek.service proxy-sentinel-logrotate.service proxy-sentinel-logrotate.timer proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service proxy-sentinel-application-materializer.service; do
    if [[ -f "$unit_backup/$unit" ]]; then cp -a "$unit_backup/$unit" "/etc/systemd/system/$unit"; else rm -f "/etc/systemd/system/$unit"; fi
  done
  systemctl daemon-reload
  if [[ "$manage_suricata" == true ]]; then systemctl start proxy-sentinel-suricata.service proxy-sentinel-logrotate.timer >/dev/null 2>&1 || true; fi
  if [[ "$manage_zeek" == true ]]; then systemctl start proxy-sentinel-zeek.service >/dev/null 2>&1 || true; fi
  if [[ "$manage_device_signals" == true ]]; then systemctl start proxy-sentinel-device-signal.service >/dev/null 2>&1 || true; fi
  if [[ "$ingest_enabled" == true ]]; then systemctl restart proxy-sentinel-ingest.service >/dev/null 2>&1 || true; fi
  systemctl start proxy-sentinel-risk-materializer.service proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.timer >/dev/null 2>&1 || true
  systemctl restart proxy-sentinel-control-plane.service >/dev/null 2>&1 || true
}
trap rollback_install ERR

if [[ -n "$old_target" ]]; then ln -sfn "$old_target" "$root/previous.next"; mv -Tf "$root/previous.next" "$root/previous"; fi
ln -sfn "$release_dir" "$root/current.next"
mv -Tf "$root/current.next" "$root/current"

cat > /etc/systemd/system/proxy-sentinel-control-plane.service <<EOF
[Unit]
Description=Proxy Sentinel production control plane
After=network-online.target docker.service
Wants=network-online.target docker.service
[Service]
Type=simple
WorkingDirectory=$root/current
EnvironmentFile=$runtime_env
ExecStart=$root/current/bin/proxy-sentinel control-plane serve --addr $control_addr --shadow-dir $root/data/shadow --sensor-id $sensor_id --frontend-dir $root/current/frontend/dist --storage-mode db --read-only=$read_only --applications-dir $root/data/applications --device-fingerprint-dir $root/data/device-fingerprints --device-fingerprint-auto-update=false --postgres-migrations-dir $root/current/migrations/postgres
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF

for unit in proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service proxy-sentinel-application-materializer.service; do
  sed "s#/opt/proxy-sentinel#$root#g" "$release_dir/deploy/systemd/$unit" > "/etc/systemd/system/$unit"
done

if [[ "$ingest_enabled" == true ]]; then
  mkdir -p "$(dirname "$eve_path")"
  [[ -e "$eve_path" ]] || install -m 0640 /dev/null "$eve_path"
  cat > /etc/systemd/system/proxy-sentinel-ingest.service <<EOF
[Unit]
Description=Proxy Sentinel realtime normalized-event ingest
After=network-online.target docker.service proxy-sentinel-suricata.service proxy-sentinel-zeek.service
Wants=network-online.target docker.service
[Service]
Type=simple
WorkingDirectory=$root/current
EnvironmentFile=$runtime_env
ExecStart=$root/current/bin/proxy-sentinel ingest run --sensor-id $sensor_id $ingest_source_args --poll-interval ${PROXY_SENTINEL_INGEST_POLL_INTERVAL:-2s} --max-batch-bytes ${PROXY_SENTINEL_INGEST_MAX_BATCH_BYTES:-8388608} --store-timeout ${PROXY_SENTINEL_INGEST_STORE_TIMEOUT:-2m} --heartbeat-interval ${PROXY_SENTINEL_INGEST_HEARTBEAT_INTERVAL:-30s}
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$root/data $(dirname "$eve_path")
[Install]
WantedBy=multi-user.target
EOF
fi

cat > /etc/systemd/system/proxy-sentinel-risk-materializer.service <<EOF
[Unit]
Description=Proxy Sentinel one-minute rolling risk materializer
After=network-online.target docker.service proxy-sentinel-ingest.service
Wants=network-online.target docker.service
[Service]
Type=simple
WorkingDirectory=$root/current
EnvironmentFile=$runtime_env
ExecStart=$root/current/bin/proxy-sentinel risk materialize --sensor-id $sensor_id --window 10m --interval 1m --event-limit ${PROXY_SENTINEL_RISK_EVENT_LIMIT:-200000}
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/proxy-sentinel-shadow.service <<EOF
[Unit]
Description=Proxy Sentinel shadow risk analysis
After=docker.service
Wants=docker.service
[Service]
Type=oneshot
WorkingDirectory=$root/current
EnvironmentFile=$runtime_env
ExecStart=$root/current/bin/proxy-sentinel shadow run --eve $eve_path$shadow_zeek_args --state $root/data/shadow/state.json --out-dir $root/data/shadow --sensor-id $sensor_id --window 10m --min-level suspicious --limit 50 --retention 168h --storage-mode db
EOF
cat > /etc/systemd/system/proxy-sentinel-shadow.timer <<EOF
[Unit]
Description=Run Proxy Sentinel shadow analysis every 10 minutes
[Timer]
OnActiveSec=2min
OnUnitActiveSec=10min
Persistent=true
Unit=proxy-sentinel-shadow.service
[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/proxy-sentinel-shadow-evaluation.service <<EOF
[Unit]
Description=Proxy Sentinel shadow validation report
After=proxy-sentinel-shadow.service
[Service]
Type=oneshot
WorkingDirectory=$root/current
EnvironmentFile=$runtime_env
ExecStart=$root/current/bin/proxy-sentinel evaluate shadow --shadow-dir $root/data/shadow --required-days 7 --samples-per-level 10 --daily-export-dir $root/data/shadow/review-exports --output $root/data/shadow/evaluation/latest.json
EOF
cat > /etc/systemd/system/proxy-sentinel-shadow-evaluation.timer <<EOF
[Unit]
Description=Refresh Proxy Sentinel shadow validation hourly
[Timer]
OnCalendar=*-*-* *:05:00
Persistent=true
Unit=proxy-sentinel-shadow-evaluation.service
[Install]
WantedBy=timers.target
EOF

if [[ "$manage_suricata" == true ]]; then
  command -v suricata >/dev/null || die "Suricata is required when PROXY_SENTINEL_MANAGE_SURICATA=true"
  mkdir -p /var/log/suricata /var/lib/suricata/rules
  [[ -s "$release_dir/assets/suricata/proxy-sentinel.rules" ]] || die "release contains no Suricata rule pack"
  install -m 0644 "$release_dir/assets/suricata/proxy-sentinel.rules" /var/lib/suricata/rules/suricata.rules
  rule_count="$(grep -Ec '^[[:space:]]*(alert|drop|reject|pass)[[:space:]]' /var/lib/suricata/rules/suricata.rules || true)"
  (( rule_count > 0 )) || die "Suricata rule count is zero"
  sed -ri 's/^([[:space:]]*)#[[:space:]]*ja3-fingerprints:[[:space:]].*/\1ja3-fingerprints: yes/' /etc/suricata/suricata.yaml
  # Mirror ports and virtual NICs commonly expose pre-offload packets with an
  # unfinished checksum. Stream checksum rejection would skip rule inspection
  # even though the transmitted frame is valid after NIC offload.
  sed -ri 's/^  checksum-validation:[[:space:]]*yes([[:space:]]*#.*)?$/  checksum-validation: no\1/' /etc/suricata/suricata.yaml
  suricata -T -c /etc/suricata/suricata.yaml >/tmp/proxy-sentinel-suricata-test.log 2>&1 || { cat /tmp/proxy-sentinel-suricata-test.log >&2; die "Suricata configuration or bundled rules failed validation"; }
  cat > /etc/systemd/system/proxy-sentinel-suricata.service <<EOF
[Unit]
Description=Proxy Sentinel Suricata mirror capture
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$(command -v suricata) -c /etc/suricata/suricata.yaml -i $interface -l /var/log/suricata --pidfile /run/proxy-sentinel-suricata.pid
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/logrotate.d/proxy-sentinel-suricata <<EOF
$eve_path {
  hourly
  size ${PROXY_SENTINEL_EVE_ROTATE_SIZE:-1G}
  rotate ${PROXY_SENTINEL_EVE_ROTATE_COUNT:-4}
  missingok
  compress
  delaycompress
  notifempty
  create 0640 root root
  sharedscripts
  postrotate
    /usr/bin/systemctl kill -s HUP proxy-sentinel-suricata.service >/dev/null 2>&1 || true
  endscript
}
EOF
  cat > /etc/systemd/system/proxy-sentinel-logrotate.service <<EOF
[Unit]
Description=Rotate Proxy Sentinel Suricata EVE log
[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate --state $root/data/logrotate.state /etc/logrotate.d/proxy-sentinel-suricata /etc/logrotate.d/proxy-sentinel-device-signals
EOF
  cat > /etc/systemd/system/proxy-sentinel-logrotate.timer <<EOF
[Unit]
Description=Check Proxy Sentinel EVE rotation hourly
[Timer]
OnCalendar=hourly
Persistent=true
Unit=proxy-sentinel-logrotate.service
[Install]
WantedBy=timers.target
EOF
fi

if [[ "$manage_device_signals" == true ]]; then
  mkdir -p "$(dirname "$device_signal_path")"
  touch "$device_signal_path"
  chmod 0640 "$device_signal_path"
  cat > /etc/logrotate.d/proxy-sentinel-device-signals <<EOF
$device_signal_path {
  hourly
  size ${PROXY_SENTINEL_DEVICE_SIGNAL_ROTATE_SIZE:-256M}
  rotate ${PROXY_SENTINEL_DEVICE_SIGNAL_ROTATE_COUNT:-4}
  missingok
  compress
  delaycompress
  notifempty
  create 0640 root root
  sharedscripts
  postrotate
    /usr/bin/systemctl restart proxy-sentinel-device-signal.service >/dev/null 2>&1 || true
  endscript
}
EOF
  cat > /etc/systemd/system/proxy-sentinel-device-signal.service <<EOF
[Unit]
Description=Proxy Sentinel lightweight TTL and Hop-Limit collector
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$root/current/bin/proxy-sentinel device-signal run --interface $interface --sensor-id $sensor_id --output $device_signal_path --bucket $device_signal_bucket${collector_instance_id:+ --collector-instance-id $collector_instance_id}${capture_scope_path:+ --capture-scope-config $capture_scope_path}
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
fi

[[ -s "$release_dir/assets/device-fingerprints/bootstrap.tar.gz" ]] || die "release contains no device fingerprint pack"
[[ -s "$release_dir/assets/applications/bootstrap.tar.gz" ]] || die "release contains no application bootstrap pack"
"$release_dir/bin/proxy-sentinel" device-fingerprint verify --bundle "$release_dir/assets/device-fingerprints/bootstrap.tar.gz" >/dev/null
"$release_dir/bin/proxy-sentinel" device-fingerprint install --bundle "$release_dir/assets/device-fingerprints/bootstrap.tar.gz" --dir "$root/data/device-fingerprints" >/dev/null

if [[ "$manage_zeek" == true ]]; then
  command -v zeek >/dev/null || die "Zeek is required when PROXY_SENTINEL_MANAGE_ZEEK=true"
  mkdir -p "$zeek_log_dir"
  cat > /etc/systemd/system/proxy-sentinel-zeek.service <<EOF
[Unit]
Description=Proxy Sentinel Zeek device-signal capture
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$zeek_log_dir
ExecStartPre=/usr/bin/test -w $zeek_log_dir
ExecStart=/usr/local/bin/zeek -i $interface $root/current/assets/zeek/local-device-signals.zeek policy/protocols/dhcp/software.zeek
Restart=always
RestartSec=5
TimeoutStopSec=30
[Install]
WantedBy=multi-user.target
EOF
fi

install -m 0755 "$release_dir/scripts/proxy-sentinelctl" /usr/local/bin/proxy-sentinelctl
mkdir -p /usr/local/lib/proxy-sentinel
install -m 0700 "$0" /usr/local/lib/proxy-sentinel/install-openeuler.sh
systemctl daemon-reload
if [[ "$manage_suricata" == true ]]; then systemctl enable --now proxy-sentinel-suricata.service proxy-sentinel-logrotate.timer; else systemctl disable --now proxy-sentinel-suricata.service proxy-sentinel-logrotate.timer >/dev/null 2>&1 || true; fi
if [[ "$manage_zeek" == true ]]; then systemctl enable --now proxy-sentinel-zeek.service; else systemctl disable --now proxy-sentinel-zeek.service >/dev/null 2>&1 || true; fi
if [[ "$manage_device_signals" == true ]]; then systemctl enable --now proxy-sentinel-device-signal.service; else systemctl disable --now proxy-sentinel-device-signal.service >/dev/null 2>&1 || true; fi
if [[ "$ingest_enabled" == true ]]; then systemctl enable --now proxy-sentinel-ingest.service; else systemctl disable --now proxy-sentinel-ingest.service >/dev/null 2>&1 || true; fi
systemctl disable --now proxy-sentinel-risk-materializer.service proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.timer >/dev/null 2>&1 || true
systemctl enable --now proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service proxy-sentinel-application-materializer.service proxy-sentinel-control-plane.service
# `enable --now` does not restart an already running service during an
# in-place upgrade. Restart each enabled long-running worker so no process
# keeps executing the binary from the previous release symlink.
if [[ "$manage_suricata" == true ]]; then systemctl restart proxy-sentinel-suricata.service; fi
if [[ "$manage_zeek" == true ]]; then systemctl restart proxy-sentinel-zeek.service; fi
if [[ "$manage_device_signals" == true ]]; then systemctl restart proxy-sentinel-device-signal.service; fi
if [[ "$ingest_enabled" == true ]]; then systemctl restart proxy-sentinel-ingest.service; fi
systemctl restart proxy-sentinel-read-model-realtime.service proxy-sentinel-read-model-coarse.service proxy-sentinel-recognition-materializer.service proxy-sentinel-application-materializer.service
systemctl restart proxy-sentinel-control-plane.service

for _ in $(seq 1 20); do
  if curl -fsS --max-time 3 "$health_url" >/dev/null 2>&1; then
    rm -rf "$unit_backup"
    trap - ERR
    log "release $version is healthy and active"
    exit 0
  fi
  sleep 2
done
false
