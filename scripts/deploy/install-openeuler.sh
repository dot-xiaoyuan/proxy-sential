#!/usr/bin/env bash
set -euo pipefail

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
health_url="${PROXY_SENTINEL_HEALTH_URL:-http://127.0.0.1:18080/readyz}"
sensor_id="${PROXY_SENTINEL_SENSOR_ID:-office-30}"
read_only="${PROXY_SENTINEL_READ_ONLY:-false}"
manage_suricata="${PROXY_SENTINEL_MANAGE_SURICATA:-true}"

log() { echo "[proxy-sentinel deploy] $*"; }
die() { echo "[proxy-sentinel deploy] $*" >&2; exit 1; }
require_value() { [[ -n "${!1:-}" && "${!1}" != replace-* ]] || die "$1 is required"; }
random_secret() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

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
  docker compose version >/dev/null || die "Docker Compose v2 is unavailable"
  systemctl --version >/dev/null || die "systemd is unavailable"
  ip link show "$interface" >/dev/null || die "mirror interface does not exist: $interface"
  [[ -r /proc/sys/net/core/rmem_max ]] || die "required network kernel sysctls are unavailable"
  pin_legacy_image POSTGRES_IMAGE proxy-sentinel-postgres
  pin_legacy_image CLICKHOUSE_IMAGE proxy-sentinel-clickhouse
  for name in POSTGRES_IMAGE CLICKHOUSE_IMAGE POSTGRES_PASSWORD CLICKHOUSE_PASSWORD PROXY_SENTINEL_POSTGRES_DSN PROXY_SENTINEL_CLICKHOUSE_DSN; do require_value "$name"; done
  if [[ -z "${PROXY_SENTINEL_IDENTITY_INGEST_KEY:-}" ]]; then PROXY_SENTINEL_IDENTITY_INGEST_KEY="$(random_secret)"; export PROXY_SENTINEL_IDENTITY_INGEST_KEY; fi
  if [[ -z "${PROXY_SENTINEL_ACTION_MASTER_KEY:-}" ]]; then PROXY_SENTINEL_ACTION_MASTER_KEY="$(random_secret)"; export PROXY_SENTINEL_ACTION_MASTER_KEY; fi
  [[ "$POSTGRES_IMAGE" =~ ^srun-docker\.pkg\.coding\.net/.+@sha256:[a-f0-9]{64}$ ]] || die "POSTGRES_IMAGE must be a digest-pinned Coding image"
  [[ "$CLICKHOUSE_IMAGE" =~ ^srun-docker\.pkg\.coding\.net/.+@sha256:[a-f0-9]{64}$ ]] || die "CLICKHOUSE_IMAGE must be a digest-pinned Coding image"
  [[ "$POSTGRES_IMAGE$CLICKHOUSE_IMAGE" != *latest* ]] || die "latest image references are forbidden"
  [[ "$read_only" == true || "$read_only" == false ]] || die "PROXY_SENTINEL_READ_ONLY must be true or false"
  [[ "$manage_suricata" == true || "$manage_suricata" == false ]] || die "PROXY_SENTINEL_MANAGE_SURICATA must be true or false"
  [[ "$sensor_id" =~ ^[A-Za-z0-9._-]+$ && "$interface" =~ ^[A-Za-z0-9._:-]+$ ]] || die "unsafe sensor or interface value"
  [[ "$control_addr" =~ ^[A-Za-z0-9.:-]+$ ]] || die "unsafe control address"
  (cd "$(dirname "$archive")" && sha256sum -c "$(basename "$checksum")")
  tar -tzf "$archive" >/dev/null
  [[ ! -e "$release_dir" && ! -e "$stage_dir" ]] || die "release version already exists: $version"
  local free_kb database_kb minimum_kb
  free_kb="$(df -Pk "$root" 2>/dev/null | awk 'NR==2 {print $4}')"
  if [[ -z "$free_kb" ]]; then free_kb="$(df -Pk /opt | awk 'NR==2 {print $4}')"; fi
  database_kb=0
  if [[ -d "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}" ]]; then database_kb="$(du -sk "${PROXY_SENTINEL_DATA_DIR:-$root/data/db}" | awk '{print $1}')"; fi
  minimum_kb="${PROXY_SENTINEL_MIN_FREE_KB:-5242880}"
  (( free_kb > minimum_kb + database_kb )) || die "insufficient disk: free=${free_kb}KB required>$((minimum_kb + database_kb))KB"
  local postgres_port="${POSTGRES_HOST_PORT:-25432}" clickhouse_port="${CLICKHOUSE_HTTP_HOST_PORT:-28123}" control_port="${control_addr##*:}"
  if ss -ltnH "sport = :$postgres_port" | grep -q . && ! docker ps --format '{{.Names}}' | grep -qx proxy-sentinel-postgres; then die "PostgreSQL port $postgres_port is occupied"; fi
  if ss -ltnH "sport = :$clickhouse_port" | grep -q . && ! docker ps --format '{{.Names}}' | grep -qx proxy-sentinel-clickhouse; then die "ClickHouse port $clickhouse_port is occupied"; fi
  if ss -ltnH "sport = :$control_port" | grep -q . && ! systemctl is-active --quiet proxy-sentinel-control-plane.service; then die "control-plane port $control_port is occupied"; fi
}

pull_images() {
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
mkdir -p "$root/releases" "$root/config" "$root/data/shadow" "$root/data/device-fingerprints" "$root/backups"
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

grep -Ev '^(CODING_REGISTRY_(USERNAME|PASSWORD)|POSTGRES_IMAGE|CLICKHOUSE_IMAGE|PROXY_SENTINEL_IDENTITY_INGEST_KEY|PROXY_SENTINEL_ACTION_MASTER_KEY)=' "$env_file" > "$root/config/runtime.env.next"
printf "POSTGRES_IMAGE='%s'\nCLICKHOUSE_IMAGE='%s'\nPROXY_SENTINEL_IDENTITY_INGEST_KEY='%s'\nPROXY_SENTINEL_ACTION_MASTER_KEY='%s'\n" "$POSTGRES_IMAGE" "$CLICKHOUSE_IMAGE" "$PROXY_SENTINEL_IDENTITY_INGEST_KEY" "$PROXY_SENTINEL_ACTION_MASTER_KEY" >> "$root/config/runtime.env.next"
chmod 0600 "$root/config/runtime.env.next"
mv -f "$root/config/runtime.env.next" "$runtime_env"

log "starting digest-pinned PostgreSQL and ClickHouse"
docker compose --env-file "$runtime_env" -f "$stage_dir/deploy/compose/storage.yml" config --quiet
docker compose --env-file "$runtime_env" -f "$stage_dir/deploy/compose/storage.yml" up -d
wait_storage

log "applying forward-compatible migrations before application switch"
PROXY_SENTINEL_STORAGE_MODE=db "$stage_dir/bin/proxy-sentinel" migrate --postgres-dir "$stage_dir/migrations/postgres" --clickhouse-dir "$stage_dir/migrations/clickhouse" >/dev/null

admin_count="$(docker exec proxy-sentinel-postgres sh -c 'psql -Atq -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT count(*) FROM local_users"')"
if [[ "$admin_count" == 0 ]]; then
  [[ -r "$admin_secret" ]] || die "initial administrator secret was not provided"
  admin_password="$(head -n 1 "$admin_secret")"
  [[ ${#admin_password} -ge 12 ]] || die "initial administrator password is too short"
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
for unit in proxy-sentinel-control-plane.service proxy-sentinel-shadow.service proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.service proxy-sentinel-shadow-evaluation.timer proxy-sentinel-suricata.service; do
  [[ -f "/etc/systemd/system/$unit" ]] && cp -a "/etc/systemd/system/$unit" "$unit_backup/$unit"
done
rollback_install() {
  log "health check failed; rolling application and systemd units back"
  if [[ -n "$old_target" ]]; then ln -sfn "$old_target" "$root/current.next"; mv -Tf "$root/current.next" "$root/current"; else rm -f "$root/current"; fi
  for unit in proxy-sentinel-control-plane.service proxy-sentinel-shadow.service proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.service proxy-sentinel-shadow-evaluation.timer proxy-sentinel-suricata.service; do
    if [[ -f "$unit_backup/$unit" ]]; then cp -a "$unit_backup/$unit" "/etc/systemd/system/$unit"; else rm -f "/etc/systemd/system/$unit"; fi
  done
  systemctl daemon-reload
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
ExecStart=$root/current/bin/proxy-sentinel control-plane serve --addr $control_addr --shadow-dir $root/data/shadow --sensor-id $sensor_id --frontend-dir $root/current/frontend/dist --storage-mode db --read-only=$read_only --device-fingerprint-dir $root/data/device-fingerprints --device-fingerprint-auto-update=false --postgres-migrations-dir $root/current/migrations/postgres
Restart=always
RestartSec=5
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
ExecStart=$root/current/bin/proxy-sentinel shadow run --eve /var/log/suricata/eve.json --state $root/data/shadow/state.json --out-dir $root/data/shadow --sensor-id $sensor_id --window 10m --min-level suspicious --limit 50 --retention 168h --storage-mode db
EOF
cat > /etc/systemd/system/proxy-sentinel-shadow.timer <<EOF
[Unit]
Description=Run Proxy Sentinel shadow analysis every 10 minutes
[Timer]
OnBootSec=2min
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
  [[ -f /var/lib/suricata/rules/suricata.rules ]] || install -m 0644 /dev/null /var/lib/suricata/rules/suricata.rules
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
fi

install -m 0755 "$release_dir/scripts/proxy-sentinelctl" /usr/local/bin/proxy-sentinelctl
mkdir -p /usr/local/lib/proxy-sentinel
install -m 0700 "$0" /usr/local/lib/proxy-sentinel/install-openeuler.sh
systemctl daemon-reload
if [[ "$manage_suricata" == true ]]; then systemctl enable --now proxy-sentinel-suricata.service; fi
systemctl enable --now proxy-sentinel-shadow.timer proxy-sentinel-shadow-evaluation.timer proxy-sentinel-control-plane.service
systemctl restart proxy-sentinel-control-plane.service

for _ in $(seq 1 20); do
  if curl -fsS --max-time 3 "$health_url" >/dev/null; then
    rm -rf "$unit_backup"
    trap - ERR
    log "release $version is healthy and active"
    exit 0
  fi
  sleep 2
done
false
