#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: deploy-shadow-30.sh [options]

Options:
  --host HOST            SSH host. Default: root@192.168.0.30
  --root DIR             Remote repository root. Default: /opt/proxy-sentinel
  --interface IFACE      Suricata mirror interface. Default: ens1f1
  --sensor-id ID         Proxy Sentinel sensor id. Default: office-30
  --cadence DURATION     Shadow timer cadence. Default: 10min
  --window DURATION      Evidence window. Default: 10m
  --retention DURATION   Shadow run retention. Default: 168h
  --control-addr ADDR    Control-plane listen address. Default: 0.0.0.0:18080
  --enable-review-writes Allow label and endpoint registration writes; enforcement remains shadow-only
  --enable-local-auth    Use the pre-created local RBAC user file on the server

Builds a Linux amd64 proxy-sentinel binary and frontend/dist, deploys them to
the remote host, installs systemd units, and enables Suricata capture, periodic
shadow analysis, and the read-only control-plane UI. All risk actions remain
shadow-only.
EOF
}

remote_host="root@192.168.0.30"
remote_root="/opt/proxy-sentinel"
mirror_iface="ens1f1"
sensor_id="office-30"
cadence="10min"
window="10m"
retention="168h"
control_addr="0.0.0.0:18080"
control_read_only_arg="--read-only"
enable_local_auth="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      remote_host="${2:-}"
      shift 2
      ;;
    --root)
      remote_root="${2:-}"
      shift 2
      ;;
    --interface)
      mirror_iface="${2:-}"
      shift 2
      ;;
    --sensor-id)
      sensor_id="${2:-}"
      shift 2
      ;;
    --cadence)
      cadence="${2:-}"
      shift 2
      ;;
    --window)
      window="${2:-}"
      shift 2
      ;;
    --retention)
      retention="${2:-}"
      shift 2
      ;;
    --control-addr)
      control_addr="${2:-}"
      shift 2
      ;;
    --enable-review-writes)
      control_read_only_arg="--read-only=false"
      shift
      ;;
    --enable-local-auth)
      enable_local_auth="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

control_auth_arg=""
if [[ "$enable_local_auth" == "true" ]]; then
  control_auth_arg="--auth-file $remote_root/data/auth/users.json"
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

binary="$build_dir/proxy-sentinel"
frontend_archive="$build_dir/frontend-dist.tar.gz"
migrations_archive="$build_dir/migrations.tar.gz"
(
  cd "$repo_root"
  GOOS=linux GOARCH=amd64 go build -o "$binary" ./cmd/proxy-sentinel
  (
    cd frontend
    pnpm build
  )
  COPYFILE_DISABLE=1 tar --no-xattrs -C frontend -czf "$frontend_archive" dist
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "$migrations_archive" migrations
)

ssh "$remote_host" "set -euo pipefail
cd '$remote_root'
git pull origin main
mkdir -p '$remote_root/bin' '$remote_root/data/shadow' '$remote_root/frontend' /var/log/suricata /var/lib/suricata/rules
if [[ ! -e /var/lib/suricata/rules/suricata.rules ]]; then
  : > /var/lib/suricata/rules/suricata.rules
fi
chmod 0644 /var/lib/suricata/rules/suricata.rules
"

remote_tmp="/tmp/proxy-sentinel-bin-$$"
remote_frontend_tmp="/tmp/proxy-sentinel-frontend-$$.tar.gz"
remote_migrations_tmp="/tmp/proxy-sentinel-migrations-$$.tar.gz"
scp "$binary" "$remote_host:$remote_tmp"
scp "$frontend_archive" "$remote_host:$remote_frontend_tmp"
scp "$migrations_archive" "$remote_host:$remote_migrations_tmp"
ssh "$remote_host" "set -euo pipefail
install -m 0755 '$remote_tmp' '$remote_root/bin/proxy-sentinel'
rm '$remote_tmp'
rm -rf '$remote_root/frontend/dist'
mkdir -p '$remote_root/frontend'
tar -C '$remote_root/frontend' -xzf '$remote_frontend_tmp'
rm '$remote_frontend_tmp'
chown -R root:root '$remote_root/frontend/dist'
tar -C '$remote_root' -xzf '$remote_migrations_tmp'
rm '$remote_migrations_tmp'
if [[ '$enable_local_auth' == 'true' && ! -s '$remote_root/data/auth/users.json' ]]; then
  echo 'local RBAC requested but data/auth/users.json does not exist; run control-plane bootstrap-admin first' >&2
  exit 1
fi

storage_env_line=''
storage_after_suffix=''
storage_shadow_wants_line=''
storage_control_wants_suffix=''
storage_dsn_args=''
evaluation_postgres_arg=''
zeek_shadow_arg=''
zeek_after_suffix=''
zeek_wants_line=''
zeek_bin=''
if command -v zeek >/dev/null 2>&1; then
  zeek_bin=\"\$(command -v zeek)\"
  zeek_version=\"\$(zeek --version 2>&1 | head -1 || true)\"
  if ! ip link show '$mirror_iface' >/dev/null 2>&1; then
    echo 'mirror interface $mirror_iface is not present; Zeek service will not be installed.' >&2
  else
    mkdir -p '$remote_root/data/zeek/logs/current'
    touch '$remote_root/data/zeek/logs/current/.write-test'
    rm -f '$remote_root/data/zeek/logs/current/.write-test'
    echo \"Zeek detected: \$zeek_version\"
    echo 'Zeek DHCP log directory is writable: $remote_root/data/zeek/logs/current'
  fi
fi
if [[ -n \"\$zeek_bin\" ]] && ip link show '$mirror_iface' >/dev/null 2>&1; then
  zeek_shadow_arg='--zeek-dhcp $remote_root/data/zeek/logs/current/dhcp.log --zeek-software $remote_root/data/zeek/logs/current/software.log'
  zeek_after_suffix=' proxy-sentinel-zeek.service'
  zeek_wants_line='Wants=proxy-sentinel-zeek.service'
fi
if [[ -f '$remote_root/deploy/compose/storage.env' ]]; then
  storage_env_line='EnvironmentFile=$remote_root/deploy/compose/storage.env'
  storage_after_suffix=' docker.service'
  storage_shadow_wants_line='Wants=docker.service'
  storage_control_wants_suffix=' docker.service'
  storage_dsn_args='--postgres-dsn \${PROXY_SENTINEL_POSTGRES_DSN} --clickhouse-dsn \${PROXY_SENTINEL_CLICKHOUSE_DSN}'
  evaluation_postgres_arg='--postgres-dsn \${PROXY_SENTINEL_POSTGRES_DSN}'
  (
    cd '$remote_root'
    set -a
    source deploy/compose/storage.env
    set +a
    docker compose --env-file deploy/compose/storage.env -f deploy/compose/storage.yml up -d
    for migration in migrations/postgres/*.sql; do
      docker compose --env-file deploy/compose/storage.env -f deploy/compose/storage.yml exec -T postgres \
        psql -v ON_ERROR_STOP=1 -U \"\${POSTGRES_USER:-proxy_sentinel}\" -d \"\${POSTGRES_DB:-proxy_sentinel}\" \
        < \"\$migration\"
    done
    for migration in migrations/clickhouse/*.sql; do
      docker compose --env-file deploy/compose/storage.env -f deploy/compose/storage.yml exec -T clickhouse \
        clickhouse-client --user \"\${CLICKHOUSE_USER:-proxy_sentinel}\" --password \"\${CLICKHOUSE_PASSWORD}\" \
        --database \"\${CLICKHOUSE_DB:-proxy_sentinel}\" --multiquery \
        < \"\$migration\"
    done
    '$remote_root/bin/proxy-sentinel' backfill identity \
      --postgres-dsn \"\${PROXY_SENTINEL_POSTGRES_DSN}\" \
      --clickhouse-dsn \"\${PROXY_SENTINEL_CLICKHOUSE_DSN}\" \
      --sensor-id office-30 \
      --window 7d
  )
fi

cat > /etc/systemd/system/proxy-sentinel-suricata.service <<EOF
[Unit]
Description=Proxy Sentinel Suricata mirror capture
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i $mirror_iface -l /var/log/suricata --pidfile /run/proxy-sentinel-suricata.pid
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

if [[ -n \"\$zeek_bin\" ]] && ip link show '$mirror_iface' >/dev/null 2>&1; then
cat > /etc/systemd/system/proxy-sentinel-zeek.service <<EOF
[Unit]
Description=Proxy Sentinel Zeek DHCP device fingerprint capture
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$remote_root/data/zeek/logs/current
ExecStartPre=/usr/bin/test -w $remote_root/data/zeek/logs/current
ExecStartPre=/bin/sh -c 'ip link show $mirror_iface >/dev/null'
ExecStart=\$zeek_bin -i $mirror_iface policy/protocols/dhcp/software.zeek
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
else
  rm -f /etc/systemd/system/proxy-sentinel-zeek.service
  echo 'Zeek is not installed on the remote host; skipping Zeek DHCP capture service.'
fi

cat > /etc/systemd/system/proxy-sentinel-shadow.service <<EOF
[Unit]
Description=Proxy Sentinel shadow risk analysis
After=proxy-sentinel-suricata.service\$zeek_after_suffix\$storage_after_suffix
\$zeek_wants_line
\$storage_shadow_wants_line

[Service]
Type=oneshot
WorkingDirectory=$remote_root
\$storage_env_line
ExecStart=$remote_root/bin/proxy-sentinel shadow run --eve /var/log/suricata/eve.json \$zeek_shadow_arg --state $remote_root/data/shadow/state.json --out-dir $remote_root/data/shadow --sensor-id $sensor_id --window $window --min-level suspicious --limit 50 --retention $retention --storage-mode dual \$storage_dsn_args
EOF

cat > /etc/systemd/system/proxy-sentinel-shadow.timer <<EOF
[Unit]
Description=Run Proxy Sentinel shadow risk analysis every $cadence

[Timer]
OnBootSec=2min
OnUnitActiveSec=$cadence
Persistent=true
Unit=proxy-sentinel-shadow.service

[Install]
WantedBy=timers.target
EOF

mkdir -p '$remote_root/data/shadow/evaluation' '$remote_root/data/shadow/review-exports'
cat > /etc/systemd/system/proxy-sentinel-shadow-evaluation.service <<EOF
[Unit]
Description=Proxy Sentinel daily shadow evaluation and review sample export
After=proxy-sentinel-shadow.service

[Service]
Type=oneshot
WorkingDirectory=$remote_root
\$storage_env_line
ExecStart=$remote_root/bin/proxy-sentinel evaluate shadow --shadow-dir $remote_root/data/shadow --required-days 7 --samples-per-level 10 --daily-export-dir $remote_root/data/shadow/review-exports --output $remote_root/data/shadow/evaluation/latest.json \$evaluation_postgres_arg
EOF

cat > /etc/systemd/system/proxy-sentinel-shadow-evaluation.timer <<EOF
[Unit]
Description=Refresh Proxy Sentinel shadow evaluation every hour

[Timer]
OnCalendar=*-*-* *:05:00
Persistent=true
Unit=proxy-sentinel-shadow-evaluation.service

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/proxy-sentinel-control-plane.service <<EOF
[Unit]
Description=Proxy Sentinel shadow control plane
After=network-online.target proxy-sentinel-shadow.timer\$storage_after_suffix
Wants=network-online.target\$storage_control_wants_suffix

[Service]
Type=simple
WorkingDirectory=$remote_root
\$storage_env_line
EnvironmentFile=-$remote_root/config/control-plane-secrets.env
ExecStart=$remote_root/bin/proxy-sentinel control-plane serve --addr $control_addr --shadow-dir $remote_root/data/shadow --sensor-id $sensor_id --frontend-dir $remote_root/frontend/dist --storage-mode dual --device-fingerprint-dir $remote_root/data/device-fingerprints --device-fingerprint-auto-update=false --operations-file $remote_root/data/control-plane-operations.json \$storage_dsn_args $control_read_only_arg $control_auth_arg
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now proxy-sentinel-suricata.service
if [[ -n \"\$zeek_bin\" ]] && ip link show '$mirror_iface' >/dev/null 2>&1; then
  systemctl enable --now proxy-sentinel-zeek.service
fi
systemctl enable --now proxy-sentinel-shadow.timer
systemctl enable --now proxy-sentinel-shadow-evaluation.timer
systemctl enable --now proxy-sentinel-control-plane.service
systemctl restart proxy-sentinel-control-plane.service
systemctl start proxy-sentinel-shadow.service
systemctl start proxy-sentinel-shadow-evaluation.service
systemctl --no-pager status proxy-sentinel-suricata.service | sed -n '1,80p'
if [[ -n \"\$zeek_bin\" ]] && ip link show '$mirror_iface' >/dev/null 2>&1; then
  systemctl --no-pager status proxy-sentinel-zeek.service | sed -n '1,80p'
fi
systemctl --no-pager status proxy-sentinel-shadow.timer | sed -n '1,80p'
systemctl --no-pager status proxy-sentinel-shadow-evaluation.timer | sed -n '1,80p'
systemctl --no-pager status proxy-sentinel-control-plane.service | sed -n '1,80p'
journalctl -u proxy-sentinel-shadow.service -n 80 --no-pager
"

echo "deployed proxy-sentinel shadow mode and control plane to $remote_host:$remote_root"
