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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

binary="$build_dir/proxy-sentinel"
frontend_archive="$build_dir/frontend-dist.tar.gz"
(
  cd "$repo_root"
  GOOS=linux GOARCH=amd64 go build -o "$binary" ./cmd/proxy-sentinel
  (
    cd frontend
    pnpm build
  )
  COPYFILE_DISABLE=1 tar --no-xattrs -C frontend -czf "$frontend_archive" dist
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
scp "$binary" "$remote_host:$remote_tmp"
scp "$frontend_archive" "$remote_host:$remote_frontend_tmp"
ssh "$remote_host" "set -euo pipefail
install -m 0755 '$remote_tmp' '$remote_root/bin/proxy-sentinel'
rm '$remote_tmp'
rm -rf '$remote_root/frontend/dist'
mkdir -p '$remote_root/frontend'
tar -C '$remote_root/frontend' -xzf '$remote_frontend_tmp'
rm '$remote_frontend_tmp'
chown -R root:root '$remote_root/frontend/dist'

storage_env_line=''
storage_after_suffix=''
storage_shadow_wants_line=''
storage_control_wants_suffix=''
storage_dsn_args=''
if [[ -f '$remote_root/deploy/compose/storage.env' ]]; then
  storage_env_line='EnvironmentFile=$remote_root/deploy/compose/storage.env'
  storage_after_suffix=' docker.service'
  storage_shadow_wants_line='Wants=docker.service'
  storage_control_wants_suffix=' docker.service'
  storage_dsn_args='--postgres-dsn \${PROXY_SENTINEL_POSTGRES_DSN} --clickhouse-dsn \${PROXY_SENTINEL_CLICKHOUSE_DSN}'
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

cat > /etc/systemd/system/proxy-sentinel-shadow.service <<EOF
[Unit]
Description=Proxy Sentinel shadow risk analysis
After=proxy-sentinel-suricata.service$storage_after_suffix
$storage_shadow_wants_line

[Service]
Type=oneshot
WorkingDirectory=$remote_root
$storage_env_line
ExecStart=$remote_root/bin/proxy-sentinel shadow run --eve /var/log/suricata/eve.json --state $remote_root/data/shadow/state.json --out-dir $remote_root/data/shadow --sensor-id $sensor_id --window $window --min-level suspicious --limit 50 --retention $retention --storage-mode dual $storage_dsn_args
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

cat > /etc/systemd/system/proxy-sentinel-control-plane.service <<EOF
[Unit]
Description=Proxy Sentinel read-only control plane
After=network-online.target proxy-sentinel-shadow.timer$storage_after_suffix
Wants=network-online.target$storage_control_wants_suffix

[Service]
Type=simple
WorkingDirectory=$remote_root
$storage_env_line
ExecStart=$remote_root/bin/proxy-sentinel control-plane serve --addr $control_addr --shadow-dir $remote_root/data/shadow --sensor-id $sensor_id --frontend-dir $remote_root/frontend/dist --storage-mode dual $storage_dsn_args --read-only
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now proxy-sentinel-suricata.service
systemctl enable --now proxy-sentinel-shadow.timer
systemctl enable --now proxy-sentinel-control-plane.service
systemctl start proxy-sentinel-shadow.service
systemctl --no-pager status proxy-sentinel-suricata.service | sed -n '1,80p'
systemctl --no-pager status proxy-sentinel-shadow.timer | sed -n '1,80p'
systemctl --no-pager status proxy-sentinel-control-plane.service | sed -n '1,80p'
journalctl -u proxy-sentinel-shadow.service -n 80 --no-pager
"

echo "deployed proxy-sentinel shadow mode and control plane to $remote_host:$remote_root"
