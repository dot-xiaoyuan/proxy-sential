#!/usr/bin/env bash

set -euo pipefail

root="/opt/proxy-sentinel"
marker="${root}/backups/snmp-canary-active"
reason="${1:-SNMP supplement rollback requested}"

[[ -L "${marker}" ]] || { echo "SNMP canary backup marker is missing" >&2; exit 1; }
backup_dir="$(readlink -f "${marker}")"
[[ "${backup_dir}" == "${root}/backups/"* ]] || { echo "invalid SNMP canary backup path" >&2; exit 1; }
[[ -f "${backup_dir}/local.zeek" ]] || { echo "missing local.zeek backup" >&2; exit 1; }
[[ -f "${backup_dir}/overnight-minimal.conf" ]] || { echo "missing ingest override backup" >&2; exit 1; }
previous_release="$(readlink -f "${backup_dir}/current")"
[[ "${previous_release}" == "${root}/releases/"* && -x "${previous_release}/bin/proxy-sentinel" ]] || { echo "invalid previous release backup" >&2; exit 1; }

systemctl stop proxy-sentinel-shared-signal.service proxy-sentinel-ingest.service proxy-sentinel-zeek-cluster.service
systemctl disable proxy-sentinel-shared-signal.service >/dev/null 2>&1 || true
install -m 0644 "${backup_dir}/local.zeek" /usr/local/zeek/share/zeek/site/local.zeek
install -m 0644 "${backup_dir}/overnight-minimal.conf" /etc/systemd/system/proxy-sentinel-ingest.service.d/overnight-minimal.conf
ln -sfn "${previous_release}" "${root}/current"
systemctl daemon-reload
/usr/local/zeek/bin/zeekctl check
systemctl start proxy-sentinel-zeek-cluster.service proxy-sentinel-ingest.service
systemctl is-active --quiet proxy-sentinel-zeek-cluster.service
systemctl is-active --quiet proxy-sentinel-ingest.service

completed_marker="${root}/backups/snmp-canary-rolled-back-$(date -u +%Y%m%dT%H%M%SZ)"
mv "${marker}" "${completed_marker}"
printf '%s reason=%q previous_release=%q backup=%q\n' "$(date -Is)" "${reason}" "${previous_release}" "${backup_dir}" >>"${root}/data/watchdog/snmp-rollback.log"
chmod 0600 "${root}/data/watchdog/snmp-rollback.log"
