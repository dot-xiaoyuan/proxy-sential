#!/usr/bin/env bash

set -euo pipefail

root="/opt/proxy-sentinel"
marker="${root}/backups/shared-canary-active"
reason="${1:-shared-access signal rollback requested}"

[[ -L "${marker}" ]] || { echo "shared canary backup marker is missing" >&2; exit 1; }
backup_dir="$(readlink -f "${marker}")"
[[ "${backup_dir}" == "${root}/backups/"* ]] || { echo "invalid shared canary backup path" >&2; exit 1; }
[[ -f "${backup_dir}/overnight-minimal.conf" ]] || { echo "missing ingest override backup" >&2; exit 1; }
previous_release="$(readlink -f "${backup_dir}/current")"
[[ "${previous_release}" == "${root}/releases/"* && -x "${previous_release}/bin/proxy-sentinel" ]] || { echo "invalid previous release backup" >&2; exit 1; }

systemctl stop proxy-sentinel-shared-signal.service proxy-sentinel-ingest.service
systemctl disable proxy-sentinel-shared-signal.service >/dev/null 2>&1 || true
install -m 0644 "${backup_dir}/overnight-minimal.conf" /etc/systemd/system/proxy-sentinel-ingest.service.d/overnight-minimal.conf
ln -sfn "${previous_release}" "${root}/current"
systemctl daemon-reload
systemctl start proxy-sentinel-ingest.service
systemctl is-active --quiet proxy-sentinel-ingest.service
systemctl is-active --quiet proxy-sentinel-zeek-cluster.service

completed_marker="${root}/backups/shared-canary-rolled-back-$(date -u +%Y%m%dT%H%M%SZ)"
mv "${marker}" "${completed_marker}"
printf '%s reason=%q previous_release=%q backup=%q\n' "$(date -Is)" "${reason}" "${previous_release}" "${backup_dir}" >>"${root}/data/watchdog/shared-rollback.log"
chmod 0600 "${root}/data/watchdog/shared-rollback.log"
