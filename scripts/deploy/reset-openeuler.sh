#!/usr/bin/env bash
set -Eeuo pipefail

usage() { echo "usage: reset-openeuler.sh --confirm-host IP [--preserve-docker-data]" >&2; }
confirm_host=""; preserve_docker_data=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm-host) confirm_host="${2:-}"; shift 2 ;;
    --preserve-docker-data) preserve_docker_data=true; shift ;;
    *) usage; exit 2 ;;
  esac
done
[[ $(id -u) -eq 0 ]] || { echo "reset must run as root" >&2; exit 1; }
[[ "$confirm_host" =~ ^[0-9a-fA-F:.]+$ ]] || { usage; exit 2; }
hostname -I | tr ' ' '\n' | grep -Fxq "$confirm_host" || { echo "host confirmation does not match this machine: $confirm_host" >&2; exit 1; }

log_file="/var/tmp/proxy-sentinel-reset-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$log_file") 2>&1
current_stage="初始化"
trap 'status=$?; echo "[清理失败] 阶段=$current_stage 行=${BASH_LINENO[0]:-unknown} 退出码=$status 命令=${BASH_COMMAND:-unknown}" >&2; echo "日志=$log_file" >&2; exit $status' ERR
stage=0
progress() { stage=$((stage + 1)); current_stage="$*"; printf '\n[%d/6] %s\n' "$stage" "$current_stage"; }

progress "保存小型配置清单"
backup="/var/tmp/proxy-sentinel-preclean-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
paths=()
for path in /opt/proxy-sentinel/config /etc/suricata /etc/systemd/system/proxy-sentinel-control-plane.service; do [[ -e "$path" ]] && paths+=("${path#/}"); done
if (( ${#paths[@]} > 0 )); then tar -C / -czf "$backup" "${paths[@]}"; chmod 0600 "$backup"; else backup="none"; fi

progress "停止并禁用 Proxy Sentinel 采集和控制服务"
mapfile -t units < <(systemctl list-unit-files 'proxy-sentinel*' --no-legend 2>/dev/null | awk '{print $1}' || true)
if (( ${#units[@]} > 0 )); then systemctl disable --now "${units[@]}" || true; fi

progress "删除 Proxy Sentinel 专属容器和匿名卷"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  for container in proxy-sentinel-postgres proxy-sentinel-clickhouse; do
    if docker inspect "$container" >/dev/null 2>&1; then
      mapfile -t volumes < <(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}' "$container" | sed '/^$/d')
      docker rm -f "$container"
      if (( ${#volumes[@]} > 0 )); then docker volume rm "${volumes[@]}" || true; fi
    fi
  done
  for image in \
    'srun-docker.pkg.coding.net/dpi/image/postgres@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a' \
    'srun-docker.pkg.coding.net/dpi/image/postgres:latest' \
    'srun-docker.pkg.coding.net/dpi/image/clickhouse@sha256:bca6494fa85aea382ddf69e8b9e8b481d2f06603b083e3dd705013a8c260e91f' \
    'srun-docker.pkg.coding.net/dpi/image/clickhouse:latest'; do
    docker image inspect "$image" >/dev/null 2>&1 && docker image rm "$image" || true
  done
  mapfile -t airgap_images < <(docker image ls --format '{{.Repository}}:{{.Tag}}' | awk '
    $0 ~ /^srun-docker\.pkg\.coding\.net\/dpi\/image\/(postgres|clickhouse):airgap-[a-f0-9]{64}$/ { print }
  ')
  if (( ${#airgap_images[@]} > 0 )); then docker image rm "${airgap_images[@]}" || true; fi
fi

progress "删除旧应用、数据库、采集日志和采集器"
for path in /opt/proxy-sentinel /var/log/suricata /var/lib/suricata /etc/suricata /usr/local/zeek; do
  [[ -e "$path" ]] && find "$path" -depth -mindepth 1 -delete && rmdir "$path"
done
for path in /usr/bin/suricata /usr/lib/libhtp.so /usr/lib/libhtp.so.2 /usr/lib/libhtp.so.2.0.0 /usr/local/bin/zeek /usr/local/bin/proxy-sentinelctl /usr/local/lib/proxy-sentinel/install-openeuler.sh /etc/ld.so.conf.d/proxy-sentinel-suricata.conf /etc/logrotate.d/proxy-sentinel-suricata; do
  [[ -e "$path" || -L "$path" ]] && unlink "$path"
done
find /etc/systemd/system -maxdepth 1 -name 'proxy-sentinel*' -type f -delete
systemctl daemon-reload
ldconfig

progress "卸载 Docker 软件包"
if rpm -q docker-ce >/dev/null 2>&1; then
  systemctl stop docker.service docker.socket containerd.service || true
  dnf remove -y docker-ce docker-ce-cli docker-ce-rootless-extras docker-compose-plugin containerd.io container-selinux
fi
if [[ "$preserve_docker_data" != true && -d /var/lib/docker ]]; then
  find /var/lib/docker -depth -mindepth 1 -delete
fi

progress "验证干净状态"
hash -r
for command in docker suricata zeek proxy-sentinelctl; do
  if command -v "$command" >/dev/null 2>&1; then echo "仍检测到命令：$command" >&2; exit 1; fi
done
[[ ! -e /opt/proxy-sentinel && ! -e /var/log/suricata ]] || { echo "Proxy Sentinel 数据仍然存在" >&2; exit 1; }
printf '\n清理完成。配置备份：%s\n清理日志：%s\n' "$backup" "$log_file"
if [[ "$preserve_docker_data" == true ]]; then echo "已保留 /var/lib/docker，非 Proxy Sentinel 容器数据可在 Docker 重装后恢复。"; fi
