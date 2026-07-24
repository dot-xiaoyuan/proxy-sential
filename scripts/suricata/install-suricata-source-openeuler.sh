#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-suricata-source-openeuler.sh [options]

Options:
  --version VERSION      Suricata source release. Default: 6.0.20
  --jobs N              Parallel build jobs. Default: nproc
  --work-dir DIR        Build work directory. Default: /tmp/proxy-sentinel-suricata-build-XXXXXX
  --keep-work-dir       Keep build work directory after installation

Build and install Suricata from the official source tarball on openEuler.
The install prefix is /usr, configuration is installed under /etc/suricata,
and logs default to /var/log/suricata.
EOF
}

version="6.0.20"
jobs="$(nproc 2>/dev/null || echo 2)"
work_dir=""
keep_work_dir="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --jobs)
      jobs="${2:-}"
      shift 2
      ;;
    --work-dir)
      work_dir="${2:-}"
      shift 2
      ;;
    --keep-work-dir)
      keep_work_dir="true"
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

if [[ "$(id -u)" -ne 0 ]]; then
  echo "please run as root: sudo scripts/suricata/install-suricata-source-openeuler.sh" >&2
  exit 1
fi

if [[ ! "$jobs" =~ ^[0-9]+$ || "$jobs" -lt 1 ]]; then
  echo "--jobs must be a positive integer" >&2
  exit 2
fi

if [[ -r /etc/os-release ]]; then
  ID=
  ID_LIKE=
  # shellcheck disable=SC1091
  . /etc/os-release
  distribution="$(printf ' %s %s ' "${ID:-}" "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"
  if [[ "$distribution" != *" openeuler "* ]]; then
    echo "this helper is intended for openEuler; detected: ${PRETTY_NAME:-unknown}" >&2
    exit 1
  fi
fi

if ! command -v dnf >/dev/null 2>&1; then
  echo "dnf is required on openEuler" >&2
  exit 1
fi

dnf install -y \
  autoconf \
  automake \
  cargo \
  gcc \
  gcc-c++ \
  jansson-devel \
  libpcap-devel \
  libtool \
  libyaml-devel \
  make \
  pcre-devel \
  pkgconf \
  rust \
  tar \
  wget \
  which \
  zlib-devel

export PATH="${PATH}:/root/.cargo/bin"

if ! command -v cbindgen >/dev/null 2>&1; then
  cargo install --force --locked cbindgen --version "${CBINDGEN_VERSION:-0.24.5}"
fi

if [[ -z "$work_dir" ]]; then
  work_dir="$(mktemp -d /tmp/proxy-sentinel-suricata-build-XXXXXX)"
else
  mkdir -p "$work_dir"
fi

if [[ "$keep_work_dir" != "true" ]]; then
  trap 'rm -rf "$work_dir"' EXIT
fi

archive="suricata-${version}.tar.gz"
source_url="https://www.openinfosecfoundation.org/download/suricata-${version}.tar.gz"

cd "$work_dir"
wget -O "$archive" "$source_url"
tar xzf "$archive"
cd "suricata-${version}"

./configure \
  --prefix=/usr \
  --sysconfdir=/etc \
  --localstatedir=/var \
  --disable-gccmarch-native

make -j "$jobs"
make install-full

if [[ -e /usr/lib/libhtp.so ]]; then
  printf '%s\n' /usr/lib > /etc/ld.so.conf.d/proxy-sentinel-suricata.conf
  ldconfig
fi

mkdir -p /var/lib/suricata/rules
if [[ ! -e /var/lib/suricata/rules/suricata.rules ]]; then
  : > /var/lib/suricata/rules/suricata.rules
fi
chmod 0644 /var/lib/suricata/rules/suricata.rules

suricata --build-info | sed -n '1,12p'
echo
echo "Suricata installed. Config: /etc/suricata/suricata.yaml"
echo "Next: sudo scripts/suricata/capture-mirror-sample.sh --interface auto --duration 1800"
