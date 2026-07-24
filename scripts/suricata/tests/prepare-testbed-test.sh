#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
prepare_script="$script_dir/../prepare-testbed.sh"
test_dir="$(mktemp -d)"
trap 'rm -r "$test_dir"' EXIT

# shellcheck source=../prepare-testbed.sh
. "$prepare_script"

assert_manager() {
  local expected="$1"
  local os_release="$2"

  PROXY_SENTINEL_OS_RELEASE_FILE="$os_release" detect_distribution
  if [[ "$package_manager" != "$expected" ]]; then
    echo "expected package manager $expected, got $package_manager" >&2
    return 1
  fi
}

cat > "$test_dir/debian" <<'EOF'
ID=debian
PRETTY_NAME="Debian GNU/Linux"
EOF

cat > "$test_dir/ubuntu-like" <<'EOF'
ID=custom
ID_LIKE="ubuntu debian"
PRETTY_NAME="Ubuntu-compatible Linux"
EOF

cat > "$test_dir/openeuler" <<'EOF'
ID=openeuler
VERSION_ID="22.03"
PRETTY_NAME="openEuler 22.03 LTS"
EOF

cat > "$test_dir/unsupported" <<'EOF'
ID=unknown
PRETTY_NAME="Unknown Linux"
EOF

assert_manager apt "$test_dir/debian"
assert_manager apt "$test_dir/ubuntu-like"
assert_manager dnf "$test_dir/openeuler"

if PROXY_SENTINEL_OS_RELEASE_FILE="$test_dir/unsupported" detect_distribution 2>/dev/null; then
  echo "unsupported distribution should fail detection" >&2
  exit 1
fi

if PROXY_SENTINEL_OS_RELEASE_FILE="$test_dir/missing" detect_distribution 2>/dev/null; then
  echo "missing os-release should fail detection" >&2
  exit 1
fi

mkdir -p "$test_dir/bin"
command_log="$test_dir/commands.log"
export command_log

cat > "$test_dir/bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
  echo 0
fi
EOF

for command_name in dnf mkdir chmod; do
  cat > "$test_dir/bin/$command_name" <<'EOF'
#!/usr/bin/env bash
printf '%s' "$(basename "$0")" >> "$command_log"
printf ' %s' "$@" >> "$command_log"
printf '\n' >> "$command_log"
EOF
done

cat > "$test_dir/bin/suricata" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

chmod +x "$test_dir/bin/"*
(
  PATH="$test_dir/bin:/usr/bin:/bin"
  package_manager=dnf
  install_packages
)

for expected_command in \
  "dnf makecache" \
  "dnf install -y jq tcpdump iproute coreutils python3" \
  "mkdir -p /tmp/proxy-sentinel" \
  "chmod 1777 /tmp/proxy-sentinel"; do
  if ! grep -Fqx "$expected_command" "$command_log"; then
    echo "expected command not executed: $expected_command" >&2
    exit 1
  fi
done

echo "prepare-testbed distribution tests passed"
