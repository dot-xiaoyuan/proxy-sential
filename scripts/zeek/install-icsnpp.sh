#!/usr/bin/env bash
# Build a pinned, architecture-specific passive parser in an explicit prefix.
# Never activates capture or sends packets. Application deployment only checks
# this artifact; it does not download/build plugins on a running mirror host.
set -euo pipefail
prefix=""; lock=""; archive_dir=""; check=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) prefix="${2:?}"; shift 2 ;;
    --lock) lock="${2:?}"; shift 2 ;;
    --archive-dir) archive_dir="${2:?}"; shift 2 ;;
    --check) check=true; shift ;;
    *) echo "usage: install-icsnpp.sh --prefix ABSOLUTE_PATH [--lock FILE] [--archive-dir DIR] [--check]" >&2; exit 2 ;;
  esac
done
[[ "$prefix" == /* && "$prefix" != / ]] || { echo "explicit absolute plugin prefix required" >&2; exit 2; }
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$lock" ]]; then
  lock="$script_dir/../../assets/zeek/icsnpp.lock.json"
  [[ -f "$lock" ]] || lock="$script_dir/../assets/zeek/icsnpp.lock.json"
fi
[[ -f "$lock" ]] || { echo "ICSNPP lock file missing" >&2; exit 1; }
zeek_version="$(zeek-config --version)"
python3 - "$zeek_version" "$lock" <<'PY'
import json,re,sys
def version(s):
    m=re.search(r'(\d+)\.(\d+)\.(\d+)',s)
    if not m: raise SystemExit('Unparseable Zeek version')
    return tuple(map(int,m.groups()))
if version(sys.argv[1]) < version(json.load(open(sys.argv[2]))['minimum_zeek_version']):
    raise SystemExit('Passive industrial identity requires Zeek >= 6.1.0')
PY
if [[ "$check" == true ]]; then
  python3 - "$prefix" "$lock" "$zeek_version" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); manifest=json.loads((root/'manifest.json').read_text()); lock=json.load(open(sys.argv[2]))
if manifest['packages'] != lock['packages'] or manifest['zeek_version'] != sys.argv[3]:
    raise SystemExit('ICSNPP lock or Zeek ABI version mismatch; rebuild explicitly')
for relative,digest in manifest['files'].items():
    path=root/relative
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
        raise SystemExit('ICSNPP installed file checksum mismatch: '+relative)
PY
  ZEEK_PLUGIN_PATH="$prefix/plugins" zeek -N ICSNPP::BACnet >/dev/null
  echo "pinned ICSNPP artifact verified for Zeek $zeek_version"
  exit 0
fi
[[ ! -e "$prefix" ]] || { echo "prefix exists; check it or select a new explicit build destination" >&2; exit 1; }
mkdir -p "$(dirname "$prefix")"
stage="$(mktemp -d "${prefix}.staging.XXXXXX")"
work="$(mktemp -d "${TMPDIR:-/tmp}/passive-icsnpp-build.XXXXXX")"
trap 'rm -rf "$work" "$stage"' EXIT
mkdir -p "$stage/plugins" "$stage/licenses"
python3 - "$lock" > "$work/packages.tsv" <<'PY'
import json,sys
for p in json.load(open(sys.argv[1]))['packages']:
    print(p['name'],p['commit'],p['archive_sha256'],sep='\t')
PY
while IFS=$'\t' read -r name commit digest; do
  archive="$work/$name.tar.gz"
  if [[ -n "$archive_dir" ]]; then
    cp "$archive_dir/$name-$commit.tar.gz" "$archive"
  else
    curl --fail --location --max-time 120 --max-filesize 52428800 --silent --show-error "https://codeload.github.com/cisagov/$name/tar.gz/$commit" -o "$archive"
  fi
  python3 - "$archive" "$digest" <<'PY'
import hashlib,sys
if hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()!=sys.argv[2]: raise SystemExit('ICSNPP archive checksum mismatch')
PY
  tar -xzf "$archive" -C "$work"
  source_dir="$work/$name-$commit"
  cp "$source_dir/LICENSE.txt" "$stage/licenses/$name-LICENSE.txt"
  cp "$source_dir/NOTICE.txt" "$stage/licenses/$name-NOTICE.txt"
  if [[ "$name" == icsnpp-bacnet ]]; then
    cmake -S "$source_dir" -B "$source_dir/build" -DCMAKE_MODULE_PATH="$(zeek-config --cmake_dir)" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$source_dir/build" --parallel 2
    tar -xzf "$source_dir/build/ICSNPP_Bacnet.tgz" -C "$stage/plugins"
  fi
done < "$work/packages.tsv"
python3 - "$stage" "$lock" "$zeek_version" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); lock=json.load(open(sys.argv[2]))
files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
(root/'manifest.json').write_text(json.dumps({'schema_version':'passive-icsnpp-build/v1','zeek_version':sys.argv[3],'packages':lock['packages'],'files':files},indent=2)+'\n')
PY
ZEEK_PLUGIN_PATH="$stage/plugins" zeek -N ICSNPP::BACnet >/dev/null
mv "$stage" "$prefix"
echo "built pinned passive parser in $prefix; capture remains inactive"
