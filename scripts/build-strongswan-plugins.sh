#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
strongswan_src=
plugin_source_root="$root_dir/vowifi-go/engine/swu"
ipsec_lib_dir=/usr/lib/ipsec
output_dir="$root_dir/dist/strongswan-plugins"

usage() {
  cat <<'EOF'
usage: build-strongswan-plugins.sh --strongswan-src DIR [options]

Options:
  --plugin-source-root DIR  Directory containing akabridge/plugin and
                            pcscfbridge/plugin (defaults to the repository).
  --ipsec-lib-dir DIR       Target strongSwan library directory.
  --output DIR              Staging directory for the two plugin binaries.

The strongSwan source tree must match the target runtime and must already have
been configured so config.h exists. This command builds and stages plugins; it
does not install packages or write into the system plugin directory.
EOF
}

fail() {
  printf 'plugin_build=fail\n'
  printf 'reason=%s\n' "$1"
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --strongswan-src)
      (($# >= 2)) || { usage >&2; exit 2; }
      strongswan_src=$2
      shift 2
      ;;
    --plugin-source-root)
      (($# >= 2)) || { usage >&2; exit 2; }
      plugin_source_root=$2
      shift 2
      ;;
    --ipsec-lib-dir)
      (($# >= 2)) || { usage >&2; exit 2; }
      ipsec_lib_dir=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || { usage >&2; exit 2; }
      output_dir=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$(uname -s 2>/dev/null || true)" == Linux ]] || fail linux_required
[[ -n "$strongswan_src" ]] || { usage >&2; exit 2; }

if [[ ! -r "$strongswan_src/config.h" \
   || ! -d "$strongswan_src/src/libstrongswan" \
   || ! -d "$strongswan_src/src/libcharon" \
   || ! -d "$strongswan_src/src/libsimaka" ]]; then
  fail strongswan_source_not_configured
fi

aka_source="$plugin_source_root/akabridge/plugin"
pcscf_source="$plugin_source_root/pcscfbridge/plugin"
[[ -r "$aka_source/Makefile" && -r "$pcscf_source/Makefile" ]] || fail plugin_source_missing

for tool in make install sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail build_tool_missing
done

aka_name=libstrongswan-eap-aka-vohive.so
pcscf_name=libstrongswan-p-cscf-vohive.so

cleanup() {
  make -C "$aka_source" \
    STRONGSWAN_SRC="$strongswan_src" \
    IPSEC_LIB_DIR="$ipsec_lib_dir" clean >/dev/null 2>&1 || true
  make -C "$pcscf_source" \
    STRONGSWAN_SRC="$strongswan_src" \
    IPSEC_LIB_DIR="$ipsec_lib_dir" clean >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! make -C "$aka_source" \
  STRONGSWAN_SRC="$strongswan_src" \
  IPSEC_LIB_DIR="$ipsec_lib_dir" clean all >/dev/null 2>&1; then
  fail eap_aka_plugin_compile_failed
fi

if ! make -C "$pcscf_source" \
  STRONGSWAN_SRC="$strongswan_src" \
  IPSEC_LIB_DIR="$ipsec_lib_dir" clean all >/dev/null 2>&1; then
  fail p_cscf_plugin_compile_failed
fi

[[ -r "$aka_source/$aka_name" && -r "$pcscf_source/$pcscf_name" ]] || fail plugin_output_missing
mkdir -p "$output_dir" || fail output_not_writable

install -m 0755 "$aka_source/$aka_name" "$output_dir/$aka_name" || fail output_not_writable
install -m 0755 "$pcscf_source/$pcscf_name" "$output_dir/$pcscf_name" || fail output_not_writable

(
  cd "$output_dir"
  sha256sum "$aka_name" "$pcscf_name" >SHA256SUMS
) || fail checksum_generation_failed

printf 'plugin_build=pass\n'
printf 'plugin_count=2\n'
printf 'checksums=SHA256SUMS\n'
printf 'system_install_required=true\n'
