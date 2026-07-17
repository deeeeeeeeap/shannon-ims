#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
builder="$root_dir/scripts/build-strongswan-plugins.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

fake_bin="$tmp_dir/bin"
strongswan_src="$tmp_dir/strongswan"
plugin_source_root="$tmp_dir/plugin-source"
output_dir="$tmp_dir/output"
mkdir -p \
  "$fake_bin" \
  "$strongswan_src/src/libstrongswan" \
  "$strongswan_src/src/libcharon" \
  "$strongswan_src/src/libsimaka" \
  "$plugin_source_root/akabridge/plugin" \
  "$plugin_source_root/pcscfbridge/plugin"
touch "$strongswan_src/config.h"
touch "$plugin_source_root/akabridge/plugin/Makefile"
touch "$plugin_source_root/pcscfbridge/plugin/Makefile"

cat >"$fake_bin/make" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

workdir=
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[$i]}" == -C ]]; then
    workdir=${args[$((i + 1))]}
  fi
done
[[ -n "$workdir" ]]
printf '%s\n' "$*" >>"$FAKE_MAKE_LOG"

case "$workdir" in
  */akabridge/plugin) soname=libstrongswan-eap-aka-vohive.so ;;
  */pcscfbridge/plugin) soname=libstrongswan-p-cscf-vohive.so ;;
  *) exit 3 ;;
esac

if [[ " $* " == *' clean '* ]]; then
  rm -f "$workdir/$soname"
fi
if [[ " $* " == *' all '* ]]; then
  printf 'fixture-plugin\n' >"$workdir/$soname"
fi
EOF
chmod 0755 "$fake_bin/make"

build_output="$tmp_dir/build.out"
PATH="$fake_bin:$PATH" \
FAKE_MAKE_LOG="$tmp_dir/make.log" \
  bash "$builder" \
    --strongswan-src "$strongswan_src" \
    --plugin-source-root "$plugin_source_root" \
    --ipsec-lib-dir "$tmp_dir/ipsec-lib" \
    --output "$output_dir" >"$build_output"

test -f "$output_dir/libstrongswan-eap-aka-vohive.so"
test -f "$output_dir/libstrongswan-p-cscf-vohive.so"
test -f "$output_dir/SHA256SUMS"
test "$(wc -l <"$output_dir/SHA256SUMS")" -eq 2
grep -q 'akabridge/plugin.*STRONGSWAN_SRC=.*IPSEC_LIB_DIR=.*clean all' "$tmp_dir/make.log"
grep -q 'pcscfbridge/plugin.*STRONGSWAN_SRC=.*IPSEC_LIB_DIR=.*clean all' "$tmp_dir/make.log"
grep -qx 'plugin_build=pass' "$build_output"
grep -qx 'plugin_count=2' "$build_output"

if grep -Fq "$tmp_dir" "$build_output"; then
  printf 'plugin builder output exposed a host path\n' >&2
  exit 1
fi

missing_source_output="$tmp_dir/missing-source.out"
rm "$strongswan_src/config.h"
if PATH="$fake_bin:$PATH" FAKE_MAKE_LOG="$tmp_dir/make.log" \
  bash "$builder" \
    --strongswan-src "$strongswan_src" \
    --plugin-source-root "$plugin_source_root" \
    --output "$tmp_dir/should-not-exist" >"$missing_source_output" 2>&1
then
  printf 'expected an unconfigured strongSwan source tree to be rejected\n' >&2
  exit 1
fi
grep -qx 'plugin_build=fail' "$missing_source_output"
grep -qx 'reason=strongswan_source_not_configured' "$missing_source_output"

printf 'build_strongswan_plugins_test=pass\n'
