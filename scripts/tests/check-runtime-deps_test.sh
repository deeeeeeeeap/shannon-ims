#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
preflight="$root_dir/scripts/check-runtime-deps.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

fake_bin="$tmp_dir/bin"
plugin_dir="$tmp_dir/plugins"
conf_dir="$tmp_dir/strongswan.d"
runtime_dir="$tmp_dir/run"
mkdir -p "$fake_bin" "$plugin_dir" "$conf_dir" "$runtime_dir"

cat >"$fake_bin/id" <<'EOF'
#!/usr/bin/env sh
if [ "${1:-}" = "-u" ]; then
  printf '0\n'
  exit 0
fi
exit 2
EOF

cat >"$fake_bin/uname" <<'EOF'
#!/usr/bin/env sh
printf 'Linux\n'
EOF

cat >"$fake_bin/charon" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
cat >"$fake_bin/pgrep" <<'EOF'
#!/usr/bin/env sh
if [ "${FAKE_CHARON_RUNNING:-0}" = "1" ]; then
  exit 0
fi
exit 1
EOF
chmod 0755 "$fake_bin/id" "$fake_bin/uname" "$fake_bin/charon" "$fake_bin/pgrep"

touch "$tmp_dir/strongswan.conf"
for plugin in \
  libstrongswan-vici.so \
  libstrongswan-eap-aka.so \
  libstrongswan-eap-identity.so \
  libstrongswan-kernel-libipsec.so \
  libstrongswan-kernel-netlink.so \
  libstrongswan-eap-aka-vohive.so \
  libstrongswan-p-cscf-vohive.so
do
  touch "$plugin_dir/$plugin"
done

run_preflight() {
  PATH="$fake_bin:$PATH" \
  SHANNON_CHARON_BIN="$fake_bin/charon" \
  SHANNON_PLUGIN_DIR="$plugin_dir" \
  SHANNON_TUN_DEVICE=/dev/null \
  SHANNON_STRONGSWAN_CONF="$tmp_dir/strongswan.conf" \
  SHANNON_STRONGSWAN_CONF_DIR="$conf_dir" \
  SHANNON_RUNTIME_DIR="$runtime_dir" \
  SHANNON_VICI_SOCKET="$runtime_dir/charon.vici" \
    bash "$preflight"
}

pass_output="$tmp_dir/pass.out"
run_preflight >"$pass_output"
grep -qx 'check.os=ok' "$pass_output"
grep -qx 'check.privilege=ok' "$pass_output"
grep -qx 'check.charon=ok' "$pass_output"
grep -qx 'check.charon_service=ok' "$pass_output"
grep -qx 'check.vici_plugin=ok' "$pass_output"
grep -qx 'check.eap_aka_method_plugin=ok' "$pass_output"
grep -qx 'check.eap_identity_plugin=ok' "$pass_output"
grep -qx 'check.kernel_libipsec_plugin=ok' "$pass_output"
grep -qx 'check.kernel_netlink_plugin=ok' "$pass_output"
grep -qx 'check.eap_aka_plugin=ok' "$pass_output"
grep -qx 'check.p_cscf_plugin=ok' "$pass_output"
grep -qx 'check.tun=ok' "$pass_output"
grep -qx 'runtime_preflight=pass' "$pass_output"

rm "$plugin_dir/libstrongswan-p-cscf-vohive.so"
fail_output="$tmp_dir/fail.out"
if run_preflight >"$fail_output"; then
  printf 'expected preflight to fail when the P-CSCF plugin is missing\n' >&2
  exit 1
fi
grep -qx 'check.p_cscf_plugin=missing' "$fail_output"
grep -qx 'runtime_preflight=fail' "$fail_output"

touch "$plugin_dir/libstrongswan-p-cscf-vohive.so"
conflict_output="$tmp_dir/conflict.out"
if FAKE_CHARON_RUNNING=1 run_preflight >"$conflict_output"; then
  printf 'expected preflight to reject a conflicting charon service\n' >&2
  exit 1
fi
grep -qx 'check.charon_service=conflict' "$conflict_output"
grep -qx 'runtime_preflight=fail' "$conflict_output"

if grep -Fq "$tmp_dir" "$pass_output" "$fail_output" "$conflict_output"; then
  printf 'preflight output exposed a host path\n' >&2
  exit 1
fi

printf 'check_runtime_deps_test=pass\n'
