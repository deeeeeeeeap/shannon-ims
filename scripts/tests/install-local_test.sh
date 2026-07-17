#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
installer="$root_dir/scripts/install-local.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

fake_bin="$tmp_dir/bin-tools"
plugin_dir="$tmp_dir/plugins"
conf_dir="$tmp_dir/strongswan.d"
runtime_dir="$tmp_dir/run"
prefix="$tmp_dir/install"
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
  libstrongswan-eap-aka-vohive.so
do
  touch "$plugin_dir/$plugin"
done

fake_app="$tmp_dir/shannon-ims"
printf '#!/usr/bin/env sh\nexit 0\n' >"$fake_app"
chmod 0755 "$fake_app"

run_installer() {
  PATH="$fake_bin:$PATH" \
  SHANNON_CHARON_BIN="$fake_bin/charon" \
  SHANNON_PLUGIN_DIR="$plugin_dir" \
  SHANNON_TUN_DEVICE=/dev/null \
  SHANNON_STRONGSWAN_CONF="$tmp_dir/strongswan.conf" \
  SHANNON_STRONGSWAN_CONF_DIR="$conf_dir" \
  SHANNON_RUNTIME_DIR="$runtime_dir" \
  SHANNON_VICI_SOCKET="$runtime_dir/charon.vici" \
    bash "$installer" "$fake_app" "$prefix"
}

blocked_output="$tmp_dir/blocked.out"
if run_installer >"$blocked_output"; then
  printf 'expected install to be blocked by a failed runtime preflight\n' >&2
  exit 1
fi
test ! -e "$prefix/bin/shannon-ims"
grep -qx 'runtime_preflight=fail' "$blocked_output"
grep -qx 'install_status=blocked' "$blocked_output"
grep -qx 'reason=runtime_preflight_failed' "$blocked_output"

touch "$plugin_dir/libstrongswan-p-cscf-vohive.so"
pass_output="$tmp_dir/pass.out"
run_installer >"$pass_output"
test -x "$prefix/bin/shannon-ims"
test -f "$prefix/config/config.yaml"
test "$(stat -c '%a' "$prefix/config/config.yaml")" = 600
test "$(stat -c '%a' "$prefix/data")" = 700
test ! -e "$prefix/data/session-secret"
grep -qx 'runtime_preflight=pass' "$pass_output"
grep -qx 'install_status=pass' "$pass_output"
grep -Fqx "run_command=cd $prefix && exec $prefix/bin/shannon-ims -c $prefix/config/config.yaml" "$pass_output"

printf 'preserve-this-config\n' >"$prefix/config/config.yaml"
run_installer >"$tmp_dir/reinstall.out"
grep -qx 'preserve-this-config' "$prefix/config/config.yaml"

printf 'install_local_test=pass\n'
