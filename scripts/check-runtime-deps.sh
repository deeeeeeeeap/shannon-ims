#!/usr/bin/env bash
set -u

dataplane=${SHANNON_DATAPLANE_MODE:-userspace}

usage() {
  cat <<'EOF'
usage: check-runtime-deps.sh [--dataplane userspace|kernel]

Read-only preflight for the Shannon IMS Wi-Fi Calling runtime. The output is
limited to stable check names and states; it does not print host paths,
subscriber identities, credentials, or authentication material.
EOF
}

while (($# > 0)); do
  case "$1" in
    --dataplane)
      if (($# < 2)); then
        usage >&2
        exit 2
      fi
      dataplane=$2
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

case "$dataplane" in
  userspace|kernel) ;;
  *)
    printf 'check.dataplane=invalid\n'
    printf 'runtime_preflight=fail\n'
    exit 2
    ;;
esac

failures=0

report() {
  local name=$1
  local state=$2
  printf 'check.%s=%s\n' "$name" "$state"
  if [[ "$state" != ok && "$state" != not_required ]]; then
    failures=$((failures + 1))
  fi
}

find_charon() {
  local candidate
  if [[ -n "${SHANNON_CHARON_BIN:-}" ]]; then
    [[ -x "$SHANNON_CHARON_BIN" ]]
    return
  fi

  for candidate in \
    /usr/lib/ipsec/charon-systemd \
    /usr/lib/ipsec/charon \
    /usr/libexec/ipsec/charon \
    /usr/libexec/strongswan/charon \
    /usr/lib/strongswan/charon \
    /usr/sbin/charon \
    /usr/bin/charon
  do
    [[ -x "$candidate" ]] && return 0
  done

  command -v charon-systemd >/dev/null 2>&1 || command -v charon >/dev/null 2>&1
}

find_plugin_dir() {
  local candidate
  if [[ -n "${SHANNON_PLUGIN_DIR:-}" ]]; then
    plugin_dir=$SHANNON_PLUGIN_DIR
    [[ -d "$plugin_dir" ]]
    return
  fi

  for candidate in \
    /usr/lib/ipsec/plugins \
    /usr/libexec/ipsec/plugins \
    /usr/lib/strongswan/plugins \
    /usr/lib64/ipsec/plugins
  do
    if [[ -d "$candidate" ]]; then
      plugin_dir=$candidate
      return 0
    fi
  done
  return 1
}

has_plugin() {
  local name
  [[ -n "${plugin_dir:-}" ]] || return 1
  for name in "$@"; do
    [[ -r "$plugin_dir/$name" ]] && return 0
  done
  return 1
}

if [[ "$(uname -s 2>/dev/null || true)" == Linux ]]; then
  report os ok
else
  report os unsupported
fi

if [[ "$(id -u 2>/dev/null || true)" == 0 ]]; then
  report privilege ok
else
  report privilege root_required
fi

if find_charon; then
  report charon ok
else
  report charon missing
fi

vici_socket=${SHANNON_VICI_SOCKET:-/run/charon.vici}
charon_service_conflict=0
if [[ -e "$vici_socket" ]]; then
  charon_service_conflict=1
fi
if command -v pgrep >/dev/null 2>&1; then
  if pgrep -x charon >/dev/null 2>&1 || pgrep -x charon-systemd >/dev/null 2>&1; then
    charon_service_conflict=1
  fi
fi
if ((charon_service_conflict == 0)); then
  report charon_service ok
else
  report charon_service conflict
fi

strongswan_conf=${SHANNON_STRONGSWAN_CONF:-/etc/strongswan.conf}
if [[ -r "$strongswan_conf" ]]; then
  report strongswan_conf ok
else
  report strongswan_conf missing
fi

strongswan_conf_dir=${SHANNON_STRONGSWAN_CONF_DIR:-/etc/strongswan.d}
if [[ -d "$strongswan_conf_dir" && -w "$strongswan_conf_dir" ]]; then
  report strongswan_conf_dir ok
else
  report strongswan_conf_dir not_writable
fi

runtime_dir=${SHANNON_RUNTIME_DIR:-/run}
if [[ -d "$runtime_dir" && -w "$runtime_dir" ]]; then
  report runtime_dir ok
else
  report runtime_dir not_writable
fi

plugin_dir=
if find_plugin_dir; then
  report plugin_dir ok
else
  report plugin_dir missing
fi

if has_plugin libstrongswan-vici.so libcharon-vici.so; then
  report vici_plugin ok
else
  report vici_plugin missing
fi

if has_plugin libstrongswan-eap-aka.so libcharon-eap-aka.so; then
  report eap_aka_method_plugin ok
else
  report eap_aka_method_plugin missing
fi

if has_plugin libstrongswan-eap-identity.so libcharon-eap-identity.so; then
  report eap_identity_plugin ok
else
  report eap_identity_plugin missing
fi

if [[ "$dataplane" == userspace ]]; then
  if has_plugin libstrongswan-kernel-libipsec.so libcharon-kernel-libipsec.so; then
    report kernel_libipsec_plugin ok
  else
    report kernel_libipsec_plugin missing
  fi
else
  report kernel_libipsec_plugin not_required
fi

if has_plugin libstrongswan-kernel-netlink.so libcharon-kernel-netlink.so; then
  report kernel_netlink_plugin ok
else
  report kernel_netlink_plugin missing
fi

if has_plugin libstrongswan-eap-aka-vohive.so; then
  report eap_aka_plugin ok
else
  report eap_aka_plugin missing
fi

if has_plugin libstrongswan-p-cscf-vohive.so; then
  report p_cscf_plugin ok
else
  report p_cscf_plugin missing
fi

tun_device=${SHANNON_TUN_DEVICE:-/dev/net/tun}
if [[ "$dataplane" == userspace ]]; then
  if [[ -c "$tun_device" && -r "$tun_device" && -w "$tun_device" ]]; then
    report tun ok
  else
    report tun unavailable
  fi
else
  report tun not_required
fi

printf 'runtime_dataplane=%s\n' "$dataplane"
if ((failures == 0)); then
  printf 'runtime_preflight=pass\n'
  exit 0
fi

printf 'runtime_preflight=fail\n'
exit 1
