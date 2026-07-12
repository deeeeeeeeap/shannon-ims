#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=${1:?usage: install-local.sh <binary> [prefix]}
prefix=${2:-/opt/shannon-ims}

test -f "$binary"

install -d -m 0755 "$prefix/bin" "$prefix/config" "$prefix/data" "$prefix/logs"
install -m 0755 "$binary" "$prefix/bin/shannon-ims"

if [[ ! -e "$prefix/config/config.yaml" ]]; then
  install -m 0600 "$root_dir/config/config.example.yaml" "$prefix/config/config.yaml"
  printf 'created_config=%s\n' "$prefix/config/config.yaml"
  printf 'action_required=edit every placeholder before first run\n'
else
  printf 'existing_config_preserved=%s\n' "$prefix/config/config.yaml"
fi

printf 'installed_binary=%s\n' "$prefix/bin/shannon-ims"
printf 'run_command=%s\n' "$prefix/bin/shannon-ims -c $prefix/config/config.yaml"
