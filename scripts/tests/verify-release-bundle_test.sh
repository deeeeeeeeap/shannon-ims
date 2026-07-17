#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

cat >"$tmp_dir/main.go" <<'EOF'
package main

func main() {}
EOF

for target in amd64:amd64: arm64:arm64: armv7:arm:7; do
  IFS=: read -r artifact_arch goarch goarm <<<"$target"
  binary="$tmp_dir/shannon-ims-$artifact_arch"
  output_dir="$tmp_dir/out-$artifact_arch"
  output="$tmp_dir/verify-$artifact_arch.out"

  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" \
    go build -trimpath -buildvcs=false -o "$binary" "$tmp_dir/main.go"
  bash "$root_dir/scripts/package-release-bundle.sh" \
    --binary "$binary" \
    --version v-test \
    --arch "$artifact_arch" \
    --output "$output_dir" >/dev/null

  bash "$root_dir/scripts/verify-release-bundle.sh" \
    --archive "$output_dir/shannon-ims_v-test_linux_${artifact_arch}.tar.gz" \
    --arch "$artifact_arch" >"$output"

  grep -qx 'bundle_smoke=pass' "$output"
  grep -Eq '^archive_sha256=[0-9a-f]{64}$' "$output"
  grep -Eq '^binary_sha256=[0-9a-f]{64}$' "$output"
  grep -qx 'release_bundle_runtime_complete=false' "$output"
  if grep -Fq "$tmp_dir" "$output"; then
    printf 'bundle verifier output exposed a host path\n' >&2
    exit 1
  fi
done

printf 'verify_release_bundle_test=pass\n'
