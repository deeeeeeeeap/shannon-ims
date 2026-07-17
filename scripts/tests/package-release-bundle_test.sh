#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
packager="$root_dir/scripts/package-release-bundle.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

fake_binary="$tmp_dir/shannon-ims"
printf '#!/usr/bin/env sh\nexit 0\n' >"$fake_binary"
chmod 0755 "$fake_binary"

package_output="$tmp_dir/package.out"
bash "$packager" \
  --binary "$fake_binary" \
  --version v-test \
  --arch amd64 \
  --output "$tmp_dir/out" >"$package_output"

archive="$tmp_dir/out/shannon-ims_v-test_linux_amd64.tar.gz"
test -f "$archive"
test -f "$archive.sha256"
(
  cd "$tmp_dir/out"
  sha256sum -c "$(basename "$archive").sha256" >/dev/null
)

mkdir -p "$tmp_dir/extracted"
tar -xzf "$archive" -C "$tmp_dir/extracted"
bundle="$tmp_dir/extracted/shannon-ims_v-test_linux_amd64"

test -x "$bundle/bin/shannon-ims"
test -f "$bundle/config/config.example.yaml"
test ! -e "$bundle/config/config.yaml"
test -f "$bundle/scripts/check-runtime-deps.sh"
test -f "$bundle/scripts/build-strongswan-plugins.sh"
test -f "$bundle/scripts/verify-release-bundle.sh"
test -f "$bundle/scripts/install-local.sh"
test -f "$bundle/README.md"
test -f "$bundle/runtime-manifest.env"
test -f "$bundle/release-manifest.env"
test -f "$bundle/LICENSE"
test -f "$bundle/NOTICE.md"
test -f "$bundle/packaging/runtime/runtime-manifest.env"
test -f "$bundle/packaging/runtime/README.md"
test -f "$bundle/vowifi-go/engine/swu/akabridge/plugin/Makefile"
test -f "$bundle/vowifi-go/engine/swu/akabridge/plugin/test/card_test.c"
test -f "$bundle/vowifi-go/engine/swu/pcscfbridge/plugin/Makefile"
grep -qx 'target_plugin_build_required=true' "$bundle/packaging/runtime/runtime-manifest.env"
grep -qx 'schema_version=1' "$bundle/release-manifest.env"
grep -qx 'product=shannon-ims' "$bundle/release-manifest.env"
grep -qx 'version=v-test' "$bundle/release-manifest.env"
grep -qx 'os=linux' "$bundle/release-manifest.env"
grep -qx 'arch=amd64' "$bundle/release-manifest.env"
grep -qx 'binary=bin/shannon-ims' "$bundle/release-manifest.env"
grep -Eq '^binary_sha256=[0-9a-f]{64}$' "$bundle/release-manifest.env"
grep -qx 'release_bundle_runtime_complete=false' "$bundle/release-manifest.env"

(
  cd "$bundle"
  sha256sum -c SHA256SUMS >/dev/null
)

grep -qx 'release_bundle=pass' "$package_output"
grep -qx 'release_bundle_runtime_complete=false' "$package_output"
grep -qx 'target_plugin_build_required=true' "$package_output"
if grep -Fq "$tmp_dir" "$package_output"; then
  printf 'release packager output exposed a host path\n' >&2
  exit 1
fi

printf 'package_release_bundle_test=pass\n'
