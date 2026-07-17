#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=
version=
arch=
output_dir="$root_dir/dist"

usage() {
  cat <<'EOF'
usage: package-release-bundle.sh --binary FILE --version VERSION --arch ARCH [--output DIR]

Creates a release archive containing the Go binary, example configuration,
runtime preflight/build/install scripts, and target-buildable strongSwan plugin
sources. The archive is intentionally marked runtime-incomplete until the
target-specific plugins are built, installed, and the preflight passes.
EOF
}

while (($# > 0)); do
  case "$1" in
    --binary)
      (($# >= 2)) || { usage >&2; exit 2; }
      binary=$2
      shift 2
      ;;
    --version)
      (($# >= 2)) || { usage >&2; exit 2; }
      version=$2
      shift 2
      ;;
    --arch)
      (($# >= 2)) || { usage >&2; exit 2; }
      arch=$2
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

[[ -f "$binary" ]] || { printf 'release_bundle=fail\nreason=binary_missing\n'; exit 1; }
[[ "$version" =~ ^[A-Za-z0-9._+-]+$ ]] || { printf 'release_bundle=fail\nreason=invalid_version\n'; exit 1; }
[[ "$arch" =~ ^[A-Za-z0-9._+-]+$ ]] || { printf 'release_bundle=fail\nreason=invalid_arch\n'; exit 1; }

for tool in install tar sha256sum find sort xargs; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'release_bundle=fail\nreason=packaging_tool_missing\n'
    exit 1
  }
done

bundle_name="shannon-ims_${version}_linux_${arch}"
archive_name="$bundle_name.tar.gz"
mkdir -p "$output_dir"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
bundle="$tmp_dir/$bundle_name"

install -d -m 0755 \
  "$bundle/bin" \
  "$bundle/config" \
  "$bundle/scripts" \
  "$bundle/packaging/runtime" \
  "$bundle/vowifi-go/engine/swu/akabridge/plugin" \
  "$bundle/vowifi-go/engine/swu/akabridge/plugin/test" \
  "$bundle/vowifi-go/engine/swu/pcscfbridge/plugin"

install -m 0755 "$binary" "$bundle/bin/shannon-ims"
install -m 0644 "$root_dir/config/config.example.yaml" "$bundle/config/config.example.yaml"
install -m 0644 "$root_dir/LICENSE" "$root_dir/NOTICE.md" "$bundle/"
install -m 0755 \
  "$root_dir/scripts/check-runtime-deps.sh" \
  "$root_dir/scripts/build-strongswan-plugins.sh" \
  "$root_dir/scripts/verify-release-bundle.sh" \
  "$root_dir/scripts/install-local.sh" \
  "$bundle/scripts/"
install -m 0644 \
  "$root_dir/packaging/runtime/runtime-manifest.env" \
  "$root_dir/packaging/runtime/README.md" \
  "$bundle/packaging/runtime/"
install -m 0644 "$root_dir/packaging/runtime/README.md" "$bundle/README.md"
install -m 0644 "$root_dir/packaging/runtime/runtime-manifest.env" "$bundle/runtime-manifest.env"

binary_sha256=$(sha256sum "$binary")
binary_sha256=${binary_sha256%% *}
cat >"$bundle/release-manifest.env" <<EOF
schema_version=1
product=shannon-ims
version=$version
os=linux
arch=$arch
binary=bin/shannon-ims
binary_sha256=$binary_sha256
release_bundle_runtime_complete=false
EOF

install -m 0644 \
  "$root_dir/vowifi-go/engine/swu/akabridge/plugin/Makefile" \
  "$root_dir/vowifi-go/engine/swu/akabridge/plugin/"*.c \
  "$root_dir/vowifi-go/engine/swu/akabridge/plugin/"*.h \
  "$bundle/vowifi-go/engine/swu/akabridge/plugin/"
install -m 0644 \
  "$root_dir/vowifi-go/engine/swu/akabridge/plugin/test/"*.c \
  "$bundle/vowifi-go/engine/swu/akabridge/plugin/test/"
install -m 0644 \
  "$root_dir/vowifi-go/engine/swu/pcscfbridge/plugin/Makefile" \
  "$root_dir/vowifi-go/engine/swu/pcscfbridge/plugin/"*.c \
  "$root_dir/vowifi-go/engine/swu/pcscfbridge/plugin/"*.h \
  "$bundle/vowifi-go/engine/swu/pcscfbridge/plugin/"

(
  cd "$bundle"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum >SHA256SUMS
)

tar -czf "$output_dir/$archive_name" -C "$tmp_dir" "$bundle_name"
(
  cd "$output_dir"
  sha256sum "$archive_name" >"$archive_name.sha256"
)

printf 'release_bundle=pass\n'
printf 'release_bundle_runtime_complete=false\n'
printf 'target_plugin_build_required=true\n'
printf 'archive=%s\n' "$archive_name"
