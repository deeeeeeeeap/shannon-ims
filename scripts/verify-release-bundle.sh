#!/usr/bin/env bash
set -euo pipefail

archive=
arch=amd64

usage() {
  cat <<'EOF'
usage: verify-release-bundle.sh --archive FILE [--arch ARCH]

Verifies the detached archive checksum, the in-bundle SHA256SUMS file,
release/runtime manifests, and Linux binary architecture without starting any
network or device activity.
EOF
}

fail() {
  printf 'bundle_smoke=fail\n'
  printf 'reason=%s\n' "$1"
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --archive)
      (($# >= 2)) || { usage >&2; exit 2; }
      archive=$2
      shift 2
      ;;
    --arch)
      (($# >= 2)) || { usage >&2; exit 2; }
      arch=$2
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

[[ -f "$archive" ]] || fail archive_missing
[[ "$arch" =~ ^[A-Za-z0-9._+-]+$ ]] || fail invalid_arch
case "$arch" in
  amd64|arm64)
    go_arch=$arch
    go_arm=
    ;;
  armv7)
    go_arch=arm
    go_arm=7
    ;;
  *)
    fail unsupported_arch
    ;;
esac
checksum_file="$archive.sha256"
[[ -f "$checksum_file" ]] || fail detached_checksum_missing

for tool in tar sha256sum mktemp grep sed readelf; do
  command -v "$tool" >/dev/null 2>&1 || fail verification_tool_missing
done

archive_dir=$(CDPATH= cd -- "$(dirname -- "$archive")" && pwd)
archive_name=$(basename -- "$archive")
(
  cd "$archive_dir"
  sha256sum -c "$archive_name.sha256" >/dev/null
) || fail detached_checksum_mismatch

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
tar -xzf "$archive" -C "$tmp_dir" || fail archive_extract_failed

shopt -s nullglob dotglob
entries=("$tmp_dir"/*)
shopt -u nullglob dotglob
[[ ${#entries[@]} -eq 1 && -d "${entries[0]}" ]] || fail archive_layout_invalid
bundle=${entries[0]}

for required in \
  bin/shannon-ims \
  config/config.example.yaml \
  SHA256SUMS \
  release-manifest.env \
  runtime-manifest.env \
  packaging/runtime/runtime-manifest.env \
  scripts/check-runtime-deps.sh
do
  [[ -e "$bundle/$required" ]] || fail required_file_missing
done
[[ ! -e "$bundle/config/config.yaml" ]] || fail runtime_config_in_archive
[[ -x "$bundle/bin/shannon-ims" ]] || fail binary_not_executable

(
  cd "$bundle"
  sha256sum -c SHA256SUMS >/dev/null
) || fail bundle_checksum_mismatch

manifest="$bundle/release-manifest.env"
grep -qx 'schema_version=1' "$manifest" || fail release_manifest_schema_invalid
grep -qx 'product=shannon-ims' "$manifest" || fail release_manifest_product_invalid
grep -qx 'os=linux' "$manifest" || fail release_manifest_os_invalid
grep -qx "arch=$arch" "$manifest" || fail release_manifest_arch_invalid
grep -qx 'binary=bin/shannon-ims' "$manifest" || fail release_manifest_binary_invalid
grep -qx 'release_bundle_runtime_complete=false' "$manifest" || fail release_manifest_runtime_state_invalid

manifest_binary_sha=$(sed -n 's/^binary_sha256=//p' "$manifest")
[[ "$manifest_binary_sha" =~ ^[0-9a-f]{64}$ ]] || fail release_manifest_binary_sha_invalid
actual_binary_sha=$(sha256sum "$bundle/bin/shannon-ims")
actual_binary_sha=${actual_binary_sha%% *}
[[ "$manifest_binary_sha" == "$actual_binary_sha" ]] || fail release_manifest_binary_sha_mismatch

runtime_manifest="$bundle/runtime-manifest.env"
grep -qx 'runtime_preflight_required=true' "$runtime_manifest" || fail runtime_manifest_preflight_missing
grep -qx 'target_plugin_build_required=true' "$runtime_manifest" || fail runtime_manifest_plugin_build_missing

elf_header=$(LC_ALL=C readelf -h "$bundle/bin/shannon-ims" 2>/dev/null) || fail binary_format_invalid
case "$arch" in
  amd64)
    grep -Eq 'Class:[[:space:]]+ELF64' <<<"$elf_header" || fail binary_arch_invalid
    grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' <<<"$elf_header" || fail binary_arch_invalid
    ;;
  arm64)
    grep -Eq 'Class:[[:space:]]+ELF64' <<<"$elf_header" || fail binary_arch_invalid
    grep -Eq 'Machine:[[:space:]]+AArch64' <<<"$elf_header" || fail binary_arch_invalid
    ;;
  armv7)
    grep -Eq 'Class:[[:space:]]+ELF32' <<<"$elf_header" || fail binary_arch_invalid
    grep -Eq 'Machine:[[:space:]]+ARM' <<<"$elf_header" || fail binary_arch_invalid
    ;;
esac

# UPX-compressed release binaries may hide Go's build-info note from
# `go version -m`. When metadata remains readable, verify it as an additional
# consistency check; ELF architecture validation above is always required.
if command -v go >/dev/null 2>&1 && go_metadata=$(go version -m "$bundle/bin/shannon-ims" 2>/dev/null); then
  grep -Fq $'build\tGOOS=linux' <<<"$go_metadata" || fail binary_goos_invalid
  grep -Fq $'build\tGOARCH='"$go_arch" <<<"$go_metadata" || fail binary_goarch_invalid
  if [[ -n "$go_arm" ]]; then
    grep -Fq $'build\tGOARM='"$go_arm" <<<"$go_metadata" || fail binary_goarm_invalid
  fi
fi

archive_sha=$(sha256sum "$archive")
archive_sha=${archive_sha%% *}
printf 'bundle_smoke=pass\n'
printf 'archive_sha256=%s\n' "$archive_sha"
printf 'binary_sha256=%s\n' "$actual_binary_sha"
printf 'release_bundle_runtime_complete=false\n'
