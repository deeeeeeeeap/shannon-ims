#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root_dir"

version="${VERSION:-dev}"
build_time=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
go_tags="${GO_TAGS:-with_utls nomsgpack}"
output="$root_dir/dist/shannon-ims_linux_amd64"

command -v go >/dev/null
command -v npm >/dev/null

npm ci --prefix "$root_dir/web"
npm run build --prefix "$root_dir/web"

rm -rf "$root_dir/internal/web/dist"
mkdir -p "$root_dir/internal/web" "$root_dir/dist"
cp -R "$root_dir/web/dist" "$root_dir/internal/web/dist"

ldflags="-s -w -X github.com/1239t/vohive/internal/global.Version=$version -X github.com/1239t/vohive/internal/global.BuildTime=$build_time"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -buildvcs=false \
  -tags "$go_tags" \
  -ldflags "$ldflags" \
  -o "$output" ./cmd/vohive

sha256sum "$output"
