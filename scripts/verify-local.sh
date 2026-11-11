#!/usr/bin/env bash
# Runs every check of the CI workflow (.github/workflows/ci.yml) on this
# machine, and the race detector on the packages that stand in for hardware
# and for outside services as well.
#
# No modem, SIM, proxy, ePDG or notification service is needed: only Linux
# with go, node and npm, python3 and the usual shell tools on PATH.
set -uo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root_dir"

skip_frontend=0
skip_race=0
skip_bundle=0

usage() {
  cat <<'EOF'
usage: verify-local.sh [--skip-frontend] [--skip-race] [--skip-bundle]

Runs the checks of the CI workflow in the order the workflow needs them:
frontend (install, lint, typecheck, tests, build), tests and vet of the
three Go modules, race tests, privacy scan and script tests, and the smoke
build of the Linux amd64 release bundle.

  --skip-frontend  keep internal/web/dist as it is instead of rebuilding it
  --skip-race      leave out the race tests
  --skip-bundle    leave out the release bundle

The last lines list every step with its result. The exit status is 0 only
when every step has passed.
EOF
}

while (($# > 0)); do
  case "$1" in
    --skip-frontend) skip_frontend=1 ;;
    --skip-race) skip_race=1 ;;
    --skip-bundle) skip_bundle=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "$(uname -s)" != Linux ]]; then
  printf 'verify_local=fail\nreason=linux_required\n'
  exit 2
fi

tools=(go python3 tar sha256sum)
((skip_frontend)) || tools+=(node npm)
for tool in "${tools[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'verify_local=fail\nreason=tool_missing\ntool=%s\n' "$tool"
    exit 2
  }
done

if ((skip_frontend)) && [[ ! -f internal/web/dist/index.html ]]; then
  # The root module embeds internal/web/dist and does not build without it.
  printf 'verify_local=fail\nreason=frontend_assets_missing\n'
  exit 2
fi

failed=0
results=()

# step NAME COMMAND...  runs the command and notes whether it passed.
step() {
  local name=$1
  shift
  local started=$SECONDS result=ok
  printf '\n### %s\n' "$name"
  "$@" || {
    result=FAIL
    failed=1
  }
  results+=("$(printf '%-4s %s (%ds)' "$result" "$name" "$((SECONDS - started))")")
}

# in_module DIR COMMAND...  runs the command in the Go module at DIR.
in_module() {
  local dir=$1
  shift
  (cd "$root_dir/$dir" && "$@")
}

sync_frontend_assets() {
  rm -rf internal/web/dist &&
    mkdir -p internal/web &&
    cp -R web/dist internal/web/dist
}

bundle_smoke() {
  local out=dist/verify-local
  local version build_time
  version="local-$(git rev-parse --short=12 HEAD 2>/dev/null || echo worktree)"
  build_time=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
  rm -rf "$out" && mkdir -p "$out" || return 1
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -buildvcs=false \
    -tags "with_utls nomsgpack" \
    -ldflags "-s -w -X 'github.com/1239t/vohive/internal/global.Version=$version' -X 'github.com/1239t/vohive/internal/global.BuildTime=$build_time'" \
    -o "$out/shannon-ims" ./cmd/vohive || return 1
  bash scripts/package-release-bundle.sh \
    --binary "$out/shannon-ims" \
    --version "$version" \
    --arch amd64 \
    --output "$out" || return 1
  bash scripts/verify-release-bundle.sh \
    --archive "$out/shannon-ims_${version}_linux_amd64.tar.gz" \
    --arch amd64
}

if ((!skip_frontend)); then
  step "frontend: install locked dependencies" npm ci --prefix web
  step "frontend: lint" npm run lint --prefix web
  step "frontend: typecheck" npm run typecheck --prefix web
  step "frontend: tests" npm test --prefix web
  step "frontend: build" npm run build --prefix web
  step "frontend: sync embedded assets" sync_frontend_assets
fi

for module in . vowifi-go third_party/swu-go; do
  step "go test [$module]" in_module "$module" go test ./... -count=1
  step "go vet [$module]" in_module "$module" go vet ./...
done

if ((!skip_race)); then
  # The lists of the workflow, and after them the simulators and the code that
  # is only reached through them.
  step "race [.]" in_module . go test -race -count=1 \
    ./internal/apduarbiter \
    ./internal/config \
    ./internal/device \
    ./internal/esim \
    ./internal/modem \
    ./internal/notify \
    ./internal/vowifihost \
    ./pkg/logger \
    ./internal/simulation/... \
    ./internal/upstreamproxy/...
  step "race [vowifi-go]" in_module vowifi-go go test -race -count=1 \
    ./internal/vowifi/ipsec3gpp \
    ./internal/vowifi/imscore \
    ./runtimehost \
    ./runtimehost/simauth \
    ./runtimehost/voiceclient \
    ./runtimehost/transport/...
  step "race [third_party/swu-go]" in_module third_party/swu-go go test -race -count=1 \
    ./pkg/crypto \
    ./pkg/ikev2 \
    ./pkg/ipsec \
    ./pkg/swu
fi

step "privacy scan" python3 scripts/check-repository-privacy.py
step "python contract tests" python3 -m unittest discover -s scripts/tests -p 'test_*.py'
for name in check-runtime-deps build-strongswan-plugins install-local package-release-bundle verify-release-bundle; do
  step "script test: $name" bash "scripts/tests/${name}_test.sh"
done

if ((!skip_bundle)); then
  step "release bundle smoke" bundle_smoke
fi

printf '\n### summary\n'
printf '%s\n' "${results[@]}"
if ((failed)); then
  printf 'verify_local=fail\n'
  exit 1
fi
printf 'verify_local=pass\n'
