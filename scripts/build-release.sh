#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/dist}"
VERSION="${VERSION:-}"
COMMIT="${COMMIT:-}"
DATE="${DATE:-}"
TARGETS="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64}"

if [[ -z "${VERSION}" ]]; then
  if git -C "${ROOT_DIR}" describe --tags --exact-match >/dev/null 2>&1; then
    VERSION="$(git -C "${ROOT_DIR}" describe --tags --exact-match)"
  else
    VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
  fi
fi
if [[ -z "${COMMIT}" ]]; then
  COMMIT="$(git -C "${ROOT_DIR}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
fi
if [[ -z "${DATE}" ]]; then
  DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

LDFLAGS="-s -w -X github.com/nothingdns/nothingdns/internal/util.Version=${VERSION}"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

printf 'Building NothingDNS release binaries\n'
printf '  version: %s\n' "${VERSION}"
printf '  commit:  %s\n' "${COMMIT}"
printf '  date:    %s\n' "${DATE}"
printf '  output:  %s\n' "${OUT_DIR}"

for target in ${TARGETS}; do
  os="${target%/*}"
  arch="${target#*/}"
  ext=""
  if [[ "${os}" == "windows" ]]; then
    ext=".exe"
  fi

  printf 'Building %s/%s...\n' "${os}" "${arch}"
  CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
    -trimpath -ldflags "${LDFLAGS}" \
    -o "${OUT_DIR}/nothingdns-${os}-${arch}${ext}" "${ROOT_DIR}/cmd/nothingdns"
  CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
    -trimpath -ldflags "${LDFLAGS}" \
    -o "${OUT_DIR}/dnsctl-${os}-${arch}${ext}" "${ROOT_DIR}/cmd/dnsctl"
done

(
  cd "${OUT_DIR}"
  sha256sum nothingdns-* dnsctl-* > SHA256SUMS
)

printf 'Release artifacts:\n'
ls -lh "${OUT_DIR}"
printf '\nChecksums:\n'
cat "${OUT_DIR}/SHA256SUMS"
