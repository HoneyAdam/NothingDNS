#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${NOTHINGDNS_BASE_URL:-http://127.0.0.1:8080}"
METRICS_URL="${NOTHINGDNS_METRICS_URL:-http://127.0.0.1:9153/metrics}"
DNS_SERVER="${NOTHINGDNS_DNS_SERVER:-127.0.0.1}"
DNS_PORT="${NOTHINGDNS_DNS_PORT:-53}"
DNS_NAME="${NOTHINGDNS_DNS_NAME:-example.com}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

curl_auth_args=()
if [[ -n "${NOTHINGDNS_AUTH_TOKEN:-}" ]]; then
  curl_auth_args=(-H "Authorization: Bearer ${NOTHINGDNS_AUTH_TOKEN}")
fi

metrics_auth_args=()
if [[ -n "${NOTHINGDNS_METRICS_AUTH_TOKEN:-}" ]]; then
  metrics_auth_args=(-H "Authorization: Bearer ${NOTHINGDNS_METRICS_AUTH_TOKEN}")
fi

require_cmd curl

echo "checking API health at ${BASE_URL}/health"
curl -fsS --max-time 5 "${BASE_URL}/health" >/dev/null

echo "checking dashboard shell at ${BASE_URL}/"
curl -fsS --max-time 5 "${curl_auth_args[@]}" "${BASE_URL}/" | grep -q '<div id="root"></div>'

echo "checking metrics at ${METRICS_URL}"
curl -fsS --max-time 5 "${metrics_auth_args[@]}" "${METRICS_URL}" | grep -q 'nothingdns_'

if [[ "${NOTHINGDNS_SKIP_DNS:-0}" != "1" ]]; then
  require_cmd dig
  echo "checking DNS query ${DNS_NAME} A via ${DNS_SERVER}:${DNS_PORT}"
  dig @"${DNS_SERVER}" -p "${DNS_PORT}" "${DNS_NAME}" A +time=3 +tries=1 +short >/tmp/nothingdns-smoke-dig.out
  test -s /tmp/nothingdns-smoke-dig.out
fi

if [[ -n "${NOTHINGDNS_DOH_URL:-}" ]]; then
  echo "checking DoH endpoint at ${NOTHINGDNS_DOH_URL}"
  curl -fsS --max-time 5 \
    -H 'accept: application/dns-message' \
    "${NOTHINGDNS_DOH_URL}?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" >/dev/null
fi

if [[ -n "${NOTHINGDNS_CLUSTER_STATUS_URL:-}" ]]; then
  echo "checking cluster status at ${NOTHINGDNS_CLUSTER_STATUS_URL}"
  curl -fsS --max-time 5 "${curl_auth_args[@]}" "${NOTHINGDNS_CLUSTER_STATUS_URL}" | grep -Eq '"(healthy|enabled|node_count)"'
fi

echo "production smoke passed"
