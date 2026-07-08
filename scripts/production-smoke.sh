#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${NOTHINGDNS_BASE_URL:-http://127.0.0.1:8080}"
METRICS_URL="${NOTHINGDNS_METRICS_URL:-http://127.0.0.1:9153/metrics}"
DNS_SERVER="${NOTHINGDNS_DNS_SERVER:-127.0.0.1}"
DNS_PORT="${NOTHINGDNS_DNS_PORT:-53}"
DNS_NAME="${NOTHINGDNS_DNS_NAME:-example.com}"
DNS_TYPE="${NOTHINGDNS_DNS_TYPE:-A}"
ZONE_NAME="${NOTHINGDNS_ZONE_NAME:-}"
ZONE_RECORD_NAME="${NOTHINGDNS_ZONE_RECORD_NAME:-}"
ZONE_RECORD_TYPE="${NOTHINGDNS_ZONE_RECORD_TYPE:-A}"
EXPECT_CLUSTER="${NOTHINGDNS_EXPECT_CLUSTER:-0}"
EXPECT_AUTH="${NOTHINGDNS_EXPECT_AUTH:-0}"

tmp_dig=""
cleanup() {
  if [[ -n "${tmp_dig}" ]]; then
    rm -f "${tmp_dig}"
  fi
}
trap cleanup EXIT

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

check_json_status() {
  local label="$1"
  local url="$2"
  local expected="$3"

  echo "checking ${label} at ${url}"
  curl -fsS --max-time 5 "${url}" | grep -q "\"status\":\"${expected}\""
}

check_auth_required() {
  local label="$1"
  local url="$2"
  local http_code
  echo "checking ${label} requires auth at ${url}"
  http_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${url}")"
  test "${http_code}" = "401"
}

check_authorized_json() {
  local label="$1"
  local url="$2"
  echo "checking authorized ${label} at ${url}"
  curl -fsS --max-time 5 "${curl_auth_args[@]}" "${url}" >/dev/null
}

check_json_status "API health" "${BASE_URL}/health" "healthy"
check_json_status "API readiness" "${BASE_URL}/readyz" "ready"
check_json_status "API liveness" "${BASE_URL}/livez" "alive"

echo "checking dashboard shell at ${BASE_URL}/"
curl -fsS --max-time 5 "${curl_auth_args[@]}" "${BASE_URL}/" | grep -q '<div id="root"></div>'

if [[ "${EXPECT_AUTH}" = "1" ]]; then
  check_auth_required "server status" "${BASE_URL}/api/v1/status"
  check_auth_required "zone list" "${BASE_URL}/api/v1/zones"
fi

if [[ ${#curl_auth_args[@]} -gt 0 ]]; then
  check_authorized_json "server status" "${BASE_URL}/api/v1/status"
  check_authorized_json "zone list" "${BASE_URL}/api/v1/zones"
  check_authorized_json "OpenAPI spec" "${BASE_URL}/api/openapi.json"
  echo "checking Swagger UI at ${BASE_URL}/api/docs"
  curl -fsS --max-time 5 "${curl_auth_args[@]}" "${BASE_URL}/api/docs" | grep -qi 'swagger'
fi

echo "checking metrics at ${METRICS_URL}"
curl -fsS --max-time 5 "${metrics_auth_args[@]}" "${METRICS_URL}" | grep -q 'nothingdns_'

if [[ "${NOTHINGDNS_SKIP_DNS:-0}" != "1" ]]; then
  require_cmd dig
  tmp_dig="$(mktemp)"
  echo "checking DNS query ${DNS_NAME} ${DNS_TYPE} via ${DNS_SERVER}:${DNS_PORT}"
  dig @"${DNS_SERVER}" -p "${DNS_PORT}" "${DNS_NAME}" "${DNS_TYPE}" +time=3 +tries=1 +short >"${tmp_dig}"
  test -s "${tmp_dig}"
fi

if [[ -n "${ZONE_NAME}" && -n "${ZONE_RECORD_NAME}" && ${#curl_auth_args[@]} -gt 0 ]]; then
  echo "checking zone record listing for ${ZONE_NAME}"
  curl -fsS --max-time 5 "${curl_auth_args[@]}" \
    "${BASE_URL}/api/v1/zones/${ZONE_NAME}/records" | grep -q '"records"'
fi

if [[ -n "${NOTHINGDNS_DOH_URL:-}" ]]; then
  echo "checking DoH endpoint at ${NOTHINGDNS_DOH_URL}"
  doh_bytes="$(curl -fsS --max-time 5 \
    -H 'accept: application/dns-message' \
    "${NOTHINGDNS_DOH_URL}?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" | wc -c)"
  test "${doh_bytes}" -gt 0
fi

if [[ -n "${NOTHINGDNS_CLUSTER_STATUS_URL:-}" ]]; then
  echo "checking cluster status at ${NOTHINGDNS_CLUSTER_STATUS_URL}"
  curl -fsS --max-time 5 "${curl_auth_args[@]}" "${NOTHINGDNS_CLUSTER_STATUS_URL}" | grep -Eq '"(healthy|enabled|node_count)"'
fi

if [[ "${EXPECT_CLUSTER}" = "1" && -n "${NOTHINGDNS_CLUSTER_STATUS_URL:-}" ]]; then
  echo "checking cluster expectation at ${NOTHINGDNS_CLUSTER_STATUS_URL}"
  curl -fsS --max-time 5 "${curl_auth_args[@]}" "${NOTHINGDNS_CLUSTER_STATUS_URL}" | grep -q '"enabled":true'
fi

echo "production smoke passed"
