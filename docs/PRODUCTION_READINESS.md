# NothingDNS Production Readiness Report

Last updated: 2026-05-24

## Verdict

NothingDNS is production-ready after the current hardening pass, provided the release candidate is built from the checked-in source plus the generated dashboard assets and all release gates below pass in CI.

No known HIGH or MEDIUM production blockers remain in the audited surface. The remaining items are operational choices or non-blocking tuning work.

## Release Gates

Run these before tagging or promoting an image:

```bash
npm --prefix web run lint
npm --prefix web run build

git diff --check
go build ./...
go vet ./...
/tmp/nothingdns-tools/actionlint

/tmp/nothingdns-helm-bin/helm lint deploy/helm/nothingdns \
  --set-string auth.authSecret='AuthSecret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
  --set-string auth.adminPassword='AdminPassword-1234567890-ABCDE'

go test ./... -count=1 -short
```

Validate rendered deployment configs:

```bash
# Raw Kubernetes ConfigMap config
awk '/^  config.yaml: \|/{flag=1; next} flag { if (substr($0,1,4)=="    ") print substr($0,5); else if ($0=="") print ""; else flag=0 }' \
  deploy/k8s/configmap.yaml > /tmp/nothingdns-k8s-config.yaml
sed -i \
  -e "s/\${NOTHINGDNS_AUTH_SECRET}/AuthSecret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ/g" \
  -e "s/\${NOTHINGDNS_ADMIN_PASSWORD}/AdminPassword-1234567890-ABCDE/g" \
  -e "s/\${NOTHINGDNS_METRICS_AUTH_TOKEN}/MetricsToken-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ/g" \
  -e "s/\${NOTHINGDNS_CLUSTER_ENCRYPTION_KEY}/ClusterKey-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ/g" \
  -e "s/\${POD_NAME}/nothingdns-0/g" \
  -e "s/\${POD_IP}/127.0.0.1/g" \
  /tmp/nothingdns-k8s-config.yaml
go run ./cmd/nothingdns -config /tmp/nothingdns-k8s-config.yaml -validate-config

# Production config, with all required secrets present
NOTHINGDNS_AUTH_TOKEN='AuthToken-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
NOTHINGDNS_AUTH_SECRET='AuthSecret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
NOTHINGDNS_ADMIN_PASSWORD='AdminPassword-1234567890-ABCDE' \
NOTHINGDNS_OPERATOR_PASSWORD='OperatorPassword-1234567890-ABCDE' \
NOTHINGDNS_VIEWER_PASSWORD='ViewerPassword-1234567890-ABCDE' \
NOTHINGDNS_METRICS_AUTH_TOKEN='MetricsToken-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
NOTHINGDNS_CLUSTER_ENCRYPTION_KEY='ClusterKey-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
go run ./cmd/nothingdns -config deploy/production.yaml -validate-config
```

The production validation should complete without missing-environment warnings.

## Closed Production Gaps

### Configuration and Deployability

- The custom YAML parser now reads production-critical fields that were previously documented but ignored: top-level `rrl`, `blocklist.urls`, `cache.serve_stale`, `cache.stale_grace_secs`, `server.pid_file`, `zonemd`, `shutdown_timeout`, and transfer policy.
- Production, staging, raw Kubernetes, and Helm-rendered configs validate through the actual daemon parser.
- Helm chart defaults now render valid NothingDNS config by default, including secret/env wiring, transfer policy, metrics auth, ingress/service ports, and network policy behavior.
- `deploy/production.yaml` documents all auth secrets as environment inputs; `docs/DEPLOYMENT_CHECKLIST.md` includes the full required env set.

### Security Behavior

- Metrics endpoints support auth token wiring in deployment manifests.
- Zone transfer is deny-by-default through `transfer.allow_list`; AXFR serving no longer depends on stale doc-only `allow-transfer` wording.
- Cluster startup no longer fails open. If `cluster.enabled=true` and cluster init/start fails, the daemon startup fails instead of silently running standalone.
- DSO session IDs now fail closed if `crypto/rand` is unavailable instead of falling back to predictable sequential IDs.
- DNSSEC `RRSIGForRRSet` now canonicalizes RRSet ordering and propagates RDATA packing errors.
- Graceful shutdown and test cleanup paths were hardened to reduce race and lifecycle ambiguity.

### CI and Supply Chain

- GitHub Actions workflows were tightened for Go, web, Helm, actionlint, container SBOM/provenance, and keyless signing.
- Codecov action usage is pinned.
- Helm lint and rendered-config validation are release gates.

### Dashboard

- The React dashboard passes lint and production build.
- Route-level code splitting removed the large Vite chunk warning; the main dashboard JS chunk is now below the warning threshold and pages load as separate chunks.
- `web/go.mod` is intentionally present as a nested Go module sentinel so root `go test ./...` does not traverse Go packages inside `web/node_modules`.

### Repository Hygiene

- Debug-printing parser tests were converted into assertion-based tests and renamed.
- `security-report/` is ignored for local scan artifacts while `security-report/SECURITY-REPORT.md` remains trackable as the finding ledger.
- Stale documentation examples were updated to match the current config schema and CLI/API behavior.

## Required Operator Inputs

For `deploy/production.yaml`, provide these as secrets in the runtime environment:

```bash
NOTHINGDNS_AUTH_SECRET
NOTHINGDNS_ADMIN_PASSWORD
NOTHINGDNS_OPERATOR_PASSWORD
NOTHINGDNS_VIEWER_PASSWORD
NOTHINGDNS_METRICS_AUTH_TOKEN
NOTHINGDNS_CLUSTER_ENCRYPTION_KEY
```

Recommended generation:

```bash
openssl rand -base64 32  # auth/user/metrics secrets
openssl rand -hex 32     # cluster encryption key
```

Do not commit literal secret values to any config file. The config validator rejects common placeholder secret strings and low-entropy secrets.

## Residual Non-Blockers

- Browser-level dashboard smoke tests are not currently part of the release gate. Add Playwright route checks if visual regression coverage is required.
- Dashboard code splitting creates many small chunks. The current build is acceptable, but chunk grouping can be tuned later if request overhead matters for a specific deployment path.
- `security-report/` may contain local ignored scan artifacts in a developer workspace. They are intentionally excluded from git except the main ledger.
- Production TLS certificate files, zone files, root trust anchor files, and runtime secrets must exist on target hosts or be provided by Kubernetes/Helm before startup.

## Promotion Checklist

- All release gates above pass on a clean checkout.
- `npm --prefix web run build` output is committed under `internal/dashboard/static/dist/`.
- Container image is built from the verified tree and includes SBOM/provenance.
- Deployment config validates with real secret values in the target environment.
- DNS, DoT/DoH, metrics, health, cluster, and dashboard endpoints are smoke-tested after rollout.
