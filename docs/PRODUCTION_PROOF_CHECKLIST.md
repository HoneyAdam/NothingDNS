# Production Proof Checklist

This document is the **evidence pack template** for release readiness. The goal is to prove behavior with repeatable commands, not to rely on broad claims.

## How to use this document

For every section below, capture:

- the exact command used
- pass/fail result
- artifact path (if any)
- operator notes / deviations

If a section cannot be executed for the target environment, mark it explicitly as **NOT VERIFIED**.

---

## 1. Build and static validation

### Required checks

```bash
go build ./...
go vet ./...
git diff --check
npm --prefix web run lint
npm --prefix web run build
npm --prefix web run smoke
```

### Record

- Build pass: `YES / NO`
- Vet pass: `YES / NO`
- Web lint/build/smoke pass: `YES / NO`
- Notes:

---

## 2. Config validation proof

### Raw config validation

```bash
go run ./cmd/nothingdns -config config.example.yaml -validate-config
```

### Production config validation

Run with real secrets/environment values:

```bash
go run ./cmd/nothingdns -config deploy/production.yaml -validate-production-config
```

### Record

- Example config valid: `YES / NO`
- Production config valid: `YES / NO`
- Missing-env warnings seen: `YES / NO`
- Notes:

---

## 3. Zone durability proof

Goal: prove that zone data survives restart through the intended persistence path.

### Minimum proof scenarios

#### A. File-backed zone survives restart

- start daemon with configured zone file
- query zone
- restart daemon
- query same zone again

#### B. KV-backed/API-created zone survives restart

- create zone through API
- add record through API
- restart daemon
- verify zone and record still exist

#### C. Zone deletion persists

- delete KV-backed zone
- restart daemon
- verify it does not reappear

### Suggested evidence commands

```bash
# create zone via API (example)
curl -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"proof.example.","nameservers":["ns1.proof.example."],"admin_email":"admin.proof.example.","ttl":3600}' \
  http://127.0.0.1:8080/api/v1/zones

curl -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"www","type":"A","data":"192.0.2.55","ttl":300}' \
  http://127.0.0.1:8080/api/v1/zones/proof.example./records
```

### Required evidence

- API response transcript or saved JSON
- post-restart zone list
- post-restart record list
- deletion proof after restart

### Record

- File-backed durability verified: `YES / NO`
- KV-backed durability verified: `YES / NO`
- Delete durability verified: `YES / NO`
- Notes:

---

## 4. Raft proof

Goal: prove that the cluster does not merely compile but behaves correctly under real operator flows.

### Minimum proof scenarios

#### A. Leader election
- bring up 3 nodes in `consensus_mode: raft`
- verify one leader emerges

#### B. Follower replication
- apply a zone change on leader
- verify follower reflects it

#### C. Restart recovery
- restart follower
- verify state returns

#### D. Snapshot/install-snapshot path
- generate enough state to snapshot
- verify lagging or restarted node catches up

### Required runtime evidence

- `/api/v1/cluster/status` outputs from all nodes
- leader ID / node counts
- zone/record proof before and after restart
- logs for snapshot/install-snapshot if available

### Record

- Leader election verified: `YES / NO`
- Replication verified: `YES / NO`
- Restart recovery verified: `YES / NO`
- Snapshot catch-up verified: `YES / NO`
- Notes:

---

## 5. Management plane proof

### API proof

Verify these return credible responses, not just HTTP 200:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/livez
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/status
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/zones
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/openapi.json
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/docs
```

### Web UI proof

Verify:

- dashboard shell loads
- login works against backend auth
- at least one zone page renders from real data
- query log / cluster / settings pages load without crashing

### Record

- API surface verified: `YES / NO`
- Web shell verified: `YES / NO`
- Login verified: `YES / NO`
- Real data pages verified: `YES / NO`
- Notes:

---

## 6. Metrics and observability proof

### Metrics endpoint

```bash
curl -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:9153/metrics
```

### Verify presence of

- `nothingdns_queries_total`
- `nothingdns_cache_hits_total`
- `nothingdns_errors_total`
- cluster metrics if cluster mode enabled

### Record

- Metrics endpoint verified: `YES / NO`
- Auth on metrics verified: `YES / NO`
- Notes:

---

## 7. Performance proof

Do not claim performance leadership without comparative measurements.

### Capture

```bash
go test ./internal/protocol -run '^$' -bench . -benchmem -count 5
go test ./internal/cache -run '^$' -bench . -benchmem -count 5
go test ./internal/dnssec -run '^$' -bench . -benchmem -count 5
```

### Record

- Protocol benchmark captured: `YES / NO`
- Cache benchmark captured: `YES / NO`
- DNSSEC benchmark captured: `YES / NO`
- Competitor comparison captured: `YES / NO`
- Notes:

---

## 8. Smoke proof

Use the repo smoke script:

```bash
NOTHINGDNS_BASE_URL='http://127.0.0.1:8080' \
NOTHINGDNS_METRICS_URL='http://127.0.0.1:9153/metrics' \
NOTHINGDNS_DNS_SERVER='127.0.0.1' \
NOTHINGDNS_DNS_PORT='53' \
NOTHINGDNS_DNS_NAME='example.com' \
NOTHINGDNS_DNS_TYPE='A' \
NOTHINGDNS_AUTH_TOKEN="$TOKEN" \
NOTHINGDNS_METRICS_AUTH_TOKEN="$METRICS_TOKEN" \
scripts/production-smoke.sh
```

### Record

- Smoke pass: `YES / NO`
- Environment used:
- Notes:

---

## 9. Final release verdict

Only mark **PROVEN READY** when the following are all true:

- build/static checks passed
- configs validated
- zone durability proven
- Raft scenarios proven (if cluster mode is part of release scope)
- API and web UI verified
- metrics verified
- smoke verified

### Final status

- `PROVEN READY`
- `READY WITH GAPS`
- `NOT PROVEN`

### Release approver notes

- Scope of proof:
- Remaining unverified items:
- Risks accepted:
