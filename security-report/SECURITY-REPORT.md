# NothingDNS — Security Report

**Date:** 2026-05-23
**Branch:** main @ HEAD (post fuzz-harness + race-detector hardening)
**Pipeline:** security-check 4-phase (Recon → Hunt × 9 parallel agents → Verify → Report)
**Predecessor report:** `SECURITY-REPORT-2026-05-05.md` (~2.5 weeks ago; archived locally, not in git)

## Status update (post-audit fixes applied 2026-05-23)

**All 2 HIGHs + all 12 MEDIUMs FIXED same-day, each with a verified regression test.** Commit graph:

| # | Commit | Fix |
|---|---|---|
| H-1 | `0fb1008` | dashboard auth_secret-as-bearer fallback removed |
| H-2 | `163f87f` | fetchDS authenticated NSEC/NSEC3 DS-denial proof required |
| M-3 | `9e78726` | Raft mTLS dialer sets RootCAs |
| M-6 | `59311b4` | DDNS prereq check inside zone lock + typed error |
| M-7 | `5c0b955` | DoWS per-connection rate limit (100 q/s) |
| M-5 | `77c60ef` | rate-limit eviction by lastTime (true LRU) |
| M-2 | `7baf246` | cache long-name key uses process-seeded maphash |
| M-1 | `a19c373` | KVStore TLV payloadLen capped at 64 MiB |
| M-4 | `c9111b9` | API blocklist error messages sanitized |
| M-8…12 | `a0c2999` | docker-compose hardening + healthcheck + CI pinning |

Each Go-level fix includes a regression test that was verified to FAIL with the bug restored and PASS with the fix in place. Infrastructure fixes (M-8 through M-12) are non-code changes with no regression-test surface; the diff itself is the audit artifact.

The 16 LOW findings remain open as roadmap items.

---

## Executive Summary

NothingDNS continues to demonstrate **strong security fundamentals**: zero external dependencies except `quic-go` + `golang.org/x/*`, RFC 9180-conformant HPKE validated against test vectors, AES-256-GCM gossip, mTLS Raft RPC (with one config bug noted below), PBKDF2-HMAC-SHA512 @ 310k for passwords, HMAC-SHA512 session tokens, TSIG with anti-replay, ACL + RPZ + rate limiting on the DNS path, race-detector clean across 195 package-runs, and ~232M cumulative fuzz executions across all wire-format parsers.

**The Phase-2 sweep produced 38 verified findings (1 false positive eliminated, 1 HIGH downgraded to MEDIUM after reachability analysis):**

| Severity | Count | Highlight |
|---|---|---|
| **HIGH** | 2 | Dashboard `auth_secret` doubles as bearer token; DNSSEC downgrade via missing DS-denial proof |
| **MEDIUM** | 12 | 6 application-layer, 5 infrastructure, 1 cache-hash collision (downgraded) |
| **LOW** | 16 | Defense-in-depth gaps; mostly admin-gated |
| **INFO** | 8 | Hygiene observations, no exploit path |

**Net risk verdict:** Two HIGH findings deserve same-week remediation. The DNSSEC downgrade is the higher real-world impact (any on-path adversary defeats DNSSEC for any downstream client). The `auth_secret`-as-bearer collapses the dashboard credential and the token-forgery key into one secret; if the dashboard URL is operator-exposed externally, this becomes critical.

---

## HIGH Severity (2)

### H-1: Dashboard treats `auth_secret` as bearer token (CWE-321 / CWE-798)

- **CVSS 3.1:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)
- **Files:** `cmd/nothingdns/main.go:434-438`, `internal/dashboard/server.go:230-236`, `internal/dashboard/server.go:357-365`
- **Defect:** When `cfg.Server.HTTP.AuthToken` is empty, `main.go` falls back to `legacyToken = cfg.Server.HTTP.AuthSecret` and calls `dashboardServer.SetAuthToken(legacyToken)`. The dashboard's HTTP layer then accepts that string as a bearer credential.
- **Why it matters:** `AuthSecret` is the HMAC-SHA512 key used at `internal/auth/auth.go:344-348` to sign every session token. Leaking the dashboard bearer therefore leaks the signing key — an attacker can forge arbitrary session tokens for any user including admin.
- **Remediation:** Drop the legacy-token fallback. Require an explicit `AuthToken` for dashboard access (or require admin session token like the rest of the API). Audit the deployment to ensure no operator has set `AuthSecret` thinking it was a separate dashboard password.

### H-2: DNSSEC downgrade via missing DS-denial proof (CWE-345 / CWE-757)

- **CVSS 3.1:** 7.4 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)
- **Files:** `internal/dnssec/validator.go:255-264`, `internal/dnssec/validator.go:1158-1177`
- **Defect:** `fetchDS()` only scans `msg.Answers` for `TypeDS` records. If the answer section contains zero DS records, the validator silently treats the subtree as Insecure — without verifying NSEC/NSEC3 proof of DS non-existence, and without signature validation of the denial.
- **Why it matters:** An on-path adversary (or malicious upstream) can strip the DS RRset from a parent zone's referral response. The validator then concludes "this zone is unsigned" and stops validating. This is the canonical DNSSEC downgrade attack and defeats the entire purpose of DNSSEC for any zone whose DS is reachable to the attacker.
- **Remediation:** After observing no DS records, require either (a) a validated NSEC/NSEC3 proof from the parent that NoData(DS) holds, with a valid RRSIG from the parent ZSK, or (b) treating the response as bogus and returning SERVFAIL. Reference: RFC 4035 §5.2 + RFC 5155 §8.

---

## MEDIUM Severity (12)

### M-1: KVStore TLV recovery — unbounded length triggers OOM on startup (CWE-789)

- **CVSS 3.1:** 5.5 (AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H)
- **File:** `internal/storage/kvstore.go:218-222`
- **Defect:** `readTLV` reads a `uint32` payload length and immediately `make([]byte, int(payloadLen) + hmacLenBytes)` with no cap.
- **Why it matters:** Mirror of the recently-fixed Raft `readSnapshot` OOM (`b9f0ed5`) and the entry-slice OOM (`e9687fe`). Requires write access to the data file (container escape, shared mount, restored backup), so it's a local trust-boundary breach rather than a network DoS — but the same defensive pattern applies and there's no reason to leave this primitive unguarded.
- **Remediation:** Add a sensible cap (e.g. `const maxKVPayload = 16 << 20` to match the WAL cap at `kvjournal.go:283`) and reject payloads above it before `make()`. Add a regression test that mirrors the corresponding Raft / journal tests.

### M-2: Cache key hash collision for names >128 bytes (CWE-407, downgraded from HIGH)

- **CVSS 3.1:** 5.3 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N)
- **Files:** `internal/cache/cache.go:236-281` (Phase-3 verifier downgraded this from HIGH→MEDIUM)
- **Defect:** Names longer than 128 bytes are reduced to a 64-bit Java-style polynomial hash (`h*31 + byte`, mislabeled `crc32Hash`). Collisions are computationally tractable and would let an attacker influence what response is served for an unrelated victim name.
- **Why it matters:** DNS names cap at 255 bytes so the >128 gate is reachable. Real-world exploitability requires choosing both names + finding a 64-bit polynomial collision (~2^32 with multi-collisions) + getting the attacker response into the cache.
- **Remediation:** Include the full name string in the cache key, or replace the hash with a keyed cryptographic hash (e.g. SipHash with a per-process random key).

### M-3: Raft mTLS dialer omits RootCAs — peer impersonation (CWE-295)

- **CVSS 3.1:** 6.8 (AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **File:** `internal/config/config.go:2402-2413`
- **Defect:** The shared `*tls.Config` populates only `ClientCAs` (server-side validation). `tls.Dial` for peer-to-peer Raft connections falls back to the host's system trust store when `RootCAs == nil`.
- **Why it matters:** Any cert that chains to a system-trusted CA (Let's Encrypt, public DigiCert, etc.) with a matching SAN can impersonate a Raft peer, inject log entries, and gain authoritative control over zone state.
- **Remediation:** Set `RootCAs = caPool` (the same pool used for `ClientCAs`) in the dialer config. Add a startup assertion that the dialer config's `RootCAs` is non-nil when mTLS is enabled.

### M-4: API blocklist handler leaks raw error chains (CWE-209)

- **Files:** `internal/api/api_blocklist.go:60`, `internal/api/api_blocklist.go:146`
- **Defect:** Both code paths use `fmt.Sprintf("Failed to ...: %v", err)` directly, bypassing the `sanitizeError` helper used elsewhere in the API.
- **Why it matters:** URL fetcher errors leak internal hostnames and TCP-dial diagnostics; `RemoveSource` errors leak file paths. Operator-gated, so a compromised low-privilege account is the prerequisite.
- **Remediation:** Replace direct interpolation with `sanitizeError(err)`; add a lint rule or test that asserts no handler returns `%v err` directly.

### M-5: Rate-limit eviction bypass via createdAt ordering (CWE-307)

- **File:** `internal/filter/ratelimit.go:84-93` + `:194-234`
- **Defect:** Buckets are created with `tokens = burst - 1`. Eviction sorts by `createdAt` (creation time), not `lastTime`. An attacker who sprays source IPs cycles fresh buckets through the cache, sacrificing the longest-tenured legitimate clients first. Legitimate clients then themselves get a fresh full-burst bucket on return → the limit is silently reset cluster-wide.
- **Remediation:** Switch eviction key to `lastAccessTime` (true LRU) and initialise new buckets with their first token already consumed (already done) — but the eviction order is the load-bearing fix.

### M-6: DDNS prerequisite check outside zone write lock (TOCTOU, CWE-367)

- **File:** `internal/transfer/ddns.go:205-237`
- **Defect:** `h.checkPrerequisites(z, req.Answers)` runs at line 205, BEFORE `h.zonesMu.Lock()` at line 235. The inline comment claims V-06 was fixed by "synchronous apply" but synchronous apply alone does not close the prereq TOCTOU — two concurrent UPDATEs with mutually-exclusive RFC 2136 prerequisites can both pass the check and then both apply.
- **Remediation:** Move the prereq check inside the locked section, or take the zone lock before the prereq check and hold through apply. Add a stress test (parallel conflicting UPDATEs) that asserts only one applies.

### M-7: DNS-over-WebSocket missing per-connection rate limit (CWE-770)

- **File:** `internal/doh/wshandler.go:33-91`
- **Defect:** The dashboard WS calls `conn.SetRateLimit(100, time.Second)` at `internal/dashboard/server.go:393`; the DoWS handler does not. The 30s read deadline resets per message (`wshandler.go:54`), so a single unauthenticated WebSocket connection can flood the resolver indefinitely. The API rate limiter only gates the initial HTTP upgrade.
- **Remediation:** Apply the same `conn.SetRateLimit` pattern to the DoWS handler, with a rate appropriate for legitimate clients (consider 100/s as a starting point matching the dashboard ceiling).

### M-8: Container image uses floating `:latest` tag (CWE-1357)

- **File:** `docker-compose.yml:10`
- **Remediation:** Replace `ghcr.io/nothingdns/nothingdns:latest` with `@sha256:<digest>` or a version tag plus digest. Document the bump process.

### M-9: docker-compose healthcheck calls `wget` on scratch image (no shell, no wget)

- **File:** `docker-compose.yml:47` (and the documented broken example at `Dockerfile:73-78`)
- **Defect:** Final stage is `FROM scratch`. `wget` doesn't exist. The container is permanently `unhealthy`, defeating the liveness signal.
- **Remediation:** Either build a thin wrapper into the binary (e.g. `nothingdns healthcheck`) and call that, or expose the HTTP `/health` endpoint via a separate sidecar.

### M-10: Container missing hardening flags (CWE-250)

- **File:** `docker-compose.yml:67-68`
- **Defect:** `cap_add: NET_BIND_SERVICE` is present but `cap_drop: ALL`, `security_opt: ["no-new-privileges:true"]`, `read_only: true`, and `pids_limit:` are absent.
- **Remediation:** Add all four. The Go binary itself only needs the bind capability; everything else is defense in depth.

### M-11: CI installs security tools at `@latest` (CWE-829)

- **File:** `.github/workflows/go.yml:115, 120`
- **Defect:** `go install golang.org/x/vuln/cmd/govulncheck@latest` and `honnef.co/go/tools/cmd/staticcheck@latest`. Job has `security-events: write` and `GITHUB_TOKEN`.
- **Remediation:** Pin to specific versions (e.g. `@v1.1.4`). Update via Renovate/Dependabot. Same for the other workflows that do `@latest`.

### M-12: Unpinned third-party GHA actions, including Snyk `@master` (CWE-829)

- **Files:** `.github/workflows/web.yml:79` uses `snyk/actions/node@master`; other workflows use floating `@v3`/`@v4` tags rather than commit SHAs.
- **Defect:** `@master` runs whatever Snyk pushes next. Workflow secrets (`SNYK_TOKEN`, GitHub OIDC) are in scope.
- **Remediation:** Pin every third-party action to a commit SHA, as already done in `container.yml`. Add comments naming the version the SHA corresponds to.

---

## LOW Severity (16)

Verified via Phase-2 grep + Phase-3 spot-check (not deep-verified for each):

1. **WebSocket payload sign-flip on 64-bit extended length** — `internal/websocket/websocket.go:386-393`. Per-connection DoS only (handler recover).
2. **TCP/UDP worker goroutines lack panic recovery before handler entry** — `internal/server/tcp.go:267`, `internal/server/udp.go:329, 341`. Low probability with current parsers but layering invariant is wrong.
3. **`RevokeToken` decrements `activeSessions` unconditionally** — `internal/auth/auth.go:411-418`. Latent: only bites once `max_sessions_per_user > 0` is enabled.
4. **`auth_secret` empty + persistence enabled silently loses token DB on restart** — `internal/auth/auth.go:121-131` × `cmd/nothingdns/main.go:245-249`. Should hard-fail.
5. **`auth_secret` validation accepts arbitrarily short strings** — `internal/config/config.go:1851-1855`. Skips the `secretHasMinEntropy` check.
6. **Raft snapshots + KV WAL unencrypted on disk** — asymmetric with DNSSEC keystore + token store, which both use AES-GCM at rest. Documented operator-trust boundary.
7. **Blocklist FQDN trailing-dot mismatch** — `internal/blocklist/blocklist.go:269,288,364` vs `:396`. BIND-style sources silently never match.
8. **RPZ client/response-IP CIDR rules ignore priority** — `internal/rpz/rpz.go:394-418, 486-510`. QNAME rules correctly honour priority; CIDR rules use insertion order.
9. **TSIG `ValidateKeySource` short-circuits on first invalid CIDR** — `internal/transfer/tsig.go:158-167`. Drops valid keys silently.
10. **Records list endpoint has no pagination cap** — `internal/api/api_zones.go:264-287`. Operator-gated.
11. **Dashboard data endpoints accept any HTTP method** — `internal/dashboard/server.go:250-271`. Not exploitable today; CSRF-defense regression risk for future state mutations.
12. **Dockerfile builder image tag-pinned not digest-pinned** — `Dockerfile:7`.
13. **`npm install` instead of `npm ci`** — `.github/workflows/web.yml:28, 68`.
14. **Workflow-scope permissions broader than needed** — `.github/workflows/go.yml:9-12`, `web.yml:9-11`.
15. **GHA build cache could leak future build-time secrets** — `.github/workflows/container.yml:57-58`.
16. **Missing image-supply-chain artifacts** — no SBOM, no SLSA provenance, no cosign signing, no Trivy/grype scan on container push.

---

## INFO (8 — hygiene, no exploit path)

1. DSO TLV bounds verified safe (sc-lang-go).
2. `handleRPZActions` reachable by viewer for 503-vs-404 probe (`internal/api/api_rpz.go:116-142`).
3. Login per-IP progressive delay hostile to shared-NAT clients.
4. TSIG BADTIME vs BADSIG timing-distinguishable (MAC still required, no exploit).
5. Admin file-path read via blocklist `AddFile` with unset `BaseDir` — admin-only.
6. Admin-controlled cluster `JoinSeed` no SSRF filter — admin-only internal port scan.
7. Unused `pull-requests: write` permission in `go.yml:12`.
8. Coverage job downloads a `go-modules` artifact that's never uploaded (go.yml:53-58).

---

## What's Clean (high-confidence)

- **All injection classes**: no SQL/NoSQL/GraphQL/LDAP/XSS/SSTI/XXE/CMDi/header-injection sinks (`sc-injection-results.md`).
- **All code-execution classes**: no `exec.Command` / `plugin.Open` / `unsafe` in production; closed type switches on RPC/RPC; bounded snapshot/WAL/journal decoders (`sc-rce-deserialization-results.md`).
- **Cryptographic primitives**: `crypto/rand` everywhere security-relevant; PBKDF2-SHA512 @ 310k > OWASP 2023; AES-256-GCM with random per-op nonces; HMAC-SHA512 tokens; DNSSEC validator rejects RSA-MD5/SHA1/DSA; NSEC3 iterations bounded.
- **Recursive resolver SSRF guards**: comprehensive disallowed-IP filter at `internal/resolver/resolver.go:884-914` blocks glue/NS-resolved RFC 1918, link-local, cloud metadata.
- **Race-detector**: 195 package-runs across 5 iterations clean (`b96v36ctv` baseline from this session).
- **Fuzz coverage**: 8 packages with harnesses; ~232M cumulative executions across cache, dnscookie, dso, odoh, protocol, raft, transfer, zone; 0 panic at the deep-fuzz baseline.

---

## Remediation Roadmap

### Phase 1 — Same week (HIGH)
- [ ] **H-1**: Remove dashboard `auth_secret`-as-bearer fallback. Require explicit `AuthToken` or admin-session-token for dashboard. Add regression test.
- [ ] **H-2**: Add NSEC/NSEC3 proof-of-no-DS validation in `fetchDS()`. Return SERVFAIL on unverified DS absence. Add test using a known NSEC-proven insecure delegation and a known on-path-strip vector.

### Phase 2 — Next sprint (network-reachable MEDIUMs)
- [ ] **M-3**: Fix Raft mTLS dialer to set `RootCAs`.
- [ ] **M-5**: Switch rate-limit eviction to LRU by `lastAccessTime`.
- [ ] **M-6**: Move DDNS prereq check inside zone write lock.
- [ ] **M-7**: Add per-connection rate limit to DoWS handler.
- [ ] **M-2**: Replace cache-key polynomial hash with full-name keying or SipHash.

### Phase 3 — Infrastructure hardening
- [ ] **M-1**: Cap KVStore TLV payload (mirror of journal cap).
- [ ] **M-4**: Apply `sanitizeError` to blocklist handler error paths.
- [ ] **M-8 to M-12**: Container + CI hygiene — pin digests, fix healthcheck, add cap_drop/no-new-privileges/read_only, pin GHA actions to SHAs, drop `@latest` for security tools.

### Phase 4 — Defense-in-depth (LOWs)
- [ ] Address LOWs L-1 through L-16 as opportunity allows. Several (L-3, L-4, L-7, L-8, L-9, L-11) are latent: they're not exploitable today but will surface on configuration change.

---

## Pipeline Statistics

- **Languages detected:** Go 1.25.0 (primary), embedded React 19 SPA (compiled binary).
- **External Go deps:** 2 direct (quic-go, golang.org/x/sys), 2 indirect (golang.org/x/{crypto, net}). Zero CVEs at pinned versions.
- **Phase 2 agents:** 9 parallel (sc-lang-go, sc-injection, sc-rce-deserialization, sc-auth, sc-secrets-crypto, sc-server-side, sc-client-api, sc-logic-race-mass, sc-infra).
- **Total raw findings:** ~41 → after dedup + verification → 38 verified (2 HIGH, 12 MED, 16 LOW, 8 INFO).
- **False positives eliminated:** 0 (one HIGH downgraded to MED on reachability analysis).
- **Verification confidence:** Each HIGH/MED hand-confirmed against actual code at cited file:line.
