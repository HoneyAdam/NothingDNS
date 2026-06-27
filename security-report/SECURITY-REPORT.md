# NothingDNS — Security Report

**Date:** 2026-06-26
**Scope:** Full codebase audit (Go server `cmd/` + `internal/`, React/TS dashboard
`web/src/`, Docker/Compose, CI workflows, install scripts).
**Pipeline:** security-check 4-phase (Recon → Hunt → Verify → Report). 9 parallel
hunters covering OWASP + 40 vuln classes; 3 adversarial verifiers re-read and tried
to refute every High claim. Full detail: `verified-findings.md` and per-skill
`sc-*-results.md` in this directory.

---

## Executive Summary

NothingDNS is, overall, **a hardened codebase**. The entire application-layer attack
surface — auth (opaque random tokens + RBAC, no JWT pitfalls), application crypto
(`crypto/rand`, AES-256-GCM with fresh nonces, constant-time compares, PBKDF2@310k),
the HTTP/DoH/WS API (CORS, security headers, body limits, timeouts, rate limiting),
the recursive resolver and DNS wire parser (bounds-checked), and the React dashboard
(no XSS sinks, in-memory tokens) — all held up under adversarial verification. Whole
classes (SQLi, CMDi, RCE, XXE, SSTI, untrusted deserialization, mass assignment) are
absent or not exploitable. The prior "cache LRU race" critical is confirmed fixed.

**The risk is concentrated in the clustering / HA subsystem and the release supply
chain — not the DNS data path.** The single most important issue is that
**Raft-based HA is both unauthenticated and has a broken encryption path**: enabling
a cluster encryption key silently breaks the cluster (AEAD nonce never transmitted),
so the only functional Raft cluster is plaintext and accepts unauthenticated
state-replacement RPCs — cluster-wide DNS poisoning. This contradicts the project
memory's belief that encrypted cluster transport is fully working; gossip is fine,
**Raft RPC is not**.

### Risk score

| | |
|---|---|
| **Overall risk (default single-node deployment)** | **Low–Medium** |
| **Overall risk (Raft-HA / XoT enabled)** | **High** |
| Confirmed Critical | 1 (Raft-HA only) |
| Confirmed High | 4 |
| Confirmed Medium | 4 |
| Confirmed Low | 16 |
| False positives eliminated | 7 classes |

> Why deployment-conditional: every Critical/High except V2 (resolver race) and V5
> (installer) is gated behind opt-in features (`cluster.enabled` + Raft, or
> `server.xot.enabled`). A stock single-node recursive resolver is exposed to V2 and
> V5 only.

### Remediation status (branch `fix/security-scan-2026-06-26`)

All Critical and High findings have been fixed, verified (build + vet + tests +
race detector + staticcheck/errcheck), and committed:

| ID | Finding | Status | Commit |
|----|---------|--------|--------|
| C1 | Raft AEAD nonce dropped + unauthenticated RPC | **Fixed** | `b1ab55d` (nonce + tests), `4151172` (require key/allow_insecure) |
| H1 | Resolver singleflight shared mutable message | **Fixed** | `67e44e9` (per-caller `Copy()`) |
| H2 | XoT zone transfer allow-all / unwired allowlist | **Fixed** | `0aa64c1` (deny-by-default + wiring) |
| H3 | Raft WAL non-atomic rewrite + false durability ack | **Fixed** | `d90c204` (temp+rename + fail-closed persist) |
| H4 | Installer no checksum verification | **Fixed** | `ebeb6b2` (SHA256SUMS verify, fail-closed) |

All 4 Mediums are now also fixed:

| ID | Finding | Status | Commit |
|----|---------|--------|--------|
| M1 | Raft RPC TLS config parsed but never wired | **Fixed** | `fix(cluster): wire Raft RPC TLS…` |
| M2 | Installer silently disables host DNS (non-interactive) | **Fixed** | `fix(install): don't silently disable host DNS…` |
| M3 | CI installs errcheck/go-errorlint from `@latest` | **Fixed** | `ci: pin errcheck and go-errorlint…` |
| M4 | Phantom pgx/PostgreSQL backend in CLAUDE.md | **Fixed** | `docs: remove phantom pgx…` |

**Lows — 7 fixed, 9 accepted/deferred with rationale:**

Fixed (code + tests):

| ID | Finding | Commit summary |
|----|---------|----------------|
| V10 | `/api/v1/status` leaked cache/cluster detail to viewers | tier response by role |
| V13 | Gossip membership map unbounded | 65536-member ceiling |
| V14 | Cluster inbound goroutines lacked `recover()` | recover in acceptLoop/handleConn/receiveLoop |
| V15 | `decodeEntrySlice` 32-bit overflow in bounds check | compute in uint64 + guard test |
| V19 | `health-check.sh` hardcoded `admin:admin` | source creds from env |
| V21 | `auth_token` length oracle via early `len()` | compare SHA-256 digests |
| V25 | no `go mod verify`; secrets echoed to stdout | verify in Dockerfile; creds to root-only file |

Accepted / deferred (rationale):

| ID | Finding | Disposition |
|----|---------|-------------|
| V11 | Blocklist `AddFile` reads an admin-supplied absolute path | **Accept** — admin-only function whose purpose is loading a local file; already acknowledged (VULN-009) |
| V12 | Wildcard-CORS Origin reflection | **Mitigated** — `validation.go` already rejects wildcard `allowed_origins` on a public bind in production mode |
| V16 | No aggregate byte cap on inbound AXFR/IXFR | **Defer** — per-record bounds already enforced; aggregate cap is hardening, needs streaming rework |
| V17 | DNS record type/RData validation gap | **Accept** — operator-gated write path |
| V18 | JSON decode lacks `DisallowUnknownFields` | **Accept** — DTOs are narrow (no mass-assignment); enabling strict decode risks breaking existing/older API clients |
| V20 | Dashboard persists `username`/`role` to localStorage | **Accept** — UI-only; authz is server-enforced via bearer+RBAC |
| V22 | No global concurrent-connection cap | **Mitigated** — slowloris covered by read/write/idle timeouts; a hard cap risks dropping legitimate load |
| V23 | CSP `style-src 'unsafe-inline'` | **Accept** — required by Radix UI; `script-src 'self'` remains strict |
| V24 | Management API defaults to `0.0.0.0:8080` | **Mitigated** — production validation requires TLS on a public `http.bind`; changing the default would break container/port-mapped deployments (maintainer call) |

H4's operational dependency is now satisfied by `.github/workflows/release.yml`,
which builds the cross-platform binaries and publishes a `SHA256SUMS` manifest to
each GitHub Release (asset names match the installer; verified end-to-end). The
installer still fails closed if a release lacks the manifest
(`NOTHINGDNS_SKIP_CHECKSUM=1` bypasses).

---

## Findings by severity

### CRITICAL

**C1 / V1 — Unauthenticated + broken-encryption Raft RPC → cluster DNS poisoning**
*(Critical when Raft HA enabled; CWE-306/CWE-345)*
`raft/encoding.go:78` seals with `Seal(nonceBuf[:0], …)` so the GCM nonce is never
sent — encrypted clusters fail closed. `initRaft` (`cluster/cluster.go:317-326`)
never requires a key/`AllowInsecureCluster`, `handleConn` (`raft/rpc.go:167`) does no
peer auth, and `HandleSnapshotRequest` (`raft/handlers.go:259-288`) applies attacker
bytes via `stateMachine.Restore`. The parsed `RPCConfig` TLS is never wired in. Net:
the only working Raft cluster is plaintext + unauthenticated.
**Remediate first.**

### HIGH

- **H1 / V2 — Resolver singleflight shares a mutable `*protocol.Message`** (CWE-362).
  Coalesced identical queries get the same message and concurrently mutate
  `Header.ID` / answer slices → data race + cross-client transaction-ID corruption.
  Remotely reachable with recursion enabled. One-line fix: `return msg.Copy(), nil`.
- **H2 / V3 — XoT zone transfer has no TSIG and silently ignores its IP allow-list**
  (CWE-306). `AllowedNetworks` is never wired (`transports.go:180`); `isAllowed`
  allows-all on empty list; mTLS optional → any TLS client can dump every zone.
- **H3 / V4 — Raft WAL non-atomic rewrite + followers ACK un-persisted entries**
  (CWE-662/CWE-460). Crash-window committed-entry loss; `persistEntriesLocked`
  swallows fsync errors yet returns `Success:true` → Raft safety violation.
- **H4 / V5 — Release installer does no checksum/signature verification** (CWE-494).
  `curl | bash` → `chmod +x` → run as root, no integrity check → root RCE on a
  hijacked/MITM'd release.

### MEDIUM

- **M1 / V6** — Raft `RPCConfig` TLS parsed but never consumed (dead "secure" config).
- **M2 / V7** — Installer disables host resolvers in the non-interactive path.
- **M3 / V8** — CI installs lint/security tools from `@latest` while holding
  `security-events: write`.
- **M4 / V9** — Phantom `pgx`/`postgres_zonestore.go` documented but absent (doc drift).

### LOW (16) — see `verified-findings.md` V10–V25
Highlights: `/api/v1/status` missing role gate (V10); admin-only arbitrary file read
via blocklist `AddFile` (V11); wildcard-CORS Origin reflection (V12); downgraded
gossip-map / missing-recover hardening gaps (V13–V14); 32-bit overflow in
`decodeEntrySlice` (V15); no AXFR/IXFR aggregate cap (V16); `health-check.sh`
`admin:admin` (V19); localStorage role tamper (V20); default `0.0.0.0:8080` API bind
(V24); non-digest-pinned images / no `go mod verify` (V25).

---

## Remediation roadmap

**Phase 1 — Before any HA/cluster production use (Critical/High):**
1. Fix the Raft AEAD nonce (`Seal(nonceBuf, nonceBuf, …)`) **and** add an
   encrypted-transport round-trip + multinode test (this path has zero coverage).
2. Enforce auth on Raft: require encryption key or explicit `AllowInsecureCluster`
   in `initRaft`; wire `RPCConfig` TLS; reject RPCs from non-peer NodeIDs. (C1, M1)
3. Resolver: copy the singleflight result for all callers. (H1)
4. XoT: wire `AllowedNetworks`, deny-by-default, require TSIG or mTLS. (H2)
5. Raft WAL: temp+fsync+rename rewrites; propagate persist errors / `Success:false`. (H3)

**Phase 2 — Supply chain (High/Medium):**
6. Publish + verify SHA256SUMS and a signature in `install.sh`; drop bare
   `curl|bash` from docs. (H4)
7. Pin CI tool versions; scope the installer's resolver changes to interactive
   consent. (M2, M3)

**Phase 3 — Hardening (Low):**
8. Add role gate to `/api/v1/status`; contain blocklist `AddFile`; tighten default
   CORS off wildcard; cap inbound XFR bytes; remove `admin:admin` from
   `health-check.sh`; digest-pin images + `go mod verify`. (V10–V25)

**Phase 4 — Hygiene:**
9. Reconcile CLAUDE.md vs `go.mod` (remove phantom `pgx`/postgres references or
   restore the backend). (M4) Add `defer recover()` to cluster goroutines as
   defense-in-depth. (V14) Update project memory: Raft RPC encryption is **not**
   working until C1 is fixed.

---

## What was verified safe (high confidence)

Auth/RBAC per-route enforcement · token crypto · application AES-GCM/PBKDF2/HKDF ·
DNS wire + TLV + Raft + WAL decoders (bounds-checked) · plain-TCP AXFR (TSIG +
deny-by-default) · CORS/CSRF posture (bearer-primary, SameSite=Strict) · WebSocket
origin+auth · request body limits + server timeouts · React dashboard (no XSS sinks,
in-memory tokens) · container/k8s/systemd hardening (scratch, non-root, cap-drop ALL,
read-only rootfs, seccomp, SHA-pinned actions, cosign+SBOM on images) · no committed
secrets · prior cache LRU race fixed.
