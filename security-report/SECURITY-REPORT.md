# Security Report — NothingDNS

**Date**: 2026-04-25
**Scanner**: security-check (AI-powered 4-phase pipeline)
**Scope**: Full codebase (372 Go files, 58 TypeScript files, deployment manifests, CI/CD)
**Risk Rating**: LOW–MEDIUM

---

## Executive Summary

NothingDNS was subjected to a comprehensive security audit covering 48 vulnerability categories across injection, authentication, cryptography, infrastructure, and business logic. **No critical or high-severity vulnerabilities were identified.** The project demonstrates strong security hygiene: modern cryptography, robust authentication, minimal dependencies, and extensive defense-in-depth.

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 16 | Hardening recommended |
| Low | 36 | Defense-in-depth / documentation |

**Top Concerns**:
1. Custom cryptographic implementations (PBKDF2, HKDF-like key derivation) increase audit surface.
2. Missing security headers (CSP) on the embedded React dashboard.
3. Kubernetes Helm defaults inadvertently expose `/metrics` via Ingress.
4. Test configuration file contains a hardcoded auth token that could be accidentally deployed.

---

## Scan Statistics

| Phase | Skills Run | Findings | False Positives Eliminated |
|-------|-----------|----------|---------------------------|
| Phase 1: Recon | 2 | Architecture mapped, 4 deps identified | 0 |
| Phase 2: Hunt | 35+ | 208 raw findings | 156 |
| Phase 3: Verify | 1 | 52 verified findings | 0 |
| Phase 4: Report | 1 | This report | 0 |

**Languages Scanned**:
- Go (98% of codebase) — sc-lang-go
- TypeScript/React (1.5%) — sc-lang-typescript
- YAML/Markdown (remainder)

**Infrastructure Scanned**:
- Dockerfile
- GitHub Actions (3 workflows)
- Kubernetes manifests + Helm charts

---

## Findings by Severity

### Medium (16)

| ID | Finding | File | CWE |
|----|---------|------|-----|
| MED-001 | Custom PBKDF2-HMAC-SHA512 implementation | `internal/auth/auth.go:152–216` | CWE-327 |
| MED-002 | Custom HKDF-like AES key derivation | `internal/auth/auth.go:691–696` | CWE-327 |
| MED-003 | Missing CSP header on dashboard | `web/index.html` | CWE-1021 |
| MED-004 | Missing CSRF defense-in-depth on mutating requests | `web/src/lib/api.ts` | CWE-352 |
| MED-005 | Vite dev server CORS proxy exposure | `web/vite.config.ts:18–23` | CWE-942 |
| MED-006 | Panic recovery logs raw panic value | `cmd/nothingdns/handler.go:88–89` | CWE-209 |
| MED-007 | gob deserialization of cache persistence | `cmd/nothingdns/cache_manager.go:234` | CWE-502 |
| MED-008 | DNSSEC trust anchor XML parsing | `internal/dnssec/trustanchor.go` | CWE-611 |
| MED-009 | DoH GET endpoint amplification risk | `internal/doh/doh.go` | CWE-770 |
| MED-010 | Config hot reload may expose partial state | `internal/config/reload.go` | CWE-362 |
| MED-011 | Global RBAC only — no per-zone authorization | `internal/api/api_zones.go` | CWE-284 |
| MED-012 | Basic auth over Ingress without explicit TLS | `deploy/k8s/ingress.yaml:10–11` | CWE-319 |
| MED-013 | Helm defaults expose `/metrics` via Ingress | `deploy/helm/nothingdns/values.yaml:75–78` | CWE-200 |
| MED-014 | Missing HEALTHCHECK in Dockerfile | `Dockerfile` | CWE-1037 |
| MED-015 | Workflow expression injection risk | `.github/workflows/container.yml:62–68` | CWE-94 |
| MED-016 | Hardcoded test auth token in local-test.yaml | `local-test.yaml:8` | CWE-798 |

### Low (36)

See `verified-findings.md` for the complete low-severity list. Key themes:
- **Auth/Session**: No refresh tokens, no concurrent session limit, role cached in tokens, password policy gaps.
- **API/Web**: Slightly different auth error messages, MCP scope audit needed, DoH error info leak.
- **Crypto**: `InsecureSkipVerify` struct field, SHA-1 in NSEC3 (RFC-mandated).
- **Infrastructure**: No `.dockerignore`, `latest` tag in K8s, overly permissive NetworkPolicy egress, unpinned `busybox` in Helm test.
- **Frontend**: `Math.random` for notification IDs, duplicate auth token retrieval from cookie.

---

## Architecture Security Assessment

NothingDNS is a **Go-based DNS server** with the following security-relevant architecture:

- **21-stage request pipeline** with panic recovery, ACL, rate limiting, DNS cookies, blocklist, cache, zone lookup, recursive resolver, DNSSEC validation, and RPZ response checks.
- **Zero external dependencies** (except `quic-go` and `golang.org/x/*` extensions), minimizing supply-chain attack surface.
- **Custom protocol parsers** for DNS wire format, YAML config, and TLV serialization — all audited for overflow and injection.
- **Multi-plane authentication**: DNS plane (cookies, TSIG, ACL), management plane (JWT/HMAC tokens with RBAC), cluster plane (AES-256-GCM gossip, optional TLS Raft).

**Trust Boundaries**:
1. Public DNS (UDP/TCP/DoH/DoT/DoQ) → handler → cache/zone/resolver
2. Management API (HTTP/WebSocket) → auth middleware → RBAC → handlers
3. Cluster internal (gossip/Raft) → encrypted + authenticated

---

## Dependency Audit Summary

| Dependency | Version | Risk |
|------------|---------|------|
| `github.com/quic-go/quic-go` | v0.59.0 | Low — actively maintained, no known critical CVEs |
| `golang.org/x/sys` | v0.43.0 | Low — official Go extension |
| `golang.org/x/crypto` | v0.45.0 | Low — official Go extension (indirect) |
| `golang.org/x/net` | v0.47.0 | Low — official Go extension (indirect) |

**Supply Chain**: Minimal attack surface. No vendoring. `go.sum` pins exact versions. Dockerfile uses multi-stage `FROM scratch` with static binary.

**Recommendation**: Pin GitHub Actions to SHA hashes (already done), consider adding SBOM generation to build pipeline.

---

## Remediation Roadmap

### Phase 1: Immediate (1–2 weeks)
1. **MED-016**: Remove hardcoded test token from `local-test.yaml` and add to `.gitignore`.
2. **MED-012**: Add explicit `tls:` section to `deploy/k8s/ingress.yaml`.
3. **MED-013**: Remove `/metrics` path from default Helm `values.yaml` ingress paths.
4. **MED-006**: Sanitize panic value before logging in `cmd/nothingdns/handler.go`.
5. **LOW-023**: Return generic error messages for DoH failures.

### Phase 2: Short-term (1 month)
6. **MED-001 / MED-002**: Replace custom PBKDF2 and HKDF-like derivation with standard library implementations (`golang.org/x/crypto/pbkdf2`, `crypto/hkdf`).
7. **MED-003**: Add CSP and security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) in Go static file server.
8. **MED-011**: Document single-tenant design constraint or add per-zone ownership.
9. **LOW-009**: Require bootstrap token from file/env for localhost bootstrap.
10. **LOW-011**: Enforce minimum password length (8–12 chars) in `ValidatePassword`.

### Phase 3: Medium-term (1–3 months)
11. **MED-007**: Migrate cache persistence from `gob` to JSON or protobuf.
12. **MED-010**: Implement atomic config pointer swap for hot reload.
13. **LOW-013 / LOW-015**: Revoke tokens on role change and re-validate role from user store.
14. **LOW-016 / LOW-017**: Implement refresh tokens and concurrent session limits if long-lived sessions are required.
15. **MED-014**: Add `HEALTHCHECK` or document orchestrator-level health checks.

### Phase 4: Long-term / Continuous
16. **LOW-025**: Audit MCP handlers for secret redaction.
17. **LOW-034**: Tighten NetworkPolicy egress rules to required CIDRs/ports.
18. **LOW-035 / LOW-036**: Pin all container images to digests in K8s manifests.
19. Establish periodic dependency audits (quarterly) and CVE monitoring for `quic-go`.
20. Add NIST test vectors for any retained custom crypto.

---

## Positive Security Controls

The following controls were verified and are working correctly:

| Control | Evidence |
|---------|----------|
| **Modern Cryptography** | AES-256-GCM, Ed25519/ECDSA/RSA, TLS 1.3, ChaCha20-Poly1305, `crypto/rand` |
| **Timing Attack Mitigation** | `subtle.ConstantTimeCompare` in auth, `dummyHash` for non-existent users (VULN-017) |
| **Rate Limiting** | Per-IP token bucket for DNS, dual-track (IP + username) login rate limiting |
| **Input Validation** | `http.MaxBytesReader` on API, DNS message length checks, EDNS0 buffer limits |
| **Anti-DoS** | Max password length (128 bytes), max CNAME depth, max recursion depth, max blocklist size (100MB / 10M entries) |
| **CSRF Protection** | `SameSite=Strict`, cookie auth restricted to safe methods, Bearer tokens for mutations |
| **XSS Mitigation** | JSON-only API responses, no `dangerouslySetInnerHTML`, React client-side rendering |
| **Secret Redaction** | Config endpoint redacts `AuthToken`, `EncryptionKey`, `PrivateKey`, `TSIGSecret` |
| **Container Security** | `FROM scratch`, static binary, non-root user (`USER 1000`), dropped capabilities |
| **K8s Security** | `runAsNonRoot`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, NetworkPolicies |
| **CI/CD Security** | All actions pinned to SHA, no hardcoded secrets, PR builds do not push images |

---

## Appendix A: Methodology

1. **Phase 1 — Reconnaissance**: Architecture mapping, tech stack detection, entry point catalog, data flow tracing.
2. **Phase 2 — Vulnerability Hunting**: 35+ security skills run in parallel, covering OWASP Top 10, language-specific scanners, and infrastructure audits.
3. **Phase 3 — Verification**: Reachability analysis, sanitization verification, context analysis (test vs production), duplicate detection, confidence scoring.
4. **Phase 4 — Reporting**: CVSS-style severity assignment, executive summary, remediation roadmap.

## Appendix B: Files Generated

```
security-report/
├── architecture.md                  # Phase 1: Architecture map
├── dependency-audit.md              # Phase 1: Dependency analysis
├── sc-lang-go-results.md            # Phase 2: Go language scan
├── sc-lang-typescript-results.md    # Phase 2: TypeScript scan
├── sc-auth-results.md               # Phase 2: Auth flaws
├── sc-authz-results.md              # Phase 2: Authorization flaws
├── sc-privilege-escalation-results.md
├── sc-session-results.md
├── sc-jwt-results.md
├── sc-sqli-results.md               # Phase 2: SQL injection
├── sc-nosqli-results.md             # Phase 2: NoSQL injection
├── sc-cmdi-results.md               # Phase 2: Command injection
├── sc-ldap-results.md               # Phase 2: LDAP injection
├── sc-header-injection-results.md   # Phase 2: Header injection
├── sc-xss-results.md                # Phase 2: XSS
├── sc-ssti-results.md               # Phase 2: SSTI
├── sc-xxe-results.md                # Phase 2: XXE
├── sc-graphql-results.md            # Phase 2: GraphQL
├── sc-csrf-results.md               # Phase 2: CSRF
├── sc-cors-results.md               # Phase 2: CORS
├── sc-clickjacking-results.md       # Phase 2: Clickjacking
├── sc-websocket-results.md          # Phase 2: WebSocket
├── sc-secrets-results.md            # Phase 2: Secrets
├── sc-data-exposure-results.md      # Phase 2: Data exposure
├── sc-crypto-results.md             # Phase 2: Cryptography
├── sc-ssrf-results.md               # Phase 2: SSRF
├── sc-path-traversal-results.md     # Phase 2: Path traversal
├── sc-file-upload-results.md        # Phase 2: File upload
├── sc-open-redirect-results.md      # Phase 2: Open redirect
├── sc-rce-results.md                # Phase 2: RCE
├── sc-deserialization-results.md    # Phase 2: Deserialization
├── sc-business-logic-results.md     # Phase 2: Business logic
├── sc-race-condition-results.md     # Phase 2: Race conditions
├── sc-mass-assignment-results.md    # Phase 2: Mass assignment
├── sc-api-security-results.md       # Phase 2: API security
├── sc-rate-limiting-results.md      # Phase 2: Rate limiting
├── sc-docker-results.md             # Phase 2: Docker
├── sc-ci-cd-results.md              # Phase 2: CI/CD
├── sc-iac-results.md                # Phase 2: IaC
├── verified-findings.md             # Phase 3: Verified findings
└── SECURITY-REPORT.md               # Phase 4: This report
```

---

*Report generated by security-check skill. For questions or corrections, open an issue in the NothingDNS repository.*
