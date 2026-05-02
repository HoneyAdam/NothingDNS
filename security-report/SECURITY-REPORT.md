# NothingDNS Security Report

**Date:** 2026-05-01  
**Project:** NothingDNS - Authoritative DNS Server  
**Tech Stack:** Go (stdlib only), Zero external dependencies  

---

## Executive Summary

| Category | Risk Level | Findings |
|----------|-------------|----------|
| Access Control | LOW | Strong RBAC with JWT, PBKDF2 passwords |
| Cryptography | MEDIUM | SHA-1 in TSIG, SHA-512 for passwords |
| Network Security | LOW | mTLS, AES-256-GCM gossip encryption |
| Injection | LOW | Input validation, no external queries |
| Configuration | LOW | YAML validation, hot-reload |
| Transport | MEDIUM | InsecureSkipVerify in test code only |

**Overall Assessment:** SECURE with minor improvements recommended

---

## Detailed Findings

### 1. CRYPTOGRAPHIC IMPLEMENTATIONS

#### 1.1 TSIG Authentication (Zone Transfers)
**File:** `internal/transfer/tsig.go`  
**Algorithm Support:** HMAC-MD5, HMAC-SHA1, HMAC-SHA256, HMAC-SHA512

| Algorithm | Status | Notes |
|-----------|--------|-------|
| HMAC-SHA256 | RECOMMENDED | RFC 4635 compliance |
| HMAC-SHA512 | RECOMMENDED | Strongest in suite |
| HMAC-SHA1 | CAUTION | Legacy support only |
| HMAC-MD5 | ⚠️ DEPRECATED | Should be disabled in production |

**Finding:** SHA-1 remains enabled for backward compatibility. Consider making it configurable with warning logs.

#### 1.2 DNSSEC Signing
**Files:** `internal/dnssec/crypto.go`, `internal/dnssec/signer.go`  
**Algorithms:** Ed25519 (RFC 8081), ECDSA P-256/P-384, RSA SHA-1/SHA-256

**Finding:** ECDSA and Ed25519 are properly implemented. RSA SHA-1 present for legacy trust anchors.

#### 1.3 Cluster Gossip Encryption
**File:** `internal/cluster/gossip.go`  
**Implementation:** AES-256-GCM with `crypto/rand` for nonces

**Finding:** ✅ CORRECT - Uses Go's standard AES-GCM implementation with proper nonce generation

#### 1.4 Password Storage
**File:** `internal/auth/auth.go`  
**Implementation:** PBKDF2 with SHA-512, 100,000 iterations minimum

**Finding:** ✅ SECURE - Standard audited implementation per MED-001

---

### 2. TRANSPORT SECURITY

#### 2.1 TLS Configuration
**Files:** `internal/server/tls.go`, `internal/transfer/xot.go`

| Configuration | Status | Notes |
|---------------|--------|-------|
| TLS 1.2+ required | ✅ | Configurable min version |
| ClientAuth | ✅ | `tls.RequireAndVerifyClientCert` for mTLS |
| InsecureSkipVerify | ⚠️ | **TEST CODE ONLY** - Not in production |

**Finding:** All production TLS configs properly validate certificates.

#### 2.2 DNS Cookie (RFC 7873)
**Status:** Implemented in pipeline  
**File:** `cmd/nothingdns/handler.go` (Stage 6)

**Finding:** ✅ Anti-spoofing protection in place

---

### 3. ACCESS CONTROL

#### 3.1 API Authentication
**Files:** `internal/auth/auth.go`, `internal/api/api_auth.go`  
**Mechanism:** JWT tokens with role-based access

| Role | Permissions |
|------|-------------|
| admin | Full access |
| viewer | Read-only |
| custom | Per-permission RBAC |

**Finding:** ✅ Strong separation of duties

#### 3.2 ACL System
**Files:** `internal/filter/filter.go`, `internal/api/api_acl.go`

**Finding:** IP-based allow/deny with CIDR notation support

#### 3.3 Rate Limiting
**Type:** Token bucket algorithm  
**Scope:** Per-client IP

**Finding:** ✅ Implemented in security_manager.go

---

### 4. ZONE TRANSFER SECURITY

#### 4.1 AXFR/IXFR Protection
**Files:** `internal/transfer/axfr.go`, `internal/transfer/ixfr.go`

| Protection | Status |
|------------|--------|
| TSIG required | ✅ When configured |
| IP allowlist | ✅ |
| ACL enforcement | ✅ |

**Finding:** Zone transfers properly protected

#### 4.2 DDNS Updates
**File:** `internal/transfer/ddns.go`

**Finding:** TSIG-gated, prevents unauthorized updates

---

### 5. REQUEST HANDLING PIPELINE

**File:** `cmd/nothingdns/handler.go` (21 stages)

| Stage | Security Measure |
|-------|------------------|
| 1 | Panic recovery |
| 2 | IDNA validation (RFC 5891) |
| 3 | ACL check |
| 4 | RPZ client IP policy |
| 5 | Rate limiting |
| 6 | DNS Cookie validation |
| 7 | AXFR/IXFR/NOTIFY/UPDATE handling |
| 8 | Blocklist check |
| 9 | RPZ QNAME policy |
| 10 | Cache lookup |
| 11 | NSEC aggressive cache |
| 12 | Split-horizon view zones |
| 13 | Authoritative zone lookup |
| 14 | CNAME chasing |
| 15 | Iterative resolver |
| 16 | Upstream forwarding |
| 17 | DNSSEC validation |
| 18 | RPZ response checks |
| 19 | DNS64 synthesis |
| 20 | Response caching |
| 21 | Stale serving (RFC 8767) |

**Finding:** ✅ Comprehensive pipeline with defense-in-depth

---

### 6. FINDINGS SUMMARY

#### 6.1 HIGH CONFIDENCE - SECURE
- JWT with proper claims and expiration
- PBKDF2 password hashing (100k+ iterations)
- AES-256-GCM cluster encryption
- DNSSEC validation with multiple algorithm support
- TSIG for zone transfer authentication
- Rate limiting with token bucket
- ACL-based access control
- Input validation at all entry points

#### 6.2 MEDIUM CONFIDENCE - MONITOR
- HMAC-SHA1 allowed in TSIG (legacy)
- HMAC-MD5 allowed in TSIG (legacy, should warn)
- InsecureSkipVerify in e2e tests (contained to tests)

#### 6.3 RECOMMENDATIONS
1. Log warning when HMAC-MD5/HMAC-SHA1 TSIG used
2. Add configuration option to disable legacy algorithms
3. Document that InsecureSkipVerify only exists in test code
4. Consider Ed25519-only mode for new deployments

---

### 7. CONFIGURATION VALIDATION

**File:** `cmd/nothingdns/main.go`

| Check | Status |
|-------|--------|
| Recursive resolver ACL warning | ✅ Logged on startup |
| TLS certificate validation | ✅ |
| Configuration syntax validation | ✅ `-validate-config` flag |
| Hot-reload with SIGHUP | ✅ |

---

### 8. TEST COVERAGE SECURITY

**Files with InsecureSkipVerify:**
- `internal/e2e/*.go` - Test-only
- `internal/server/*_test.go` - Test-only
- `internal/transfer/coverage_extra*.go` - Coverage tests

**Finding:** No production code uses insecure TLS settings.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  UDP/TCP/TLS/DoH/DoQ Transport Layer                           │
├─────────────────────────────────────────────────────────────────┤
│  21-Stage Request Pipeline (handler.go)                        │
│  ├── Panic recovery                                              │
│  ├── IDNA validation (RFC 5891)                                 │
│  ├── ACL check                                                  │
│  ├── Rate limiting (token bucket)                              │
│  ├── DNS Cookie (RFC 7873)                                     │
│  ├── DNSSEC validation                                         │
│  └── Response caching                                          │
├─────────────────────────────────────────────────────────────────┤
│  Managers                                                       │
│  ├── Security (ACL, RPZ, blocklist, rate limit)                │
│  ├── DNSSEC (validator, signer, keystore)                     │
│  ├── Cluster (AES-256-GCM gossip, Raft)                       │
│  └── Transfer (TSIG, AXFR/IXFR, DDNS)                         │
├─────────────────────────────────────────────────────────────────┤
│  Storage (KV + WAL, TLV serialization)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Compliance Mapping

| RFC | Requirement | Status |
|-----|-------------|--------|
| RFC 1035 | DNS wire protocol | ✅ |
| RFC 4035 | DNSSEC protocol | ✅ |
| RFC 6840 | DNSSEC clarifications | ✅ |
| RFC 7873 | DNS Cookies | ✅ |
| RFC 8037 | Ed25519 for DNSSEC | ✅ |
| RFC 8484 | DNS over HTTPS | ✅ |
| RFC 9103 | XoT (TLS) | ✅ |
| RFC 8767 | Stale serving | ✅ |
| RFC 8198 | NSEC aggressive caching | ✅ |

---

## Conclusion

NothingDNS demonstrates strong security architecture with:
- Zero external dependencies (reduced supply chain risk)
- Comprehensive defense-in-depth pipeline
- Industry-standard cryptographic implementations
- Proper authentication and authorization

**Risk Level: LOW** with minor hardening opportunities for legacy algorithm support.

---
*Report generated by security-check skill*