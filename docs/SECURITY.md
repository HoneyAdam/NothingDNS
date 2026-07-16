# Security Policy

## Supported Versions

| Version | Supported          |
|---------|-------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in NothingDNS, please report it responsibly.

**Do NOT open a public GitHub issue** for security vulnerabilities.

### How to Report

1. **Email**: Send a description of the vulnerability to the maintainers
2. **Private Security Forum**: Use [GitHub's Private Vulnerability Reporting](https://github.com/NothingDNS/NothingDNS/security/advisories/new) if available
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- Acknowledgment within 48 hours
- Regular updates on remediation progress
- Public disclosure after a fix is released

## Security Design Principles

### Minimal External Dependencies

NothingDNS has **minimal external dependencies** — only two non-standard-library packages:

1. **`github.com/quic-go/quic-go`** — Required for DNS over QUIC (DoQ, RFC 9250). QUIC is a complex protocol that requires a mature implementation. The `quic-go` library is actively maintained and widely used in production.

2. **`golang.org/x/sys`** — Required for platform-specific socket operations (e.g., `SO_REUSEPORT` for multi-core scalability on Linux).

All cryptographic operations use Go's standard library `crypto/*` packages. No third-party crypto libraries are used.

### DNSSEC
- Signing uses RSA/SHA-256/SHA-512 with key rollover support
- Validation follows RFC 4035 with chain-of-trust from trust anchors
- NSEC3 opt-out support for large delegations

### TSIG
- RFC 2845 HMAC-MD5/SHA-1/SHA-256/SHA-512 for AXFR/IXFR/DDNS
- TSIG errors cause transfer failure, not silent fallback

### Network
- TLS/DoT/DoH/DoQ support with configurable cipher suites
- SO_REUSEPORT for multi-core scalability
- No arbitrary code execution in zone files

### Supply Chain
- GitHub Actions are pinned by commit SHA instead of mutable tags where credentials are available
- Container images are built with SBOM and SLSA provenance attestations
- Published container image digests are keylessly signed with Sigstore cosign via GitHub OIDC
- Operators should deploy immutable image digests and verify cosign signatures before promotion

### ACL
- IP-based access control for queries and management
- Rate limiting (RRL) for query amplification prevention

### API Security

- **HTTP bind address**: The default `http.bind` in `config.example.yaml` is
  `"0.0.0.0:8080"`, which listens on every network interface. In production,
  bind to `"127.0.0.1:8080"` behind a reverse proxy (nginx, Caddy), enable
  TLS for HTTPS encryption, or restrict access with a firewall.
- **CORS wildcard origins**: The production config validator
  (`validateProduction`) rejects `allowed_origins: ["*"]` when `http.bind`
  is a public (`0.0.0.0` / `::`) address. Use explicit origin lists in
  production (`allowed_origins: ["https://dns.example.com"]`).
- **Rate limiting**: Login endpoints are rate-limited per-IP and per-account
  with configurable lockout thresholds. Unauthenticated requests consume rate
  limit budget before authentication (prevents tie-to-IP bypass via brute
  force).
- **Auth token storage**: Bearer tokens are held in memory only
  (Zustand store), never written to localStorage. The backend HttpOnly cookie
  is never read from JavaScript.

## Authorization Model

### RBAC and Zone Access

NothingDNS uses role-based access control with three levels: `admin`, `operator`, and `viewer`.

**Important**: All authenticated operators have **global access** to all zones. There is no per-zone ownership, multi-tenant isolation, or object-level authorization. If you require strict separation between zones, run separate NothingDNS instances.

## Known Limitations

- DNSSEC signing is performed on-the-fly (not pre-signed). High-QPS DNSSEC-signed zones may experience elevated CPU usage.
- TSIG uses HMAC-MD5 for backwards compatibility. Prefer SHA-256 or SHA-512 where supported.
