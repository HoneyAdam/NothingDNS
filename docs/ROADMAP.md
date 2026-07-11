# NothingDNS Roadmap

## Overview

NothingDNS is a production-grade DNS server written in Go with a minimal external dependency set. This roadmap outlines planned features, improvements, and long-term vision.

## Version History

| Version | Status | Date |
|---------|--------|------|
| 0.1.1 | Current | 2026-07-06 |
| 0.2.0 | Planned | TBD |
| 1.0.0 | Future | TBD |

---

## v1.1.0 — Operator Experience

Target: Better tooling and reliability improvements.

### CLI Completeness

- [x] `dnsctl record` — Add/update/remove records via API
- [x] `dnsctl zone add/remove` — Zone lifecycle management
- [x] `dnsctl cluster join/leave` — Cluster operations
- [x] `dnsctl blocklist reload` — Blocklist refresh
- [ ] `nothingdns -validate-config -config <path>` documentation and UX polish

### Reliability Improvements

- [x] RPZ: Log malformed rules at Warn level with line number
- [ ] RPZ: Add `rpz_parse_errors_total` metric counter
- [x] Raft: Expand test coverage to 150+ tests, ratio > 0.50
- [x] Frontend auth: Fix login flow to use JWT endpoint properly
- [x] Token auth: Remove query parameter token support

### Metrics & Observability

- [ ] Per-record-type latency histograms
- [ ] Upstream health scoring
- [ ] Cluster node latency breakdown
- [ ] Blocklist match rate by source

---

## v1.2.0 — Performance

### Caching Enhancements

- [ ] Redis adapter for distributed cache
- [ ] Cache prefetch policies (predictive, ML-based)
- [ ] Persistent negative cache with disk spillover

### Query Processing

- [ ] Batch query processing for UDP
- [ ] Zero-copy wire format parsing
- [ ] SIMD-accelerated name compression

### DNSSEC Performance

- [ ] Pre-signed zone support
- [ ] Hardware acceleration (PKCS#11)
- [ ] ECDSA P-384 support
- [ ] Ed25519ph (pre-hashed) for large zones

---

## v2.0.0 — Major Architecture Changes

### Storage

- [ ] **BadgerDB adapter** — Alternative to current KVStore using Badger
- [ ] **Tiered storage** — Hot (memory), warm (SSD), cold (HDD)
- [ ] **Automatic compaction** — Background garbage collection

### Clustering

- [ ] **Multi-cluster federation** — Regions that share cache selectively
- [ ] **Anycast support** — Multiple nodes advertising same IP
- [ ] **Raft improvements** — Joint consensus, linearizable reads
- [ ] **Consensus metrics** — Election timing, log lag, snapshot progress

### Security

- [ ] **mTLS for cluster** — Mutual TLS instead of pre-shared key
- [ ] **Audit log export** — Syslog, SIEM integration (Elasticsearch, Splunk)
- [ ] **Rate limit by ASN** — BGP-based rate limiting
- [ ] **OAuth2/OIDC** — Identity provider integration

### Protocols

- [ ] **DNS-over-HTTP/3** — HTTP/3 support for DoH
- [ ] **EPP (Extensible Provisioning Protocol)** — Domain registrar protocol
- [ ] **CRISP** — Chaotic Resolver to Improve Speed Privacy
- [ ] **Privacy Pass** — Token binding for DNS

### Observability

- [ ] **OpenTelemetry native** — Full OTLP export
- [ ] **Distributed tracing** — End-to-end query tracing across cluster
- [ ] **Prometheus alerting rules** — Production-grade alerts
- [ ] **Grafana dashboards** — Pre-built dashboard JSON

### API

- [ ] **GraphQL API** — Alternative to REST for complex queries
- [ ] **Webhooks** — Event-driven notifications (zone update, cache clear)
- [ ] **Streaming API** — Server-sent events for real-time updates
- [ ] **gRPC management API** — High-performance management interface

---

## Long-Term Vision

### Cloud-Native

- [ ] **Kubernetes operator** — Custom controller for NothingDNS
- [ ] **Helm improvements** — Values schema, complex configurations
- [ ] **Admission controller** — Validate DNS configurations at deploy time
- [ ] **Multi-tenant isolation** — cgroups, namespaces for multi-tenant

### Research & Experimentation

- [ ] **QNAME minimization improvement** — RFC 7816bis
- [ ] **Aggressive NSEC4** — NSEC for hashed names without NSEC3 chain
- [ ] **Zero-knowledge DNS** — Proof of no record without revealing zone
- [ ] **CoDoNS** — Collaborative DNS with privacy

### Integration

- [ ] **Terraform provider** — Infrastructure as code
- [ ] **Ansible collection** — Configuration management
- [ ] **Pulumi provider** — Modern IaC
- [ ] **Service mesh integration** — Istio, Linkerd support

---

## Backlog (Unprioritized)

These items are collected but not yet scheduled:

### Features
- ACME (Let's Encrypt) integration for automatic TLS
- ACME DNS challenge provider
- BGP route reflector for anycast
- DHCP integration for dynamic IP updates
- DNSBL (DNS Block List) aggregation
- Email autoreply via custom DNS records
- Split-horizon views by AS number
- Time-series database for query analytics
- WHOIS proxy

### Performance
- ARM64 optimizations
- Vectorized DNS message parsing (AVX-512)
- Lock-free data structures for hot paths
- NUMA-aware memory allocation
- RDMA for cluster communication

### Security
- Certificate transparency monitoring
- DNS CERT record type for S/MIME
- Certificate Management over CMS (CMC)
- TPM 2.0 integration for key storage
- FIPS 140-2 compliance mode

### Usability
- Interactive setup wizard
- Migration tools from BIND, PowerDNS
- Zone file validation tool
- DNSSEC deployment assistant
- Configuration GUI (desktop app)

---

## Deprecation Notices

### Planned Removals

| Feature | Version | Reason |
|---------|---------|--------|
| HMAC-MD5 for TSIG | v2.0 | Insecure, use SHA-256 |
| JSON API (DoH) | v2.0 | Use wire format or JSON+DO |
| Legacy auth token | v2.0 | JWT only |
| SWIM (SWIM-only mode) | v2.0 | Use Raft for consistency |

---

## External Dependencies Policy

| Package | Purpose | May Remove When |
|---------|---------|----------------|
| quic-go | DoQ transport | Standard library QUIC available |
| golang.org/x/sys | Socket options | Go stdlib exposes needed options |

---

## Community Requests

These features are requested by users but not yet planned:

1. **IPv6-only mode** — Disable IPv4 completely
2. **Windows native support** — Without Docker
3. **DNS-over-TOR** — Anonymized DNS resolution
4. **Let's Encrypt DNS challenge** — Automated certificate management
5. **PowerDNS-compatible API** — Migration path

---

## Contributing to Roadmap

The roadmap is driven by:
1. **Security audits** — Critical fixes prioritized
2. **User requests** — Upvoted issues
3. **Maintainer experience** — Operational burden reduction
4. **Industry trends** — RFC compliance, performance standards

To propose features:
1. Open a GitHub issue with `feature-request` label
2. Describe the use case and motivation
3. Explain expected behavior
4. Provide sample configuration if applicable

---

## Versioning Policy

- **MAJOR** (x.0.0): Breaking changes, major architecture
- **MINOR** (x.y.0): New features, backwards-compatible
- **PATCH** (x.y.z): Bug fixes, security updates

**Support**: Latest minor version gets security patches.
**EOL**: Major version supported for 2 years after next major release.