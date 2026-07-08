# NothingDNS Competitor Matrix

An evidence-based comparison against the main DNS products NothingDNS competes with. This document is intentionally conservative: **"better" requires proof**, not preference.

## Compared products

- **NothingDNS**
- **BIND 9**
- **Unbound**
- **CoreDNS**
- **PowerDNS Authoritative + Recursor**
- **Pi-hole / AdGuard Home / Technitium** (management-plane and self-host market)

## Evaluation rules

- **Yes** = built-in and evidenced in the codebase/docs
- **Partial** = available with caveats, split components, or weaker proof
- **No** = not present / not a core product capability
- **Unknown** = not enough evidence in this repository to compare honestly

## Summary

NothingDNS is strongest where operators want **one integrated DNS platform** rather than multiple components stitched together. It is weaker where incumbents have long production history, install base, and ecosystem trust.

## Capability matrix

| Capability | NothingDNS | BIND 9 | Unbound | CoreDNS | PowerDNS | Self-host DNS suites |
|---|---|---|---|---|---|---|
| Authoritative DNS | **Yes** | Yes | Limited/No | Partial | Yes | Partial/Yes |
| Recursive resolver | **Yes** | Partial | Yes | Partial | Yes (separate recursor) | Partial |
| Forwarder mode | **Yes** | Yes | Yes | Yes | Yes | Yes |
| DNSSEC validation | **Yes** | Yes | Yes | Partial | Yes | Partial |
| DNSSEC signing | **Yes** | Yes | No | Partial | Yes | Partial |
| AXFR / IXFR / DDNS / NOTIFY | **Yes** | Yes | Partial | Partial | Yes | Partial |
| DoT | **Yes** | Partial | Yes | Partial | Partial | Partial |
| DoH | **Yes** | Partial | Partial | Partial | Partial | Yes |
| DoQ | **Yes** | Rare/Partial | Partial | Partial | Partial | Rare |
| Embedded web UI | **Yes** | No | No | No | Partial | **Yes** |
| REST API | **Yes** | Partial/RNDC-style tooling | No | No/Plugin-specific | Yes | **Yes** |
| Embedded CLI | **Yes** | Yes | Partial | Partial | Partial | Partial |
| Single-binary product story | **Yes** | No | No | **Yes** | No | Yes |
| Integrated auth + recursive + policy + UI | **Yes** | No | No | No | No | Partial |
| Built-in clustering | **Yes** | Partial | No | Partial | Partial | Rare |
| Raft consensus option | **Yes** | No/Unknown | No | No/Unknown | No/Unknown | Rare |
| Embedded persistent zone DB | **Yes** | Partial (file/db based ops) | No | No | Yes | Yes |
| Prometheus metrics | **Yes** | Partial | Partial | **Yes** | Partial | Partial |
| OpenAPI / Swagger | **Yes** | No | No | No | Partial | Rare |

## Where NothingDNS is genuinely strong

### 1. Product integration

NothingDNS combines in one codebase and runtime surface:

- authoritative DNS
- recursive/forwarding logic
- DNSSEC validation/signing
- policy controls (ACL, RPZ, blocklists, RRL)
- REST API
- embedded React dashboard
- CLI
- optional cluster / Raft mode
- persistent zone storage

Many competitors require combining multiple products or external systems to achieve the same operational surface.

### 2. Operator experience potential

NothingDNS has the pieces to win on operator ergonomics:

- API + web UI + CLI out of the box
- embedded docs / OpenAPI surface
- single deployable product story
- Kubernetes/Helm/systemd/Docker assets already in repo

This is a meaningful differentiator against BIND/Unbound-class tools.

### 3. Architectural ambition

Very few DNS projects try to combine:

- authoritative + recursive
- zone durability
- management plane
- encrypted transports
- policy engine
- cluster consensus

in one implementation.

## Where NothingDNS is still behind

### 1. Market trust

Incumbents still lead in:

- years in production
- install base
- community familiarity
- ecosystem depth
- operational folklore / battle scars

### 2. Proof burden

NothingDNS has strong implementation evidence, but market leadership requires more public proof:

- repeatable benchmarks against incumbents
- live upgrade / failure / recovery playbooks
- long-running cluster soak results
- migration guides and real operator case studies

### 3. Ecosystem

We are behind projects like CoreDNS and PowerDNS in:

- integrations
- plugin ecosystem
- external tooling familiarity
- deployment mindshare

## Current honest position

### Claim we can support today

> NothingDNS is an unusually broad, integrated DNS platform with real authoritative, recursive, persistence, clustering, API, and dashboard surfaces.

### Claim we cannot support today

> NothingDNS is clearly ahead of all competitors overall.

That statement requires stronger benchmark, reliability, and adoption proof.

## What would move us into leadership territory

1. **Proof pack** — public, reproducible release gates and recovery checks
2. **Benchmark pack** — compare latency, memory, QPS, and DNSSEC cost against BIND / Unbound / CoreDNS / PowerDNS
3. **Cluster confidence pack** — failure scenarios, snapshot/restart/membership recovery evidence
4. **Migration story** — import/migrate from BIND, PowerDNS, Pi-hole, AdGuard Home
5. **Operator UX polish** — make day-1 and day-2 operations easier than incumbents

## Verdict

- **Best integrated all-in-one story:** plausible
- **Best overall DNS product in the market:** not yet proven
- **High-potential differentiated contender:** yes
