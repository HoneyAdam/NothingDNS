# Market Leadership Roadmap

This roadmap converts the broad goal of "be the best in the market" into an evidence-driven execution plan. It does **not** assume feature count alone wins the market.

## Principles

1. **Trust beats breadth.** A smaller proven surface beats a larger unproven one.
2. **Proof beats claims.** Public benchmark and recovery evidence matter more than adjectives.
3. **Operator time matters.** We win when deployment, operations, and troubleshooting are easier.
4. **Integration is our wedge.** The strongest differentiation is the all-in-one product surface.

---

## Where we can win

### Strongest differentiator

NothingDNS can become the strongest **integrated all-in-one DNS platform**:

- authoritative + recursive
- policy engine
- encrypted transports
- embedded persistence
- optional cluster / Raft
- API + dashboard + CLI

That is a clearer market wedge than trying to out-BIND BIND on age or out-CoreDNS CoreDNS on ecosystem.

### We are not going to win first on

- decades of production reputation
- install base
- plugin ecosystem size
- default enterprise procurement comfort

So the roadmap focuses on **proof, usability, and integrated product quality**.

---

## Phase 1 — Prove the core claims (0–2 weeks)

### Goal

Make the project's strongest claims auditable and reproducible.

### Deliverables

1. **Production proof pack**
   - `docs/PRODUCTION_PROOF_CHECKLIST.md`
   - release evidence artifact format

2. **Competitor matrix**
   - `docs/COMPETITOR_MATRIX.md`
   - honest strengths/weaknesses by category

3. **Release proof script(s)**
   - extend smoke and validation tooling
   - make evidence collection repeatable

### Exit criteria

- we can prove build, config validation, web/API health, metrics auth, and smoke behavior from a clean tree
- claims about persistence and cluster behavior are tied to specific tests or runtime validation steps

---

## Phase 2 — Close trust gaps in durability and clustering (1–3 weeks)

### Goal

Remove operator doubt around the two highest-stakes product claims:

- zone durability
- cluster correctness

### Work items

#### A. Zone durability truth table

Document and verify:

- file-backed zones
- KV-backed zones
- API-created zones
- DDNS-mutated zones
- deletion persistence
- restart behavior
- config-zone vs KV-zone interactions

#### B. Cluster operating model

Document and verify:

- SWIM vs Raft roles
- what state is replicated
- what state is durable locally
- leader/follower expectations
- restart and snapshot semantics
- failure and recovery playbooks

#### C. Runtime proof scenarios

Add explicit operator-run scenarios for:

- leader election
- follower replication
- restart recovery
- snapshot/install-snapshot
- degraded cluster behavior

### Exit criteria

- a skeptical operator can answer "what persists, what replicates, and what recovers" without reading the source

---

## Phase 3 — Become the easiest serious DNS platform to operate (2–4 weeks)

### Goal

Beat traditional competitors on operator experience.

### Work items

1. **Dashboard trust pass**
   - every major page backed by real data
   - clear empty/error/loading states
   - role-aware affordances

2. **CLI trust pass**
   - every documented command works
   - no stale examples
   - scripts for common admin workflows

3. **Deployment trust pass**
   - systemd, Docker, Helm, raw K8s all validated end-to-end
   - metrics auth, secret inputs, and smoke checks documented

4. **Troubleshooting trust pass**
   - faster diagnosis workflows
   - explicit cluster/persistence failure playbooks
   - minimal ambiguity in docs

### Exit criteria

- first successful deployment and first successful diagnosis take less time than with incumbent stacks for common operator workflows

---

## Phase 4 — Publish measurable performance and reliability evidence (2–4 weeks)

### Goal

Turn technical quality into public competitive leverage.

### Work items

1. **Benchmark pack**
   - protocol
   - cache
   - DNSSEC
   - query throughput/latency under realistic mixes

2. **Competitor comparison runs**
   - BIND
   - Unbound
   - CoreDNS
   - PowerDNS
   - a self-host DNS suite where comparable

3. **Recovery drills**
   - restart time
   - snapshot restore time
   - leader failover time
   - config reload latency

4. **Public evidence format**
   - table + methodology + caveats
   - no cherry-picking

### Exit criteria

- we can say where we are faster, where we are simpler, and where we are still behind

---

## Phase 5 — Grow the adoption surface (4+ weeks)

### Goal

Reduce switching cost from incumbents.

### Highest-leverage items

- migration guides from BIND / PowerDNS / Pi-hole / AdGuard Home
- import/translation helpers
- better example deployments
- Terraform / Ansible / operator stories
- public reference architectures

### Exit criteria

- operators can adopt NothingDNS without manually reverse-engineering their migration path

---

## Strategic ranking of next bets

### Highest ROI

1. **Proof and release evidence**
2. **Durability/cluster trust**
3. **Operator UX and docs**
4. **Comparative benchmark publication**
5. **Migration/adoption tooling**

### Lower ROI right now

- speculative advanced protocols
- flashy feature additions without proof
- benchmark claims without methodology
- ecosystem expansion before operator trust is established

---

## What "best in market" would actually mean for NothingDNS

We should define success narrowly and honestly:

### A claim we can realistically target

> Best integrated self-hostable DNS platform for teams that want authoritative + recursive + policy + API + UI + optional clustering in one product.

### A claim we should avoid until much later

> Best DNS server overall for every use case.

---

## Immediate next actions

1. Keep the newly added competitor matrix up to date with evidence, not opinions.
2. Use the production proof checklist as a release gate input, not just documentation.
3. Extend the smoke/proof tooling so results can be captured in CI and release notes.
4. Prioritize trust-building work over new shiny protocol features.

## Status

- Competitor matrix: **started**
- Production proof checklist: **started**
- Market execution roadmap: **started**
- Proof automation: **needs implementation expansion**
