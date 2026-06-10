# Performance Backlog

Tracks remaining performance work after the audit landed in commits
`1679ec1`, `8e6d2b0`, and `6940dca` (May 2026).

> Rule: no optimization without a measurement to back it up. Every item
> below has a benchmark target and an honest estimate of risk.

---

## Baseline (after current commits)

Hardware: AMD Ryzen 9 9950X3D, Go 1.26.2, Windows. Bench command:

```bash
go test -bench=. -benchmem -run='^$' -benchtime=500ms ./internal/...
```

| Bench | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `MessageUnpack` (no release) | 575 | 1041 | 42 |
| `MessageUnpack_Released` (3A pool active) | 561 | 849 | 37 |
| `CacheGet_Hit` (single thread) | 65 | 13 | 1 |
| `CacheGet_Hit` (32 threads parallel) | 44 | 15 | 1 |
| `CacheSet` (single thread) | 287 | 139 | 3 |
| `CacheSetParallel` (32 threads) | 85 | 136 | 2 |
| `ParseDomain` | 104 | 192 | 5 |
| `IsSubdomain` | 312 | 320 | 9 |
| `ReverseDNS_v6` | 1453 | 1105 | 6 |

At 100 k QPS the dominant residual cost is the **~37 allocations per
inbound query** in `protocol.UnpackMessage`. About 24 of those come
from per-record structs (Question, ResourceRecord, Name, label slices,
RData) that aren't yet pooled. The other ~12 are label strings, which
cannot be pooled while names are stored as `[]string` (strings are
immutable).

---

## Backlog, ranked by impact

### P0 — Phase 3B: per-record pools

**Files (~3-5):** `internal/protocol/{labels,question,record,message}.go`,
`internal/protocol/bench_test.go`.

**Goal:** Pool `*Question`, `*ResourceRecord`, `*Name`, `[]string` label
slices, and the most common `RData` types (`RDataA`, `RDataAAAA`,
`RDataCNAME`, `RDataMX`, `RDataNS`, `RDataPTR`, `RDataSOA`, `RDataTXT`,
`RDataSRV`).

**Estimated win:** `MessageUnpack_Released` 37 → ~15 allocs/op (−59%);
B/op 849 → ~250 (−70%). At 100 k QPS that's roughly 60 MB/s of allocator
pressure removed — much larger than anything in 1, 2, or 3A.

**Risk:** **Medium-high.** Per-type Release recursion must be exhaustive;
a single missed branch leaks pool slots silently. RData is variant-typed
(20+ concrete types) so a switch over types is required. Use-after-Release
is silent corruption — write a `-race` build with poison-on-Put for
debug builds.

**Plan:**
1. Add pools and `Release()` for `*Name` and `[]string` Labels first
   (simplest types).
2. Add `*Question.Release()` (calls Name.Release).
3. Add `*ResourceRecord.Release()` with a type-switch over RData.
4. Update `(*Message).Release()` to recurse.
5. Update `UnpackQuestion` / `UnpackName` / `UnpackResourceRecord` /
   per-RData Unpack to use pools.
6. Verify `BenchmarkMessageUnpack_Released` shows the drop.
7. Verify `go test ./... -race` clean.

**Out of scope:** Label string pooling (impossible without wire-byte
names — see P3 below).

---

### P1 — Phase 3C: migrate transports to call `Release()`

**Files (~5):** `internal/server/{udp,tcp,tls}.go`,
`internal/doh/handler.go`, possibly `internal/odoh/odoh.go`.

**Goal:** After each request is fully handled, call `query.Release()`
in the transport so the pooled `*Message` actually returns to the pool.
Without this, Phase 3A and 3B's pools sit empty in production and
allocate fresh on every Get.

**Estimated win:** Activates the Phase 3A and 3B savings in production.
The bench numbers from those phases become real production numbers.

**Risk:** **High.** This is the lifecycle audit step the original
performance report flagged as the riskiest. If a code path in the
handler retains the query message past the response (e.g., async
logging, audit trail, cache key derivation that lives past the call,
NOTIFY relay), Release-then-access produces silent data corruption.

**Plan:**
1. Audit `cmd/nothingdns/handler.go ServeDNS` for any goroutine spawn
   that captures the query.
2. Audit each transport's response path for places that read `r.*`
   after `reply(w, r, ...)` returns.
3. Add `defer query.Release()` only after every retain site is
   identified and either copies (`query.Copy()`) or runs synchronously.
4. Build with `-race` and run the e2e suite hard.
5. Add a poison-on-Release debug mode (build tag `pool_poison`) that
   memsets released structs to a sentinel — surfaces use-after-release
   immediately during testing.

**Coupling:** Should land **after** Phase 3B so the per-record allocs
are pooled too — otherwise we're only saving 5 allocs in production.

---

### P2 — Cache: alloc-free cache key on the request hot path

**Files (~3):** `internal/cache/cache.go`, `cmd/nothingdns/handler.go`,
`cmd/nothingdns/authoritative.go`.

**Goal:** Eliminate the per-query `cache.MakeKey(qname, qtype, doBit)`
string allocation. Currently 1 alloc / ~13 B per query in
[handler.go:324](../cmd/nothingdns/handler.go#L324).

**Estimated win:** Small — 1 alloc / 13 B per query (~1.3 MB/s at 100 k
QPS). Order of magnitude smaller than Phase 3B.

**Approach options:**
- **A:** Change internal storage to `map[Key]*Entry` where
  `type Key struct { Name string; QType uint16; DO bool }`. Tests need
  parseKey shim; `Entry.Key` field shape changes; persistence file
  format must keep string form for backward compat.
- **B:** Keep `map[string]*Entry`, exploit the Go compiler's
  `m[string(b)]` no-alloc optimization for lookups. Works for `Get`,
  not for `Set` (Set must store a string in the map).

Either way, only `Get` benefits — `Set` already allocates a string
because the map key has to outlive the call.

**Risk:** Low (option A — many test sites; option B — depends on a
compiler optimization that's documented but not guaranteed).

**When to do this:** Only after P0/P1. Marginal win compared to message
pooling.

---

### P3 — Wire-byte names (the big one)

**Scope:** Project-wide. Touches every consumer of
`protocol.Name.Labels`.

**Goal:** Replace `Name { Labels []string; FQDN bool }` with
`Name { Wire []byte }` (a single contiguous length-prefixed wire-format
slice borrowed from the packet buffer until the request completes; copied
once if cached). All label-level operations (case-insensitive compare,
suffix match, label count, length) work directly on bytes.

**Estimated win:** Eliminates the ~12 label-string allocs that survive
Phase 3B. `MessageUnpack_Released` 37 → ~6 allocs/op. Plus removes the
`String()` allocation in DNSSEC's `CanonicalWireName(rr.Name.String())`
path.

**Risk:** **High.** This is the largest refactor on the list. Every
caller of `Name.Labels` (zone matcher, RPZ engine, blocklist, audit
logger, DNSSEC validator/signer, transfer, dashboard JSON)
becomes a touch point. CLAUDE.md flags
`protocol.CanonicalWireName()` as a shared canonical encoder; that
constraint extends to whatever replaces label-slice access.

**When to do this:** Only after P0/P1 are stable in production for some
time. This is a multi-week refactor with high regression risk.

---

### P4 — `util.ReverseDNS` IPv6 path: 1453 ns → ~50 ns

**Files (1):** `internal/util/ip.go`.

**Goal:** Rewrite the IPv6 reverse DNS builder in
[`ReverseDNS`](../internal/util/ip.go#L246) to use a fixed-size buffer
and a hex nibble lookup table instead of 32× `fmt.Sprintf` + a
`strings.Join`.

**Estimated win:** ~30× speedup on `ip6.arpa` PTR queries; 6 allocs → 1
alloc per call. Affects PTR queries and the iterative resolver's
zone-cut PTR lookups.

**Risk:** Trivial. ~30 LOC. Existing tests cover the output format.

**Why it's not P0:** Affects only PTR queries, which are a small slice
of total traffic for most deployments.

---

### P5 — `util.IsSubdomain` / `util.ParseDomain` allocation cleanup

**Files (1):** `internal/util/domain.go`.

**Goal:** Replace `IsSubdomain(child, parent string) bool` (currently
9 allocs / 320 B) with a pure-byte right-to-left compare (0 allocs).
Same treatment for `ParseDomain` and `NormalizeDomain` if the only
need is normalisation, not the full `*Domain` struct.

**Estimated win:** Per-call: 9 → 0 allocs on `IsSubdomain`. Used
heavily in zone load and ACL/blocklist config parsing — mostly cold
path, but the request path also calls into these via splithorizon and
NOTIFY validators.

**Risk:** Low. ~50 LOC. Existing unit tests cover the function's
contract.

---

### P6 — Cache `Set` regression vs pre-sharding

**Files (1):** `internal/cache/cache.go`.

**Observation:** Phase 2A regressed single-thread `CacheSet` from 218
ns to 287 ns (+32%). Causes:
- `maphash.String` runs once per Set for shard selection (~10-15 ns).
- Per-shard maps start smaller (cap/16) and grow more often during
  cache warm-up.
- Per-shard atomic counters add a write-set on every Set.

**Possible mitigations:**
- Hoist shard hashing to the caller for high-volume Set paths.
- Pre-size per-shard maps using a hint about expected steady-state
  fill (skip the early growth churn).
- Make `Stats` an opt-in feature (build tag) — its atomic counters cost
  ~5-10 ns per call.

**Estimated win:** Maybe 30-50 ns/op recovered on single-thread Set.
Trade-off vs visibility (atomic counters are useful in production).

**Risk:** Low. Localized to cache package.

**Why it's not P0:** Set is ≤ 10% of operations on a hit-heavy DNS
cache. The 70-ns regression in absolute terms is dwarfed by the 200+ ns
parallel Set saving.

---

### P7 — Probe pprof / live e2e load test

**Files:** none — scaffolding.

**Goal:** None of the wins above have been measured under live UDP
load on this server. Synthetic benches are lower bounds. Real wins
compound when GC pauses disappear.

**Plan:**
1. Stand up a load generator (e.g. `dnsperf` or a bespoke Go client
   pummelling UDP/53).
2. Capture CPU + heap profiles before and after each phase.
3. Track p50/p95/p99 latency, throughput, CPU%, RSS, GC pause time.
4. Publish numbers in `docs/PERF_RESULTS.md`.

**Risk:** None. This is measurement, not change.

**Why it's important:** Without this, the bench numbers above are
internally consistent but don't tell you how much faster the *actual*
server is. Some changes (sharding) might overshoot; others (label-byte
names) may have second-order benefits no benchmark captures.

---

## What's already done (May 2026)

| Commit | Phase | Change | Bench Δ |
|---|---|---|---|
| `1679ec1` | 1 | Probabilistic LRU promotion | CacheGet_Hit −22% serial, −23% parallel |
| `8e6d2b0` | 2A | 16-shard cache | CacheGet_Hit **−77% parallel**, Set **−68% parallel** |
| `6940dca` | 3A | Pool `*Message` + section slices | Unpack_Released −12% allocs / −18% bytes |

---

## Recommended next phase

**Bundle P0 + P1 as a single phased release.** P0 (per-record pools)
on its own delivers no production win; P1 (transport migration) on its
own gives only the small Phase 3A savings. Together they activate the
full ~25-alloc reduction per query in production.

Plan the rollout as:
1. Phase 3B-1 — `*Name` + label slice pools alone, with `-race` test.
2. Phase 3B-2 — `*Question` + `*ResourceRecord` pools.
3. Phase 3B-3 — RData pools (per type).
4. Phase 3C — UDP transport migration (highest-volume).
5. Phase 3C — TCP / TLS / DoH migration.
6. Production canary with poison-on-Release build for one week.

After that, P4 (ReverseDNS) and P5 (IsSubdomain) are quick wins that
can ship anytime — independent of the message-pool work.

P3 (wire-byte names) is the eventual largest payoff but should not be
attempted until P0-C are stable in production.
