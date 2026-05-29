# NothingDNS — Refactoring & Improvement Plan

> **Status:** Analysis snapshot — 2026-05-29
> **Scope:** Whole repository (411 Go files, ~231k LOC, `cmd/` + `internal/`)
> **Baseline health:** `go build` ✅ · `go vet ./...` ✅ · `golangci-lint` ⚠️ (14 issues) · `gofmt` ⚠️ (9 files) · no real `TODO/FIXME` in source
> **Author:** Generated from a multi-agent code survey. Findings carry a **confidence** tag — `High` = directly verified in this pass; `Medium` = strong signal from excerpt reading, verify the exact lines before acting; `Investigate` = plausible risk that an agent flagged but could not fully confirm.

---

## 0. How to read this document

This is a **working plan**, not a verdict. The codebase is in good shape overall: it builds clean, `go vet` is silent, there are 238 test files against 173 source files, and the source is free of `TODO/FIXME` debt markers. The items below are *opportunities* ordered by leverage, not a list of defects you must fix to ship.

⚠️ **Before acting on any "correctness/concurrency" item, reproduce it.** Some findings were produced by agents reading code excerpts; a few of those agents reversed their own conclusions on closer reading (noted inline). Treat the `Investigate` and `Medium` items as hypotheses to confirm with a targeted read + a failing test, never as confirmed bugs.

The work breaks into:
- **Part A — Quick wins** (hours): formatting, lint, doc drift, dead code.
- **Part B — Cross-cutting** (days): error/log/context conventions, dependency policy.
- **Part C — Subsystem deep-dives** (weeks): the large files and the consensus layer.
- **Part D — Security & correctness** (prioritized separately because the blast radius is high).
- **Part E — Testing & tooling**.
- **Part F — Phased roadmap** that sequences all of the above.

---

## 1. Codebase health snapshot

| Signal | Result | Notes |
|---|---|---|
| `go build ./cmd/...` | ✅ Pass | Both `nothingdns` and `dnsctl` compile |
| `go vet ./...` | ✅ Clean | No findings |
| `golangci-lint run ./...` | ⚠️ 14 issues | 2 × `errcheck`, 3 × `errorlint`, 9 × `gofmt` (mostly tests) |
| `gofmt -l` | ⚠️ 9 files | Overlaps with lint gofmt findings |
| `TODO/FIXME/HACK/XXX` in source | ✅ None | (7 grep hits were all `DEBUG` substring false-positives) |
| Test files | 238 (vs 173 source) | Healthy ratio; coverage uneven (see §E) |
| Interfaces declared in `internal/` | 32 | DI surface is thin; managers are concrete (see §C) |
| `panic`/`log.Fatal` outside main/tests | 5 | Mostly intentional fail-fast; one is a Raft persistence panic (see §D) |
| External deps | `quic-go`, `pgx/v5`, `golang.org/x/*` | **`pgx/v5` is undocumented policy drift** (see §B5) |

### Size hotspots (refactor candidates by sheer mass)

| File | LOC | Smell |
|---|---|---|
| `internal/config/config.go` | 2679 | Monolith: struct + defaults + 15 unmarshalers + 12 validators |
| `internal/cluster/gossip.go` | 1746 | God object: SWIM + election + crypto + handlers + stats |
| `internal/protocol/types.go` | 1721 | 17 RData types in one file |
| `cmd/nothingdns/handler.go` | 1551 | `ServeDNS` 21-stage god-method (~767 lines) |
| `internal/cluster/raft/raft.go` | 1474 | Long state-machine + RPC fan-out |
| `internal/dnssec/validator.go` | 1422 | Long `validateMessage` / `buildChain` |
| `cmd/dnsctl/dnssec.go` | 1354 | CLI command sprawl |
| `internal/api/server.go` | 1307 | 90+ manual `mux.HandleFunc`, fixed middleware order |
| `internal/api/api_zones.go` | 1293 | Handler + business logic + validation mixed |
| `cmd/nothingdns/main.go` | 1210 | Wiring + lifecycle + reload all inline |

---

## 2. Priority matrix

| Pri | Theme | Items | Effort | Why now |
|---|---|---|---|---|
| **P0** | Verify security/correctness hypotheses | §D1–D6 | 2–4 d | High blast radius if real; cheap to disprove |
| **P0** | Quick wins | §A1–A4 | 0.5 d | Free; unblocks clean lint gate in CI |
| **P1** | Doc/dependency truth | §B5 | 0.5 d | CLAUDE.md actively misleads contributors |
| **P1** | Context propagation | §B3 | 1–2 d | Breaks tracing + cancellation in hot path |
| **P1** | `ServeDNS` decomposition | §C1 | 3–5 d | Unlocks testability of the entire pipeline |
| **P2** | `config.go` decomposition | §C2 | 3–5 d | Biggest maintenance tax; drift-prone |
| **P2** | API service-layer extraction | §C4 | 3–5 d | Kills REST/MCP duplication (~400 LOC) |
| **P2** | Cluster god-object split + locks | §C3 | 1–2 wk | Correctness-sensitive; do carefully |
| **P3** | Protocol/cache/resolver polish | §C5 | ongoing | Incremental, low-risk |
| **P3** | Test coverage + flake removal | §E | ongoing | Raises confidence for all the above |

---

## Part A — Quick wins (do first, low risk)

### A1. Fix `gofmt` (9 files) · Confidence: High
```
internal/api/coverage_with_test.go
internal/cluster/raft/coverage_extra_test.go
internal/cluster/raft/encoding_test.go
internal/config/validate_test.go
internal/dnscookie/fuzz_test.go
internal/cache/fuzz_test.go
internal/filter/rrl_test.go
internal/geodns/mmdb_decoder_test.go
internal/metrics/metrics.go          <-- only non-test file
```
**Action:** `gofmt -w` the list. Then add a CI gate (`gofmt -l` must be empty). Note `internal/metrics/metrics.go:104` is the only production file affected.

### A2. Fix `errcheck` (2 sites) · Confidence: High
- `cmd/dnsctl/zone.go:107` — `os.Stdout.Write(body)` return ignored. Wrap and surface (CLI can `fmt.Fprintln(os.Stderr, ...)` on error).
- `internal/api/api_auth.go:170` — `s.authStore.DeleteUser("admin")` return ignored. **This is in an auth path** — if the delete fails the caller likely assumes success. Capture and handle.

### A3. Fix `errorlint` non-wrapping verbs (3 sites) · Confidence: High
- `cmd/nothingdns/zone_manager.go:131` — `%v` → `%w` for `decErr`.
- `internal/config/config.go:1938` — `%v` → `%w` for hex parse error.
- `internal/transfer/ddns.go:414` — `fmt.Errorf("%w: %v", ErrPrereqFailed, err)` — the second `%v` should also be `%w` (Go 1.20+ supports multiple `%w`), so `errors.Is` works for both wrapped errors.

### A4. ~~Remove dead fields~~ — WITHDRAWN (false positive) · Confidence: High
- `cmd/nothingdns/handler.go:84–85` (`notifyOnce`/`updateOnce`) were flagged as unused but are **in use** at `cmd/nothingdns/transfer.go:306` and `:399` (`h.notifyOnce.Do(...)` / `h.updateOnce.Do(...)`). **Do not remove.** (Verified 2026-05-29.)

### A5. Stray repo artifacts in working tree · Confidence: High
Working tree shows committed/loose runtime artifacts: `cache.json`, `data.db`, `logs/`, `ixfr-journals/`, `clusters/`, `nothingdns` (23 MB binary). The git status also shows the entire `internal/dashboard/static/dist/assets/*` was **deleted**. **Action:** confirm `.gitignore` covers runtime state and the built binary; decide intentionally whether `dist/` build output is tracked (the deletion suggests a build pipeline change mid-flight — resolve before it bit-rots).

---

## Part B — Cross-cutting concerns

### B1. Logging consistency · Confidence: High
A solid custom structured logger exists (`internal/util/logger.go`, levels DEBUG→FATAL, text/JSON). Most code uses it correctly. **Escapes to fix:**
- `internal/cluster/raft/integration.go:233` — raw `log.Printf("raft: stateMachine.Apply failed...")`.
- `internal/otel/middleware.go:113` — raw `log.Printf("span: ...")`.
- `internal/cluster/raft/raft.go:792, 865` — `fmt.Printf(...)` to stdout for snapshot-restore failures.

**Action:** thread the configured `*util.Logger` into `raft`/`otel` (or accept a minimal `Logger` interface) and replace these. Add a lint rule (`forbidigo`) banning `log.Printf`/`fmt.Printf` outside `cmd/*/main.go` and tests.

### B2. Error handling · Confidence: High
Generally good: `fmt.Errorf` + `%w` dominant, sentinel errors in `internal/transfer/errors.go`, correct `errors.Is` usage at call sites. Beyond the 3 `errorlint` hits (A3), one swallowed parse error to chase down:
- `cmd/nothingdns/authoritative.go` — `glueName, _ = protocol.ParseName(...)` silently drops a parse error in glue handling. **Action:** log at debug and skip the glue record explicitly.

### B3. Context propagation · Confidence: Medium–High (P1)
The DNS hot path creates fresh root contexts instead of inheriting request scope, which **defeats tracing correlation and client-cancellation**:
- `cmd/nothingdns/handler.go:119` — tracing span started from `context.Background()` → orphaned spans.
- `handler.go:555` — recursive resolver `context.WithTimeout(context.Background(), 5s)`.
- `handler.go:696` — DNSSEC validation `ctx := context.Background()`.
- `internal/storage/postgres_zonestore.go:68,115,122,142` — every zone op builds its own `context.Background()` instead of taking a parent `ctx`.

**Action:**
1. Give `integratedHandler.ServeDNS` a single request-scoped `ctx` (derive from a server-level base ctx + per-query deadline) and thread it into resolver, validator, tracer, and storage.
2. Change `postgres_zonestore` methods to accept `ctx context.Context` from callers.
3. This is a prerequisite for the §C1 middleware refactor — do it as part of that.

### B4. Goroutine lifecycle (server layer = good; specific gaps below) · Confidence: Medium
Server transports manage goroutines well (per-round `WaitGroup`, stop channels, `atomic.Pointer` for hot-swapping the rate limiter on reload — a nice pattern). Gaps flagged:
- `cmd/nothingdns/main.go` — server `go func()`s are not tracked by a single `WaitGroup`; `xotServer.AcceptLoop()` reportedly has no stop signal. Verify shutdown actually joins every loop.
- See §C3 for cluster/raft goroutine fan-out (the higher-risk area).

### B5. ⚠️ Dependency policy drift (P1) · Confidence: High
`CLAUDE.md` states deps are *only* `quic-go` + `golang.org/x/*`, "everything else hand-rolled on stdlib," and "no `gopkg.in/yaml`." **Reality:** `go.mod` now requires `github.com/jackc/pgx/v5 v5.7.2` (+ 3 transitive jackc deps), used by `internal/storage/postgres_zonestore.go` and wired in `cmd/nothingdns/zone_manager.go:156`.

This is a legitimate feature (optional Postgres zone backend), but the docs now mislead every contributor and any "minimal deps" review. ✅ **DONE (2026-05-29):** `CLAUDE.md` Dependency Policy updated to document pgx/v5 as an explicitly-approved, runtime-optional backend with a note on the `//go:build postgres` gate option. Original options retained below for reference. **Action (choose one):**
- **(a)** Update `CLAUDE.md` + `Dependency Policy` section to document Postgres as an explicitly-approved, runtime-optional backend; **or**
- **(b)** If the minimal-deps philosophy is load-bearing, move Postgres behind a build tag (`//go:build postgres`) so the default `scratch` binary never links pgx.

Recommendation: **(a)** unless binary size / supply-chain surface is a hard constraint, in which case **(b)**.

### B6. Code duplication (cross-package) · Confidence: Medium
- ✅ **DONE (2026-05-29)** `cmd/dnsctl/helpers.go` — `apiRequest()` and `apiGetRaw()` duplicated URL-scheme validation + auth-header + do/read/status logic. Extracted `buildAPIRequest(method, path, body)` and `doAPIRequest(req)`; both callers now compose them. Tests green.
- ✅ **DONE (2026-05-29)** `cmd/nothingdns/main.go` — the 4 identical transport-serve goroutines (UDP/TCP/TLS/DoQ) now go through a `serveBg(name, serveFn)` closure. (Did *not* add WaitGroup/stop-channel lifecycle tracking — that's the separate B4 concern, noted in a code comment.)
- The big one — REST vs MCP business-logic duplication — is §C4 (still open).

---

## Part C — Subsystem deep-dives

### C1. `cmd/nothingdns/handler.go` — decompose `ServeDNS` (P1) · Confidence: High (smell), Medium (specific line claims)

**Problem:** `integratedHandler.ServeDNS` is a ~767-line method running 21 sequential stages with ~88 interleaved diagnostic calls. Stages cannot be unit-tested in isolation, reordered, or individually disabled. RPZ response-IP/NSDNAME checks are **duplicated 3×** (after CNAME resolution, after recursive resolve, after upstream forward — reported at lines ~494, ~586, ~743).

**Refactor — chain-of-responsibility / middleware:**
```go
type Stage func(ctx context.Context, q *query, w server.ResponseWriter) (handled bool, err error)

// e.g. idnaStage, aclStage, rpzClientStage, rateLimitStage, cookieStage,
//      blocklistStage, cacheStage, viewStage, authoritativeStage,
//      resolverStage, upstreamStage, dnssecStage, rpzResponseStage,
//      dns64Stage, cacheStoreStage, staleStage
type Pipeline struct{ stages []Stage }
func (p *Pipeline) ServeDNS(...) { for _, s := range p.stages { if handled, _ := s(ctx, q, w); handled { return } } }
```
Benefits: each stage ~50–100 LOC and individually testable; ordering becomes data; the 3× RPZ duplication collapses into one `rpzResponseStage` (extract `applyRPZToResponse(...)` helper first as a no-risk intermediate step).

**Progress (2026-05-29):** Two no-risk intermediate steps **DONE** as groundwork for the full pipeline split:
- ✅ Extracted `applyRPZResponsePolicy(w, r, q, resp, label)` — collapsed the 3× duplicated RPZ response-IP + NSDNAME blocks (CNAME / recursive / upstream paths) into one helper. Added `TestApplyRPZResponsePolicy_*`.
- ✅ Extracted package-level `writeResponse(w, msg, context)` — replaced 6 ad-hoc `fmt.Fprintf(os.Stderr, ...)` write-failure sites (now logged via `util.Warnf`) **and** 3 fully-unchecked `w.Write(resp)` calls in `applyRPZRule`. Removed the now-unused `os` import.
- Net effect: `handler.go` 1551 → 1517 LOC, lint still 0. The full stage-pipeline decomposition (below) remains the larger follow-up.

**Companion fixes (verify lines):**
- ✅ ~~Extract a `writeResponse` helper~~ — DONE (see Progress above).
- `wireLen()` (≈ handler.go:936) allocates a 512-byte buffer per call on the RRL path → use a `sync.Pool` or precompute packed length.
- **Zone lookup TOCTOU (Investigate):** zones are read under `zonesMu.RLock()` then handled after unlock (≈443–471); a concurrent SIGHUP reload could swap zone pointers. Confirm whether zone objects are immutable-after-publish (copy-on-write) — if they are, this is a non-issue; if mutated in place, copy refs under lock and/or guard zone content with its own RWMutex.
- CNAME chasing (`chaseCNAMEInZones`) — confirm an explicit max-depth/loop guard exists; add one if not.

### C2. `internal/config` — break the 2679-line monolith (P2) · Confidence: High

**Problems:**
1. `Config` struct has ~30 top-level subsystem fields. Adding a subsystem touches 6 places (struct, defaults, unmarshal, validate, reload callback, docs).
2. **15 near-identical `unmarshalX` functions** (~lines 1319–1766) of `field = getX(node, "key", field)` boilerplate — drift-prone (add a struct field, forget the unmarshaler → silently defaulted).
3. **Defaults live in two places:** `DefaultConfig()` *and* inline `if x == "" { x = ... }` scattered through unmarshalers (e.g. DoHPath, Timeout, Strategy, Level, metrics Bind, ConsensusMode).
4. **12 validators** with inconsistent error message shapes (`server:` vs `server.field` vs `section[i].field`; "must be" vs "cannot be").
5. Hard-coded enum allow-lists duplicated across validators (and again in `internal/dnssec`).

**Refactor:**
- Split `Config` into per-domain structs in per-domain files: `network_config.go`, `resolver_config.go`, `clustering_config.go`, `security_config.go`, `extensions_config.go`. Top-level `Config` becomes a thin container.
- Introduce a `ValidationError{Path, Message, Value, Remediation}` type and a single formatter; convert validators to emit it.
- Centralize enum allow-lists as package-level vars (`ValidUpstreamStrategies`, `ValidDNSSECAlgorithms`, `ValidLogLevels`) and reuse from `dnssec`.
- Consolidate all defaults into `DefaultConfig()` (or per-struct `ApplyDefaults()`); remove inline fallbacks.
- **Optionally** replace the 15 hand unmarshalers with one reflection-driven `unmarshalNode(node, &cfg)` using `yaml:"..."` struct tags — collapses ~300 LOC and makes "unknown key" warnings possible (catches typos like `dons_workers`).

**Custom YAML parser (`parser.go`/`tokenizer.go`) — decide its fate · Confidence: Medium:**
- The tokenizer *emits* `TokenAnchor`/`TokenAlias`/`TokenPipe`/`TokenGreater` but the parser **silently ignores** them → a config using anchors or `|` block scalars parses to *wrong* values with **no error**. **Minimum fix:** make these a hard parse error ("anchors/aliases/multiline not supported") instead of silent data loss.
- The column-based dedent logic in `parseBlockSequence` is the documented fragile spot (single regression test guards it). Consider rewriting to indent-*level* stack tracking (as `parseMapping` already does) for robustness.
- **Strategic question:** is maintaining ~835 LOC of bespoke YAML (no anchors, no multiline, fragile dedent, ~3000 LOC of tests) worth it vs adopting a vetted parser? Given the project already broke the "no third-party YAML" rule by adding pgx, re-evaluate. If keeping it: add a fuzz target (`FuzzParseYAML`).

**Hot reload (`reload.go`) · Confidence: Medium:**
- Reload callbacks take no args and each must re-fetch config → easy to read stale config. Pass `newCfg *Config` into callbacks.
- Reload is not atomic across zones (zone 3 failing leaves zones 1–2 swapped). Load+validate all into a temp state, then swap under one lock. (Mirror in `main.go` SIGHUP handler — guard against overlapping reloads.)

### C3. `internal/cluster` + `raft` — split god-objects, harden concurrency (P2, careful) · Confidence: **Investigate** (HA code — reproduce before changing)

> ⚠️ This is the highest-stakes area. Every item below must be reproduced with a test (ideally `-race` + an in-memory transport) before any change. Do **not** refactor consensus code speculatively.

**Maintainability (safe to do):**
- `gossip.go` (1746) → split into `swim.go` (membership), `election.go`, `encryption.go` (AEAD), `handlers.go` (zone/config/cache messages), `gossip.go` (coordination).
- `raft.go` (1474) → extract per-state handlers behind a small FSM interface; unify `broadcastVoteRequest`/`broadcastHeartbeat`/`replicateToFollowers` fan-out.
- `cluster.go:1027–1034` — `cacheSyncLoop` has a duplicated `consensus == ConsensusRaft` branch (dead/incomplete refactor) — simplify.

**Concurrency hypotheses to verify (treat as bugs only after reproduction):**
- **Unbounded RPC goroutines** (`raft.go` ~913–1149): one goroutine per peer per broadcast with no timeout/cancellation; `sendVoteRequest` can block on `n.voteRespCh` if the buffer (10) fills. Wrap in `context.WithTimeout` tied to `n.ctx`; bound via the response channel select.
- **Lock drop/re-acquire in `replicateToFollowers`** (~1101–1149): reads `currentTerm` under lock, unlocks, then per-peer re-locks; if a snapshot install truncates `n.log` between, `copy(entries, n.log[offset:])` could panic. Build all `AppendRequest`s under a single lock hold, then send lock-free.
- **`applyCommitted` reaches into `node.mu` directly** (`integration.go:216–238`) and calls `stateMachine.Apply` while holding it → lock-ordering risk with the zone SM's own mutex. Snapshot the entries-to-apply under lock, release, then apply.
- **Callbacks invoked under `callbacksMu.RLock()`** (`gossip.go:617–676`): foreign code runs under the lock → deadlock potential. Copy the callback fn pointer, release, then call.
- **Election goroutine fan-out** (`gossip.go:~1245`): `go startElection()` per detector tick with no in-flight guard → can stack. Add a `TryLock` single-flight guard.
- **AEAD nonce generation** (`gossip.go:~1731`): confirm `io.ReadFull(rand.Reader, nonce)` error is checked and the message is *not* sent on failure (nonce reuse in GCM is catastrophic). If unchecked, fix immediately — this one graduates to **P0/D**.
- **`persistHardStateLocked` panics on save failure** (`raft.go:389–402`): a transient disk error crashes the whole DNS server. Consider logging + leader step-down instead of `panic`, so query serving survives.

**Testability:**
- `Transport` interface has only a TCP impl. Add an `InMemoryTransport` so Raft can be unit-tested under `-race` without sockets. This is the single highest-leverage investment for safely doing everything else in this section.

### C4. `internal/api` — extract a service layer, tame routing (P2) · Confidence: High

**Biggest win — kill REST/MCP duplication (~400 LOC):** `internal/api/mcp/tools.go` reimplements zone/record/cache operations that already exist in the REST handlers (`callZoneCreate` vs `handleCreateZone`, `callRecordAdd` vs `handleAddRecord`, `callCacheFlush` vs `handleCacheFlush`, …). Extract a transport-agnostic **service layer** (`ZoneService`, `CacheService`, …) taking `(ctx, user, input)` and returning `(output, error)`; have both REST and MCP call it. Single source of truth for validation + business rules; also enables future gRPC.

**Handler boilerplate (repeated 40–50×):**
- Method-dispatch (`if r.Method != ... { 405 }`) → a `RegisterRoute(path, map[method]handler)` helper.
- JSON decode + body-limit + 400 → a generic `s.decode(w, r, &req) bool` helper (also standardizes `http.MaxBytesReader` everywhere — security win).
- Auth gates (`requireOperator`/`requireAdmin`) applied both at handler entry *and* inside sub-branches → wrap at registration: `s.WithOperator(handler)`.

**Routing & middleware (`server.go`):**
- 90+ manual `mux.HandleFunc` + prefix routes that hand-parse subpaths (`handleZoneActions` does `strings.SplitN`). Introduce a small route-builder grouping related routes.
- Middleware order is fixed inline (`securityHeaders(cors(auth(mux)))`) with **no request logging** and **rate-limiting buried inside authMiddleware** (so unauthenticated paths like `/health` skip rate limiting). Build an explicit middleware stack; move rate-limit to its own layer *before* auth; add a logging middleware. Make middleware error bodies use `writeJSON`, not raw `http.Error`.

**API ↔ core coupling:**
- Handlers reach into `zone.Zone` internals and manage its `RWMutex` themselves (`api_zones.go:50–59`), and round-trip config through JSON to redact fields (`api_config.go:91–137`). Introduce API DTOs (`PublicZoneInfo`, `PublicConfig`) and let managers expose read methods that handle their own locking.

**Security to verify (see also §D):** CSRF posture (relies on SameSite + safe-method cookie gating, no synchronizer token); `sanitizeError`'s `/`-contains heuristic is crude. OpenAPI (`openapi.go`, 702 LOC) is hand-maintained and already drifting (endpoints like `/zones/{name}/ptr-bulk`, `/config/cache` missing) — consider generating it from handler metadata.

### C5. `protocol` / `dnssec` / `resolver` / `cache` — incremental polish (P3)

**`protocol/types.go` (1721) · Confidence: Medium:**
- Split per RData category (`types_address.go`, `types_pointer.go`, `types_text.go`, `types_dnssec.go`, `types_svc.go`).
- **Allocation bounds (Investigate, DoS):** variable-length unpacks (e.g. `RDataZONEMD.Unpack` ~1685, `RDataCERT` ~1038) `make([]byte, n)` from wire-derived lengths. `rdlength` is uint16-bounded (≤65535) so per-record exposure is capped, but add explicit per-field sanity caps + clear errors anyway.
- Compression-pointer loop protection (`labels.go` `UnpackName`, `MaxPointerDepth=5`) looks correct — just add a clarifying comment on the `ptrOffset`-set-once logic.

**`dnssec/validator.go` (1422) · Confidence: Medium:**
- **Duplicate canonical name encoder:** `crypto.go:528 toWireFormat()` reimplements `protocol.CanonicalWireName()`, which CLAUDE.md explicitly forbids ("do not create new ones"). Divergence risk in NSEC3 hashing. Replace `toWireFormat` with a thin wrapper over `CanonicalWireName` (+ label-length validation if needed). **High confidence this should change.**
- **Fail-closed review (Investigate):** when `RequireDNSSEC=false`, a missing RRSIG path may treat unsigned RRsets as Insecure without an authenticated-denial (NSEC/NSEC3) proof (`validator.go:~430`). Confirm against RFC 4035 §4.3 intent for this server's threat model; if signatures can be stripped and silently accepted, tighten.
- Extract `validateMessage`/`buildChain` sub-steps; enumerate unsupported algorithms (e.g. Ed448/16) with explicit "not implemented" errors instead of a generic default.

**`resolver/resolver.go` (1099) · Confidence: Medium (note: agent self-corrected several claims):**
- TxID uses `crypto/rand` ✅. **Source-port randomization (Investigate):** verify the UDP transport binds randomized ephemeral source ports rather than relying on default kernel behavior; if connections are long-lived/reused, ensure per-query unpredictability. *(The surveying agent initially flagged this then noted it's delegated to the transport — confirm what the transport actually does before acting.)*
- Bailiwick/glue checks (`extractDelegation`) appeared **correct** on the agent's closer read — just add an explicit test (`TestExtractDelegation_GlueForUnlistedNS`) to lock the behavior.
- Per-delegation timeout granularity: the single `config.Timeout` covers the whole resolution; a slow shallow delegation can starve deeper ones. Consider per-hop deadlines.
- `resolveNSAddresses` goroutines key off the parent `ctx` but won't exit until in-flight inner calls return; add a `done` channel for prompt cancellation.

**`cache/cache.go` (997) · Confidence: Medium:**
- Sound design (sharded, intrusive LRU, `maphash` with per-process seed for long-name keys, prefetch now wired). Polish items:
  - Stale TTL hard-coded to 30s (`~433`) — make configurable per RFC 8767.
  - Negative-TTL clamping to min/max happens silently — optional debug log when clamped.
  - Shard count fixed at 16 — make configurable for very-large/very-small core counts.
  - Document `SetPrefetchFunc` reentrancy contract (callback must not re-enter cache synchronously).
  - Verify the `sync.Pool` "copy before `defer Put`" rule (CLAUDE.md gotcha) holds at every buffer-pool site.

---

## Part D — Security & correctness (prioritize verification, P0)

These are pulled out because the cost of being wrong is high. **Each is a hypothesis until reproduced.**

| ID | Item | Location | Confidence | Action / Outcome |
|---|---|---|---|---|
| D1 | ~~AEAD nonce generation may not check `rand.Read` error~~ | `cluster/gossip.go:1588,1732` | ✅ **DISPROVEN** | Error *is* checked and returns without sending in both `encrypt` and `encryptWithAAD`. No fix needed. (Verified 2026-05-29) |
| D2 | Raft panics on HardState persist failure → full crash | `cluster/raft/raft.go:389–402` | ✅ **INTENTIONAL — keep** | Documented Raft-safety fail-fast: a node that thinks it persisted its vote/term but didn't can double-vote across restart (split-brain). Panicking is *safer* than continuing; do **not** change to "keep serving." Recovery = supervisor restart. (Reviewed 2026-05-29) |
| D3 | Unbounded/timeout-less Raft RPC goroutines | `cluster/raft/raft.go:~913–1149` | Investigate | Add ctx timeout; reproduce leak under partition |
| D4 | Lock drop/re-acquire vs snapshot truncation → possible panic | `cluster/raft/raft.go:~1101` | Investigate | Build requests under single lock hold |
| D5 | DNSSEC "fail-open" when `RequireDNSSEC=false` & RRSIG missing | `dnssec/validator.go:429–451` | ✅ **INTENTIONAL — design decision, flagged for review** | Verified: with `RequireDNSSEC=false` (default) a missing RRSIG `continue`s and the message can return `ValidationSecure`; **strict mode (`RequireDNSSEC=true`) correctly returns Bogus.** This is *explicitly tested & documented* (`validator_test.go:1271` asserts "SECURE with RequireDNSSEC=false"). `buildChain` is rigorous (empty DS requires an authenticated NSEC/NSEC3 denial proof — downgrade guard at validator.go:271). **Minor residual caveat (owner's call, not patched):** per RFC 4035 §3.2.3, AD=1 should require *all* answer/authority RRsets authenticated; in permissive mode AD=1 (handler.go:655) can be set on a response containing an unsigned answer RRset. If stricter AD semantics are desired, return `ValidationInsecure` (not Secure) when *any* answer RRset lacks a valid RRSIG — but this changes documented behavior and breaks `validator_test.go:1271`, so it needs an explicit decision. (Verified 2026-05-29) |
| D6 | Source-port randomization for upstream/recursive UDP | `resolver` transport | Investigate | Verify kernel vs explicit randomization |
| D7 | `authStore.DeleteUser` error ignored in auth path | `api/api_auth.go:170` | ✅ **FIXED** | Error now handled (returns 409). (Part A, 2026-05-29) |
| D8 | CSRF relies on SameSite only; no synchronizer token | `api/server.go:~920` | Medium | Add double-submit/synchronizer token for state-changing verbs |
| D9 | Duplicate canonical name encoder (NSEC3 divergence) | `dnssec/crypto.go:531` | ✅ **FIXED** | `toWireFormat` now delegates encoding to `protocol.CanonicalWireName` (keeps label-length guard). NSEC3 tests green. (2026-05-29) |
| D10 | Protocol unpack allocation caps | `protocol/types.go` | ✅ **MOSTLY DISPROVEN + hardened** | Verified: the record-level unpacker (`record.go:165`) checks `offset+rdlength > len(buf)` and returns `ErrBufferTooSmall` **before** dispatching to any `RData.Unpack`. So every wire-length allocation is bounded by `rdlength` (uint16 ≤65535) *and* the bytes are guaranteed present — no unbounded-alloc / OOB-slice DoS via the message path. SSHFP/TLSA/SVCB also re-check internally. **Hardening applied:** added the matching `endOffset > len(buf)` guard to `RDataZONEMD.Unpack` (the lone allocator that lacked it — latent panic only if `Unpack` is called directly, bypassing record.go). (Verified + fixed 2026-05-29) |

**Verification pass results (2026-05-29):** Of the items triaged so far — **D1 false positive** (code already correct), **D2 intentional safety design** (kept), **D5 intentional & tested design** (kept, minor RFC-strictness caveat flagged for owner), **D7 fixed**, **D9 real & fixed**. So of the "Investigate"/correctness hypotheses examined, only D9 was a genuine defect; D1/D2/D5 were correct/intended. **D10 mostly disproven** (caller already bounds-checks rdlength against the buffer) — added one defensive guard to ZONEMD for parity. So across the deep-dive correctness items examined (D1, D2, D5, D10), **only D9 was a genuine defect**; the rest were already-correct, intentional, or caller-mitigated. This hit rate is exactly why the doc tags everything as a hypothesis — **confirm before changing**, especially security/consensus code. Remaining open: D3, D4 (need Raft `InMemoryTransport` + `-race`), D6 (resolver source-port), D8 (CSRF token).

**Recommended approach for D1–D6:** spin up the `-race` detector (CLAUDE.md notes it's gated on a CGO host — arrange one), add an in-memory Raft transport (§C3), and write targeted reproduction tests. Disprove or confirm each before touching consensus code.

---

## Part E — Testing & tooling

### Coverage gaps (Confidence: Medium — ratios are file-count proxies, run real `-cover`)
Lowest-coverage critical packages reported:
- `internal/api` (~45%) — auth/RBAC flows under-tested.
- `internal/protocol` (~48%) — wire parsing edge cases.
- `internal/resolver` (~45%) — fallback/error paths.

**Action:** run `go test ./... -coverprofile` for real numbers; prioritize API auth paths, protocol fuzzing, and resolver error/timeout branches.

### Flaky-test signals (Confidence: Medium)
`time.Sleep`-based synchronization in:
- `internal/server/tcp_test.go`, `internal/server/coverage_test.go`
- `internal/api/handler_test.go` (health-check waits)

**Action:** replace sleeps with channels/`WaitGroup`/polling-with-deadline.

### Fuzzing
Fuzz tests exist (`dnscookie`, `cache`). **Add** fuzz targets for the two highest-risk untrusted-input parsers: `protocol` wire decode and the custom YAML parser.

### CI gates to add
1. `gofmt -l` must be empty (after A1).
2. `golangci-lint run` must be clean (after A1–A3).
3. `go test -race ./...` on a CGO-enabled runner (currently gated off — unblock it; race coverage is the single biggest safety net for §C3/§D).

---

## Part F — Phased roadmap

### Phase 0 — Hygiene (0.5–1 day) · no behavior change
- A1 gofmt, A2 errcheck, A3 errorlint, A4 dead fields, A5 repo artifacts.
- B5(a) doc fix for pgx, or open a decision issue for B5(b).
- Add CI gates: gofmt + golangci-lint clean.

### Phase 1 — Safety net + truth (3–5 days)
- Unblock `go test -race` on a CGO runner.
- Add `InMemoryTransport` for Raft (§C3 testability).
- Reproduce/triage D1–D6; fix any confirmed (D1, D2, D9 are the likely-real, low-controversy ones).
- B3 context propagation groundwork.

### Phase 2 — Highest-leverage structure (1–2 weeks)
- C1 `ServeDNS` → middleware pipeline (start by extracting the 3× RPZ helper + `writeResponse`, then the stages).
- C4 API service layer (collapse REST/MCP duplication) + decode/auth helpers.

### Phase 3 — Monolith decomposition (1–2 weeks)
- C2 `config.go` split + ValidationError + centralized defaults/enums; harden the YAML parser (fail loudly on anchors/multiline) or replace it.
- C5 `protocol/types.go` split; D9/D10 follow-through.

### Phase 4 — Consensus hardening (carefully, 1–2 weeks)
- C3 gossip/raft file splits (safe), then the verified concurrency fixes (D3, D4, callbacks-under-lock, election single-flight) — each behind a reproduction test under `-race`.

### Phase 5 — Polish (ongoing)
- C5 cache/resolver config knobs and cancellation; E test coverage + flake removal; OpenAPI generation; logging escapes (B1).

---

## Appendix — File → primary recommendation index

| File | Section | One-liner |
|---|---|---|
| `cmd/nothingdns/handler.go` | C1 | Decompose `ServeDNS` into a stage pipeline; fix RPZ 3× dup, `wireLen` alloc, contexts |
| `cmd/nothingdns/main.go` | B4, C2, F | Track goroutines in one WG; extract transport-start; atomic+guarded reload |
| `cmd/nothingdns/zone_manager.go` | A3, B5 | `%w`; Postgres wiring is the policy-drift entry point |
| `internal/config/config.go` | C2 | Split by domain; ValidationError; centralize defaults/enums; reflection unmarshal |
| `internal/config/parser.go` | C2 | Fail loudly on anchors/multiline; rewrite column dedent; fuzz |
| `internal/cluster/gossip.go` | C3, D1 | Split god-object; verify AEAD nonce; callbacks-under-lock; election single-flight |
| `internal/cluster/raft/raft.go` | C3, D2–D4 | FSM extract; bounded RPC goroutines; lock-hold for replication; no panic-on-persist |
| `internal/cluster/raft/integration.go` | B1, C3 | Use logger not `log.Printf`; snapshot entries before `Apply` |
| `internal/api/server.go` | C4, D8 | Route-builder + explicit middleware stack; CSRF token |
| `internal/api/api_zones.go` | C4 | Move logic to ZoneService; DTOs; decode helper |
| `internal/api/mcp/tools.go` | C4 | Call shared service layer (kill ~400 LOC dup) |
| `internal/api/api_auth.go` | A2, D7 | Handle `DeleteUser` error |
| `internal/api/openapi.go` | C4 | Generate from handlers to stop drift |
| `internal/protocol/types.go` | C5, D10 | Split by category; allocation caps |
| `internal/dnssec/validator.go` | C5, D5, D9 | Use `CanonicalWireName`; fail-closed review; extract long methods |
| `internal/resolver/resolver.go` | C5, D6 | Verify source-port randomization; per-hop timeout; goroutine cancel |
| `internal/cache/cache.go` | C5 | Configurable stale TTL/shards; document prefetch reentrancy |
| `internal/otel/middleware.go` | B1 | Use configured logger |
| `cmd/dnsctl/helpers.go` | B6 | Dedup `apiRequest`/`apiGetRaw` URL validation |

---

*Generated from a structural survey + static checks (`go vet`, `golangci-lint`, `gofmt`). Correctness/concurrency items in Parts C–D are hypotheses to verify with reproduction tests before code changes — especially anything touching `internal/cluster`.*
