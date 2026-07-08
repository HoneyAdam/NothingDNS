# NothingDNS — Refactoring & Improvement Plan

> **Status:** Updated 2026-06-15 — see "Session 2026-06-15" section at bottom for latest completed work.
> **Original analysis snapshot:** 2026-05-29
> **Scope:** Whole repository (Go server + CLI + React web dashboard)
> **Baseline health:** `go build` ✅ · `go vet ./...` ✅ · `golangci-lint` ⚠️ (14 issues) · `gofmt` ✅ (0 files) · no `TODO/FIXME` in source
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
| **P0** | ~~Verify security/correctness hypotheses~~ | §D1–D6 | 2–4 d | ✅ DONE (2026-05-29) |
| **P0** | ~~Quick wins~~ | §A1–A4 | 0.5 d | ✅ DONE (2026-05-29) |
| **P1** | ~~Doc/dependency truth~~ | §B5 | 0.5 d | ✅ DONE (2026-05-29) |
| **P1** | ~~Context propagation~~ | §B3 | 1–2 d | ✅ DONE (2026-05-29) |
| **P1** | ~~`ServeDNS` decomposition~~ | §C1 | 3–5 d | ✅ DONE (2026-06-15) — full 20-stage pipeline |
| **P2** | ~~`config.go` decomposition~~ | §C2 | 3–5 d | ✅ DONE (prior session) — split into 20 files |
| **P2** | ~~API service-layer + helpers~~ | §C4 | 3–5 d | ✅ DONE (2026-06-15) — `requireMethod`, `decode`, DTO extraction |
| **P2** | ~~Cluster god-object split~~ | §C3 | 1–2 wk | ✅ DONE (2026-06-15) — gossip→6 files, raft→5 files |
| **P2** | ~~Reload unification + guard~~ | §C1/main | 0.5–1 d | ✅ DONE (2026-06-15) |
| **P3** | Protocol/cache/resolver polish | §C5 | ongoing | Incremental, low-risk |
| **P3** | Test coverage + flake removal | §E | ongoing | Raises confidence for all the above |

---

## Part A — Quick wins (do first, low risk)

### A1. ~~Fix `gofmt`~~ — ✅ DONE (2026-05-29) · Confidence: High
`gofmt -l` returns 0 files. CI gate recommended: `gofmt -l .` must be empty. The 8 test files listed previously were already formatted; the only remaining production-file fix was `internal/metrics/metrics.go` (struct field alignment).

### A2. ~~Fix `errcheck`~~ — ✅ DONE (2026-05-29) · Confidence: High
- `cmd/dnsctl/zone.go:107` — was already fixed in a prior session (`%w` on write error).
- `internal/api/api_auth.go:170` — `s.authStore.DeleteUser("admin")` error now captured; on failure the handler returns `500` with `sanitizeError` message. Auth path no longer silently assumes success.

### A3. ~~Fix `errorlint`~~ — ✅ DONE (2026-05-29) · Confidence: High
- `cmd/nothingdns/zone_manager.go:117` — `%v` → `%w` for `decErr` (line shifted from 131 due to prior refactors).
- `internal/config/config.go:1894` — `%v` → `%w` for hex parse error (line shifted from 1938).
- `internal/transfer/ddns.go:414` — was already correct; only 2 errorlint hits remained, both fixed above.

### A4. ~~Remove dead fields~~ — WITHDRAWN (false positive) · Confidence: High
- `cmd/nothingdns/handler.go:84–85` (`notifyOnce`/`updateOnce`) were flagged as unused but are **in use** at `cmd/nothingdns/transfer.go:306` and `:399` (`h.notifyOnce.Do(...)` / `h.updateOnce.Do(...)`). **Do not remove.** (Verified 2026-05-29.)

### A5. ~~Stray repo artifacts~~ — ✅ DONE (2026-05-29) · Confidence: High
Verified `.gitignore` covers all runtime artifacts: `cache.json` (line 95), `*.db` (line 63 → covers `data.db`), `logs/` (line 46), `ixfr-journals/` (line 98), `/nothingdns` binary (line 26), `/cmd/nothingdns/nothingdns` (line 28). Added `clusters/` directory to `.gitignore` explicitly (not previously listed). All runtime state is now intentionally ignored.

---

## Part B — Cross-cutting concerns

### B1. Logging consistency · Confidence: High · ✅ **DONE (2026-05-29)**
A solid custom structured logger exists (`internal/util/logger.go`, levels DEBUG→FATAL, text/JSON). Most code uses it correctly. Fixed the 4 raw `log.Printf`/`fmt.Printf` escapes:

- `internal/cluster/raft/integration.go` — added `logger *util.Logger` field to `ClusterIntegration`; `log.Printf` → `ci.logger.Errorf`
- `internal/otel/middleware.go` — `LogSpans` now uses `util.Debugf` instead of raw `log.Printf`
- `internal/cluster/raft/raft.go` (2 sites) — both snapshot-restore `fmt.Printf` → `util.Errorf`

**Trade-offs:** `raft.go`'s `Node` struct remains logger-free (no `util` field), which is correct — errors there are propagated up to integration layer callers that hold the logger. The `util.Errorf` stand-in in raft.go is a pragmatic intermediate step; the B1 lint rule (`forbidigo`) remains as future work.

### B2. Error handling · Confidence: High
Generally good: `fmt.Errorf` + `%w` dominant, sentinel errors in `internal/transfer/errors.go`, correct `errors.Is` usage at call sites. Beyond the 3 `errorlint` hits (A3), one swallowed parse error to chase down:
- `cmd/nothingdns/authoritative.go` — `glueName, _ = protocol.ParseName(...)` silently drops a parse error in glue handling. **Action:** log at debug and skip the glue record explicitly.

### B3. Context propagation · Confidence: Medium–High (P1) · ✅ **DONE (2026-05-29)**
The DNS hot path was creating fresh root contexts instead of inheriting request scope, which **defeated tracing correlation and client-cancellation**.

**Implemented changes:**
1. `cmd/nothingdns/handler.go`: `serverCtx` + `cancelServer` fields added to `integratedHandler`; `ServeDNS` derives a per-request `reqCtx` from `serverCtx` with `context.WithCancel`, so every query is a descendant of the server-scoped context. Graceful shutdown now calls `cancelServer()` before stopping transports — in-flight queries see deadline propagation instead of orphaned Background() goroutines.
2. `internal/resolver`/`internal/storage`: **No changes needed here** — `resolver.go` already derives from its `ctx` parameter; `internal/storage/zonestore.go` has no `context.Background()` creations (the refactor.md cited a `postgres_zonestore.go` path that does not exist — caller-supplied `ctx` is used throughout).

**Trade-off accepted:** tests that call `ServeDNS` directly (not through `main.go`) get `serverCtx == nil`; the code guards this with a nil check and falls back to `context.Background()` for the per-request ctx. This is the correct behavior — test code doesn't go through the server lifecycle, so it shouldn't participate in server-level cancellation.


### B4. Goroutine lifecycle · Confidence: Medium · ✅ **DONE (2026-05-29)**
Fixed: `internal/transfer/xot.go` (`XoTServer`) **AcceptLoop goroutine leak confirmed and fixed.** After `Close()` closed the listener, `Accept()` kept returning errors and the loop `continue`d forever — goroutine never exited. Fix: `stopCh` closed in `Close()` before `wg.Wait()`; `AcceptLoop` exits via `select { case <-s.stopCh: return }` on error path; each connection goroutine also registered in `wg`; `if s.stopCh != nil` guard for tests that construct `XoTServer` directly. C3 (cluster/raft goroutine fan-out) remains open.

### B5. ⚠️ Dependency policy drift (P1) · Confidence: High
`CLAUDE.md` states deps are *only* `quic-go` + `golang.org/x/*`, "everything else hand-rolled on stdlib," and "no `gopkg.in/yaml`." **Reality:** `go.mod` now requires `github.com/jackc/pgx/v5 v5.7.2` (+ 3 transitive jackc deps), used by `internal/storage/postgres_zonestore.go` and wired in `cmd/nothingdns/zone_manager.go:156`.

This is a legitimate feature (optional Postgres zone backend), but the docs now mislead every contributor and any "minimal deps" review. ✅ **DONE (2026-05-29):** `CLAUDE.md` Dependency Policy updated to document pgx/v5 as an explicitly-approved, runtime-optional backend with a note on the `//go:build postgres` gate option. Original options retained below for reference. **Action (choose one):**
- **(a)** Update `CLAUDE.md` + `Dependency Policy` section to document Postgres as an explicitly-approved, runtime-optional backend; **or**
- **(b)** If the minimal-deps philosophy is load-bearing, move Postgres behind a build tag (`//go:build postgres`) so the default `scratch` binary never links pgx.

Recommendation: **(a)** unless binary size / supply-chain surface is a hard constraint, in which case **(b)**.

### B6. Code duplication (cross-package) · Confidence: Medium
- ✅ **DONE (2026-05-29)** `cmd/dnsctl/helpers.go` — `apiRequest()` and `apiGetRaw()` duplicated URL-scheme validation + auth-header + do/read/status logic. Extracted `buildAPIRequest(method, path, body)` and `doAPIRequest(req)`; both callers now compose them. Tests green.
- ✅ **DONE (2026-05-29)** `cmd/nothingdns/main.go` — the 4 identical transport-serve goroutines (UDP/TCP/TLS/DoQ) now go through a `serveBg(name, serveFn)` closure. (Did *not* add WaitGroup/stop-channel lifecycle tracking — that's the separate B4 concern, noted in a code comment.)
- ~~The big one — REST vs MCP business-logic duplication — is §C4.~~ Moot: the MCP server has been removed from the codebase; only the REST-side service extraction in §C4 remains open.

---

## Part C — Subsystem deep-dives

### C1. `cmd/nothingdns/handler.go` — decompose `ServeDNS` (P1) · ✅ **DONE (2026-06-15)** · Confidence: High

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
- ✅ ~~`wireLen()` allocates 512-byte buffer per RRL call~~ — DONE (2026-05-29). `protocol.Message` already has a `WireLength()` method that computes wire length without allocation. Replaced `wireLen(r)` → `r.WireLength()` and `wireLen(resp)` → `resp.WireLength()`; removed the redundant helper function.
- ✅ ~~CNAME chasing loop guard~~ — DONE. `chaseCNAMEInZones` (`authoritative.go:369`) already has `maxCNAMEDepth = 16` constant and a `visited` map for loop detection.
- **Zone lookup TOCTOU (Investigate — real concern):** `ServeDNS` reads `handler.zones` under `zonesMu.RLock()` (handler.go:398–411), then dereferences zone pointers *after* releasing the lock. The reload path (`main.go:468–470`) replaces zone objects in the same map under `zonesMu.Lock()`. Individual `zone.Zone` objects have their own `mu sync.RWMutex` (zone.go:60) and `handleListZones` uses `z.RLock()` when reading zone content. The practical blast radius is low (max one stale-zone-answer before GC), but the correct fix is either (a) copy zone pointer references under the read lock before releasing or (b) make zone objects immutable after publish. Mark as TODO for C1 additional hardening.

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
- ✅ Reload callbacks now receive `*Config` (DONE 2026-06-15): `ReloadCallback` changed to `func(*Config) error`; `ReloadHandler.reloadFromPath` loads/validates config before dispatching to callbacks.
- Reload is not atomic across zones (zone 3 failing leaves zones 1–2 swapped). Load+validate all into a temp state, then swap under one lock. (Mirror in `main.go` SIGHUP handler — guard against overlapping reloads.)

### C3. `internal/cluster` + `raft` — split god-objects, harden concurrency (P2, careful) · Confidence: **Investigate** (HA code — reproduce before changing) · ✅ **File splits DONE (2026-06-15)**

> ⚠️ This is the highest-stakes area. Every concurrency item below must be reproduced with a test (ideally `-race` + an in-memory transport) before any change. Do **not** refactor consensus code speculatively.

**Maintainability (✅ DONE 2026-06-15):**
- ✅ `gossip.go` (1800) → split into `gossip_types.go` (260), `gossip_encryption.go` (68), `gossip_swim.go` (379), `gossip_election.go` (382), `gossip_handlers.go` (607), `gossip.go` (160 core). Zero behavior change — pure code movement.
- ✅ `raft.go` (1920) → split into `types.go` (386), `state.go` (626), `handlers.go` (478), `replication.go` (236), `membership.go` (239), `raft.go` (17 doc anchor). Pre-existing `rpc.go` preserved.
- `cluster.go:1027–1034` — `cacheSyncLoop` has a duplicated `consensus == ConsensusRaft` branch (dead/incomplete refactor) — simplify. **Remaining.**

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

### C4. `internal/api` — extract a service layer, tame routing (P2) · ✅ **Helpers DONE (2026-06-15)** · Confidence: High

**Progress (2026-05-29):** `ZoneService` created (`internal/api/zone_service.go`) — `ListZones()` and `GetZone()` methods now extract the business logic from REST handlers into a single, testable service type. `handleListZones` and `handleGetZone` now delegate to it. *(Update: the MCP server has since been removed from the codebase, so the MCP-handler wiring and the MCP raw-zone-object exposure previously tracked here are moot.)*

**Progress (2026-06-15):**
- ✅ Added `requireMethod(w, r, methods...)` helper — replaces 19× repeated 3-line method-dispatch blocks.
- ✅ Added `decode(w, r, &dst)` helper — replaces 17× repeated JSON decode + `MaxBytesReader` + error-response blocks. Standardizes body-limit enforcement everywhere (security win).
- ✅ Applied across 10 handler files (`api_cache.go`, `api_blocklist.go`, `api_rpz.go`, `api_upstreams.go`, `api_acl.go`, `api_cluster.go`, `api_zones.go`, `api_config.go`, `api_auth.go`, `api_dnssec.go`). 7 files no longer need `encoding/json` import.
- ✅ API ↔ core coupling: extracted `Zone.GetDefaultTTL()`, `Zone.GetOrigin()`, `Zone.RecordsByType()` — API handlers no longer manage the zone's `RWMutex` or iterate its internal `Records` map. Deleted the API-side `bulkPTRRecordsOfTypeLocked` helper.

**Remaining:**
- `WithOperator`/`WithAdmin` middleware wrappers at registration (instead of handler entry).
- `CacheService`, `BlocklistService` extraction (partially done — stubs exist).
- Route-builder for the remaining 26 complex multi-path handlers.
- OpenAPI generation from handler metadata (§C4 openapi drift).

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
| D3 | ~~Unbounded/timeout-less Raft RPC goroutines~~ | `cluster/raft/raft.go:~913–1155` | ✅ **FIXED** | Added `raftRPCTimeout = 5s` constant; `Transport` interface updated to accept `context.Context`; `TCPTransport` applies `conn.SetDeadline` from ctx; `sendVoteRequest`/`sendAppendRequest` wrap calls in `context.WithTimeout`. Response channels use `select` + `default` to avoid blocking when the Raft loop is slow. `InMemoryTransport` added for race-detector testing; `TestInMemoryTransport_Timeout` verifies deadline is respected. (Fixed 2026-05-29) |
| D4 | ~~Lock drop/re-acquire vs snapshot truncation → possible panic~~ | `cluster/raft/raft.go:~1080–1120` | ✅ **FIXED** | `replicateToFollowers` goroutines now read `nextIndex`, `n.log[offset:]`, `prevLogIndex`, and `prevLogTerm` under a **single** lock hold, then build the `AppendRequest` before releasing. Previously the lock was dropped between reading `nextIndex` and reading `n.log`, creating a window where a concurrent snapshot-install could truncate the log and cause a panic in `copy(entries, n.log[offset:])`. (Fixed 2026-05-29) |
| D5 | DNSSEC "fail-open" when `RequireDNSSEC=false` & RRSIG missing | `dnssec/validator.go:429–451` | ✅ **INTENTIONAL — design decision, flagged for review** | Verified: with `RequireDNSSEC=false` (default) a missing RRSIG `continue`s and the message can return `ValidationSecure`; **strict mode (`RequireDNSSEC=true`) correctly returns Bogus.** This is *explicitly tested & documented* (`validator_test.go:1271` asserts "SECURE with RequireDNSSEC=false"). `buildChain` is rigorous (empty DS requires an authenticated NSEC/NSEC3 denial proof — downgrade guard at validator.go:271). **Minor residual caveat (owner's call, not patched):** per RFC 4035 §3.2.3, AD=1 should require *all* answer/authority RRsets authenticated; in permissive mode AD=1 (handler.go:655) can be set on a response containing an unsigned answer RRset. If stricter AD semantics are desired, return `ValidationInsecure` (not Secure) when *any* answer RRset lacks a valid RRSIG — but this changes documented behavior and breaks `validator_test.go:1271`, so it needs an explicit decision. (Verified 2026-05-29) |
| D6 | ~~Source-port randomization for upstream/recursive UDP~~ | `resolver/resolver.go:952–964` | ✅ **NOT AN ISSUE** | `StdioTransport.queryUDP` calls `net.DialTimeout("udp", addr)` per-query — each call creates a fresh socket with a kernel-assigned ephemeral source port. No persistent UDP connection is reused across queries. Transaction IDs are generated with `crypto/rand` (`nextSecureID()`) which is cryptographically random. The OS ephemeral port range on Linux (32768–60999) provides adequate unpredictability for this use case. (Investigated 2026-05-29) |
| D7 | `authStore.DeleteUser` error ignored in auth path | `api/api_auth.go:170` | ✅ **FIXED** | Error now handled (returns 409). (Part A, 2026-05-29) |
| D8 | CSRF relies on SameSite only; no synchronizer token | `api/server.go:~920` | Medium | Add double-submit/synchronizer token for state-changing verbs |
| D9 | Duplicate canonical name encoder (NSEC3 divergence) | `dnssec/crypto.go:531` | ✅ **FIXED** | `toWireFormat` now delegates encoding to `protocol.CanonicalWireName` (keeps label-length guard). NSEC3 tests green. (2026-05-29) |
| D10 | Protocol unpack allocation caps | `protocol/types.go` | ✅ **MOSTLY DISPROVEN + hardened** | Verified: the record-level unpacker (`record.go:165`) checks `offset+rdlength > len(buf)` and returns `ErrBufferTooSmall` **before** dispatching to any `RData.Unpack`. So every wire-length allocation is bounded by `rdlength` (uint16 ≤65535) *and* the bytes are guaranteed present — no unbounded-alloc / OOB-slice DoS via the message path. SSHFP/TLSA/SVCB also re-check internally. **Hardening applied:** added the matching `endOffset > len(buf)` guard to `RDataZONEMD.Unpack` (the lone allocator that lacked it — latent panic only if `Unpack` is called directly, bypassing record.go). (Verified + fixed 2026-05-29) |

**Verification pass results (2026-05-29):** Of the 10 hypotheses examined — D1 false positive, D2/D5 intentional, D3/D4/D7/D9 real fixes, D6 not an issue, D10 mostly disproven. **Only D8 remains** (CSRF synchronizer token, medium effort).

**InMemoryTransport added (2026-05-29):** `InMemoryHub` + `InMemoryTransport` in `rpc.go` enables fully in-memory multi-node Raft testing with the race detector. `TestInMemoryTransport_Timeout` confirms context deadlines are respected.

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
- [x] B3 context propagation groundwork — ✅ DONE (2026-05-29): `serverCtx` threaded into `integratedHandler`; `ServeDNS` derives per-request `reqCtx` from it; graceful shutdown cancels in-flight query trees before stopping transports.
- [x] InMemoryTransport for Raft — ✅ DONE (2026-05-29): `InMemoryHub` + `InMemoryTransport` in `rpc.go` enables fully in-memory multi-node Raft testing under race detector. `TestInMemoryTransport_Timeout` verifies context deadlines are respected.
- [x] D1–D6 triage — ✅ DONE (2026-05-29): All 10 D-items resolved. D3/D4 real fixes, D6 not an issue, D7/D9 fixed, D10 hardened. Remaining open: D8 (CSRF token — low priority given SameSite=StrictMode).
- [ ] Unblock `go test -race` on a CGO runner (CI infrastructure item).

### Phase 2 — Highest-leverage structure (1–2 weeks) · ✅ **DONE (2026-06-15)**
- [x] C1 `ServeDNS` → middleware pipeline — ✅ DONE: full 20-stage pipeline in `pipeline.go` + `pipeline_stages.go`. Each stage individually testable; RPZ 3× dup collapsed.
- [x] C4 API service layer + decode/auth helpers — ✅ DONE: `requireMethod` (19 sites), `decode` (17 sites), `ZoneService`, zone DTO methods.
- [x] Reload unification + mutex guard — ✅ DONE: single `reloadAllComponents()` closure guarded by `sync.Mutex`; API + SIGHUP both delegate.
- [x] Transport lifecycle extraction — ✅ DONE: `transports.go` with `startServers()` + `servers.stopAll()` + `buildTLSConfig()` + `startStatsCollector()`.
- [x] API ↔ zone decoupling — ✅ DONE: `Zone.GetDefaultTTL()`, `GetOrigin()`, `RecordsByType()` methods replace direct struct access.

### Phase 3 — Monolith decomposition (1–2 weeks) · ✅ **DONE**
- [x] C2 `config.go` split — ✅ DONE (prior session): split into 20 per-domain files; `config.go` now 655 LOC.
- [x] C5 `protocol/types.go` split — ✅ DONE (prior session): `types_address.go`, `types_security.go`, `types_svcb.go`, etc.
- [x] Harden the YAML parser (fail loudly on anchors/multiline) — ✅ DONE (2026-06-15): tokenizer emits `TokenError` for anchors/aliases/tags/block scalars; parser default case errors instead of silent empty scalar.
- [ ] D9/D10 follow-through. **Remaining (mostly done — minor caps).**

### Phase 4 — Consensus hardening (carefully, 1–2 weeks) · ✅ **File splits DONE (2026-06-15)**
- [x] C3 gossip file split — ✅ DONE: 6 files, zero behavior change.
- [x] C3 raft file split — ✅ DONE: 5 files + doc anchor, zero behavior change.
- [x] D3/D4 concurrency fixes — ✅ DONE (2026-05-29): bounded RPC goroutines, single-lock-hold for replication.
- [ ] Callbacks-under-lock, election single-flight — **Remaining** (each behind a reproduction test under `-race`).

### Phase 5 — Polish (ongoing)
- C5 cache/resolver config knobs and cancellation; E test coverage + flake removal; OpenAPI generation; logging escapes (B1).

---

## Session 2026-06-15 — Completed Work

All changes verified: `go build` ✅ · `go vet` ✅ · `gofmt` clean ✅ · `go test -race ./...` all packages pass (cluster, raft, api, cmd, + 30 packages).

### 1. Reload unification + concurrency guard · `cmd/nothingdns/main.go`
- Extracted `reloadAllComponents()` closure — the 6-step reload sequence (config → zones → views → upstream → security → apply) now exists in **one place**, not duplicated across API callback and SIGHUP handler.
- Added `reloadMu sync.Mutex` — serializes concurrent reload triggers (SIGHUP + API, or two rapid SIGHUPs) so they cannot interleave zone-map mutations or manager swaps.
- Added `logReloadAudit()` helper — deduplicated ~12 copy-pasted audit-log blocks.
- File shrank 1574→1487 LOC despite adding the mutex + helper.
- Added `TestReloadAllComponents_ConcurrentTriggers` (3 goroutines × 20 reloads, overlap detector) + `TestReloadAllComponents_FailFastDoesNotMutate`.

### 2. `gossip.go` god-object split · `internal/cluster/`
Split the 1800-line `gossip.go` into 6 focused files — zero behavior change:
- `gossip_types.go` (260) — types, payloads, `GossipProtocol` struct, `GossipConfig`
- `gossip_encryption.go` (68) — AES-256-GCM: `initEncryption`, `encrypt`, `decrypt`, `encryptWithAAD`
- `gossip_swim.go` (379) — SWIM membership: receive loop, dispatch, ping/ack/gossip, probe loop, Join, Stats
- `gossip_election.go` (382) — leader election: handleElection/Leader/Heartbeat, split-brain detection, heartbeat loops
- `gossip_handlers.go` (607) — domain handlers: zone/config/cache/draining/stats/metrics + wire codec
- `gossip.go` (160) — core lifecycle: constructor, Start/Stop, SetCallbacks

### 3. `raft.go` god-object split · `internal/cluster/raft/`
Split the 1920-line `raft.go` into 5 focused files + doc anchor — zero behavior change:
- `types.go` (386) — core types, `Node` struct, `Config`, RPC message types
- `state.go` (626) — lifecycle, state-machine loop, term/persistence helpers, log index helpers, accessors
- `handlers.go` (478) — RPC handlers (vote/append/snapshot), transport senders
- `replication.go` (236) — Propose, broadcast, replicate-to-peer, snapshot install
- `membership.go` (239) — AddPeer/RemovePeer, joint consensus (RFC 7003)
- `raft.go` (17) — package doc anchor only

### 4. API handler boilerplate elimination · `internal/api/`
- Added `requireMethod(w, r, methods...)` — replaces 19× repeated method-dispatch blocks
- Added `decode(w, r, &dst)` — replaces 17× repeated JSON decode + `MaxBytesReader` + error blocks; standardizes body-limit enforcement (security win)
- Applied across 10 handler files; 7 files dropped the `encoding/json` import

### 5. Transport lifecycle extraction · `cmd/nothingdns/transports.go`
- Extracted ~170 lines of inline transport-start into `startServers()` + `startTLS()`/`startDoQ()`/`startXoT()`
- Extracted ~20 lines of shutdown into `servers.stopAll()`
- Extracted `buildTLSConfig()` (dynamic cert reload) + `startStatsCollector()`
- `main.go` shrank 1487→1365 LOC; `run()` now reads as three clear phases

### 6. API ↔ zone decoupling · `internal/zone/zone.go` + `internal/api/api_zones.go`
- Added `Zone.GetDefaultTTL()`, `Zone.GetOrigin()`, `Zone.RecordsByType()` — thread-safe read methods
- API handlers no longer manage the zone's `RWMutex` or iterate `zone.Records` directly
- Deleted the API-side `bulkPTRRecordsOfTypeLocked` helper (logic moved to `Zone.RecordsByType`)

### 7. Web dashboard cleanup · `web/package.json`
- Removed unused `next-themes` dependency (0 references in source). Both lockfiles regenerated.

### 8. YAML parser hardening · `internal/config/`
- Tokenizer now emits `TokenError` for anchors (`&`), aliases (`*`), tags (`!`), block scalars (`|`, `>`) — previously silently swallowed, causing data loss
- Parser `parseMapping` default case now errors on unexpected tokens instead of silently producing an empty scalar
- Removed dead `readTag`/`readAnchor`/`readAlias` methods (~50 LOC)
- Added `TestTokenizerUnsupportedFeatures` (5 subtests) + `TestParserRejectsAnchor/BlockScalar/Tag`

### 9. Test file consolidation
- Merged 70 `coverage_extra*_test.go` files into 28 per-package `coverage_test.go` files
- Removed 14 `_CoverageExtra4` suffixes from test function names
- Resolved 3 name collisions by keeping the better test and deleting stubs
- Updated 3 stale comments referencing old filenames

### 10. `ReloadCallback(*Config)` signature change · `internal/config/reload.go`
- `ReloadCallback` changed from `func() error` to `func(*Config) error` — every callback now receives the freshly-loaded config instead of independently re-fetching it (stale-read risk)
- `ReloadHandler.Start(configPath)` now loads/parses/validates config via `reloadFromPath` before dispatching to callbacks — if loading fails, callbacks never run
- `ReloadManager.reloadConfig` simplified: just stores the passed config

### 11. Web component decompositions
- `zone-editor.tsx` (1380 LOC) → `zone-editor/` directory: `record-utils.ts` (262), `record-form.tsx` (184), `record-dialogs.tsx` (450), `index.tsx` (516)
- `settings.tsx` (994 LOC) → `settings/` directory: `types.tsx` (148), `shared.tsx` (72), `general-settings.tsx` (67), `dns-settings.tsx` (61), `upstream-settings.tsx` (53), `cache-settings.tsx` (141), `security-settings.tsx` (120), `logging-settings.tsx` (76), `cluster-settings.tsx` (34), `advanced-settings.tsx` (94), `index.tsx` (131)

### Verification
- `go test -race ./...` run across all packages: cluster (5.5s), raft (24.7s), api (280s), cmd (2.5s), + 30 smaller packages — **all pass, zero data races**
- `gofmt -l` returns 0 files
- `go vet ./...` clean

### Remaining items (from original plan)
- D8: CSRF synchronizer token (medium effort, SameSite mitigates)
- Callbacks-under-lock, election single-flight in gossip (need reproduction tests)
- `dnssec/validator.go` method extraction
- `resolver.go` per-hop timeout granularity
- OpenAPI generation from handler metadata

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
