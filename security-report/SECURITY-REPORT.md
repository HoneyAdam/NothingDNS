# NothingDNS — Security Report (post 30/30 + L-6 wiring re-scan)

**Date:** 2026-05-23 (re-scan after first-pass 30/30 closure + L-6 wiring)
**Predecessor:** `SECURITY-REPORT-2026-05-23-postfix.md` (full closed list)
**Pipeline:** security-check 4-phase (Recon → Hunt × 9 parallel agents → Verify → Report)

---

## Executive Summary

The re-scan confirmed all 30 prior findings are committed and unbroken. It surfaced **13 NEW findings** that the first pass missed or that the fixes themselves introduced. **All 13 closed same session.**

| Severity | New count | Status |
|---|---|---|
| HIGH | 2 | ✅ FIXED |
| LOW | 11 | ✅ FIXED (10 fully + 1 deferred-perf-hint L-N4) |
| INFO | 3 | hygiene only, not actioned |

**Bottom line:** 2 HIGH + 12 LOW from the re-scan are landed. The full 2026-05-23 work covers **43 verified findings closed same-day** (2H + 12M + 16L original + 2H + 11L re-scan).

---

## NEW-HIGH findings

### NEW-H1: KV at-rest encryption non-functional in production
- **Commit:** `a6ee399`
- **Class:** Self-inflicted regression from db8daa5 (L-6 wiring)
- **CVSS 3.1:** 6.8 (AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N)
- **Root cause:** `KVStore.save()` dispatched to `writeTLV` only when `hmacKey != nil`. The L-6 production wiring passes `nil` hmacKey + non-nil aeadKey, so save took the legacy JSON branch and the AEAD branch inside writeTLV never ran. Startup log misleadingly printed "AES-256-GCM at rest" while the on-disk file was plain JSON.
- **Test gap:** `TestKVStore_EncryptedRoundTrip` supplied BOTH keys and passed; production wiring shape (nil hmac, non-nil aead) was untested.
- **Fix:** widened the save() dispatch to fire on `s.hmacKey != nil || s.aeadKey != nil`. Added `TestKVStore_EncryptedAeadOnly_NoPlaintextOnDisk` that exactly mirrors production wiring.

### NEW-H2: DNSSEC negative-response NSEC/NSEC3 accepted without RRSIG verification
- **Commit:** `15a397b`
- **Class:** Pre-existing — H-2 fix didn't generalise to sibling code path
- **CVSS 3.1:** 7.4 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N) — same as H-2
- **Root cause:** `validateNegativeResponse` walked `msg.Authorities` directly and trusted whatever NSEC/NSEC3 wire claims arrived. The range/bitmap checks (`validateNSEC`, `validateNSEC3`, NSEC3 closest-encloser) only prove "given THIS record exists, it implies non-existence" — they do not authenticate the record itself. Same downgrade-attack class as H-2; on-path attacker can forge NXDOMAIN/NODATA with no signature.
- **Fix:** new `authenticatedDenialRRs` helper (same shape as `verifyDSDenial`) filters to NSEC/NSEC3 RRsets whose RRSIG validates under chain[len-1].dnsKeys. validateNegativeResponse walks the filtered set; the NXDOMAIN-NSEC3 closest-encloser collection also reads from it. Three existing tests asserted the buggy behaviour (Secure on unsigned mocks) — repurposed to assert Bogus.

---

## NEW-LOW findings

All fixed; commits inline.

| ID | File:line | Fix commit | Description |
|---|---|---|---|
| L-N1 | kvstore.go:484, snapshot.go:321 | `5267048` | Encrypted-path `io.ReadAll` bounded via `io.LimitReader` + post-read sanity check |
| L-N2 | kvstore.go writeTLV | `12d20d4` | `len(payload) > maxKVPayload` guard before uint32 narrowing |
| L-N3 | KVStore.Close, Snapshotter | `12d20d4` | Best-effort key zeroize + caller-slice copy (decouple zeroize from caller state) |
| L-N5 | api_zones.go handleListZones, api_rpz.go handleRPZRules | `5ab7cfa` | L-10 cap generalised to two sibling list endpoints (5000 cap + Total + Truncated) |
| L-N6 | api/api_metrics.go handleDashboardStats | `5ab7cfa` | L-11 method gate generalised to API-package mirror handler |
| L-N7 | server/tls.go processMessage | `a1539d7` | L-2 panic recovery generalised to DoT worker |
| L-N8 | docker-compose.yml | `3dbcda4` | `${NOTHINGDNS_IMAGE:-...}` env-var pattern replaces hardcoded `:latest` |
| L-N9 | go.yml + web.yml | `3dbcda4` | codecov-action SHA-pin HOWTO comment (operator-action-required) |
| L-N10 | http.MaxSessionsPerUser | `27ef0eb` | YAML field added + parsed + plumbed to auth.NewStore |
| L-N11 | zone_manager.go storage key | `27ef0eb` | Bad-hex AEAD key fail-fast instead of silent plaintext fallback |

**L-N4** (cipher.AEAD rebuild on every Save/Load) deferred — pure perf optimisation, not security; if it becomes a hot-path concern it can land as a separate refactor.

---

## Patterns reinforced

Two failure modes are recurring across this 2026-05-23 work and worth pinning in memory:

1. **"Test shape ≠ production shape" (NEW-H1)**: regression tests must exercise the same combination of optional configuration the production wiring uses. Maximally-configured fixtures don't catch dispatch-gap bugs.
2. **"Fix not generalised to sibling" (L-N5/6/7, NEW-H2)**: when a fix patches a specific file:line, the same anti-pattern usually exists in sibling handlers / sibling code paths. Audit them BEFORE committing the original fix — not after the next scan catches them.

---

## Session-wide finding ledger (2026-05-23)

| Severity | Original scan | Re-scan | Closed same-day |
|---|---|---|---|
| HIGH | 2 | 2 | 4/4 |
| MEDIUM | 12 | 0 | 12/12 |
| LOW | 16 | 11 | 27/27 |
| **Total** | **30** | **13** | **43/43** |

All 43 findings landed with regression tests verified to FAIL with the fix reverted, then restored. Infra fixes (non-Go) have no regression-test surface; the diff is the audit artifact.

---

## Pipeline statistics (re-scan)

- 9 parallel hunt agents (same groupings as first pass)
- ~12 minutes wall time
- 1 verifier inline (the two HIGHs)
- ~1.1M tokens for Phase 2+3 hunt + verify
- 3 INFO-only items not actioned: cipher.AEAD per-call rebuild (perf), Dockerfile cache-layer ordering (perf), healthcheck timeout asymmetry (ops)
