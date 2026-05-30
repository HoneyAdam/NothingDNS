// NothingDNS - DNS query pipeline stages

package main

import (
	"context"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/idna"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// setupStage creates per-request context, tracing span, and deferred cleanup.
// This is always the first stage.
func setupStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		q.reqID = util.GenerateRequestID()
		q.start = time.Now()

		// Defer latency recording and audit logging
		// (defer is handled at the ServeDNS wrapper level to keep stages simple)
		return false, nil
	}
}

// validationStage checks for empty questions and validates IDNA.
func validationStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if len(q.msg.Questions) == 0 {
			h.logger.Debug("Query with no questions")
			sendError(q.currentWriter, q.msg, protocol.RcodeFormatError)
			return true, nil
		}

		q.q = q.msg.Questions[0]
		q.qname = q.q.Name.String()
		q.qtype = q.q.QType

		h.logger.Debugf("[%s] Query: %s %s", q.reqID, q.qname, typeToString(q.qtype))

		// RFC 5891: Validate IDNA (internationalized domain names)
		if h.idnaEnabled {
			if _, err := idna.ToASCII(q.qname); err != nil {
				h.logger.Debugf("IDNA validation failed for %s: %v", q.qname, err)
				sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeFormatError, protocol.EDEProhibited, "invalid IDNA")
				return true, nil
			}
		}

		return false, nil
	}
}

// metricsStage records the incoming query metric.
func metricsStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.metrics != nil {
			h.metrics.RecordQuery(typeToString(q.qtype))
		}
		return false, nil
	}
}

// aclStage checks the access control list.
func aclStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.aclChecker != nil && clientIP != nil {
			allowed, redirect := h.aclChecker.IsAllowed(clientIP, q.qtype)
			if !allowed {
				if redirect != "" {
					h.logger.Infof("ACL redirect: %s %s from %s -> %s", q.qname, typeToString(q.qtype), clientIP, redirect)
					h.handleACLRedirect(q.currentWriter, q.msg, q.q, redirect)
				} else {
					h.logger.Infof("ACL denied: %s %s from %s", q.qname, typeToString(q.qtype), clientIP)
					sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				}
				return true, nil
			}
		}
		return false, nil
	}
}

// rpzClientStage checks RPZ client IP policy.
func rpzClientStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.rpzEngine != nil && clientIP != nil {
			if rule := h.rpzEngine.ClientIPPolicy(clientIP); rule != nil {
				h.applyRPZRule(w, q.msg, q.q, rule)
				return true, nil
			}
		}
		return false, nil
	}
}

// rateLimitStage checks per-IP rate limits.
func rateLimitStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.rateLimiter != nil && clientIP != nil {
			if !h.rateLimiter.Allow(clientIP) {
				h.logger.Debugf("RRL dropped: %s %s from %s", q.qname, typeToString(q.qtype), clientIP)
				if h.metrics != nil {
					h.metrics.RecordRateLimited()
				}
				sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				return true, nil
			}
		}
		return false, nil
	}
}

// doBitStage extracts the DO bit from the OPT record for cache key calculation.
// Run after validation so q.q is set, and before cache lookup.
func doBitStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if opt := q.msg.GetOPT(); opt != nil {
			optHdr := protocol.ParseEDNS0Header(opt)
			q.doBit = optHdr.DO
		}
		q.cacheKey = cache.MakeKey(q.qname, q.qtype, q.doBit)
		return false, nil
	}
}

// cacheStage checks the DNS cache before any upstream resolution.
// Returns (handled=true) if a cached response was found and sent.
func cacheStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if entry := h.cache.Get(q.cacheKey); entry != nil {
			q.cacheHit = true
			if entry.IsNegative {
				h.logger.Debugf("Cache hit (negative) for %s", q.qname)
				if h.metrics != nil {
					h.metrics.RecordCacheHit()
					h.metrics.RecordResponse(entry.RCode)
				}
				sendError(q.currentWriter, q.msg, entry.RCode)
				return true, nil
			}
			h.logger.Debugf("Cache hit for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordCacheHit()
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			reply(q.currentWriter, q.msg, entry.Message)
			return true, nil
		}

		if h.metrics != nil {
			h.metrics.RecordCacheMiss()
		}
		return false, nil
	}
}

// nsecCacheStage checks RFC 8198 aggressive NSEC cache before upstream.
func nsecCacheStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.nsecCache != nil {
			if synthResp := h.nsecCache.Lookup(q.qname, q.qtype); synthResp != nil {
				h.logger.Debugf("NSEC cache hit for %s (aggressive negative)", q.qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(synthResp.Header.Flags.RCODE)
				}
				reply(q.currentWriter, q.msg, synthResp)
				return true, nil
			}
		}
		return false, nil
	}
}

// blocklistStage checks if the query domain is blocklisted.
func blocklistStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.blocklist != nil && h.blocklist.IsBlocked(q.qname) {
			h.logger.Infof("Blocked query for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordBlocklistBlock()
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeNameError, protocol.EDEFiltered, "blocked by blocklist")
			return true, nil
		}
		return false, nil
	}
}

// rpzQnameStage checks RPZ QNAME policy.
func rpzQnameStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.rpzEngine != nil {
			if rule := h.rpzEngine.QNAMEPolicy(q.qname); rule != nil {
				if h.applyRPZRule(w, q.msg, q.q, rule) {
					return true, nil
				}
			}
		}
		return false, nil
	}
}

// splitHorizonStage checks view-specific zones (split-horizon DNS).
func splitHorizonStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.splitHorizon != nil && clientIP != nil {
			if view := h.splitHorizon.SelectView(clientIP); view != nil {
				if vzMap, ok := h.viewZones[view.Name]; ok {
					for origin, z := range vzMap {
						if isSubdomain(q.qname, origin) {
							h.logger.Debugf("View %s: checking zone %s for %s", view.Name, origin, q.qname)
							if h.handleAuthoritative(z, w, q.msg, q.q) {
								return true, nil
							}
						}
					}
				}
			}
		}
		return false, nil
	}
}

// authoritativeStage checks local authoritative zones for a direct answer.
func authoritativeStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		h.zonesMu.RLock()
		var matchedZones []struct {
			name string
			z    *zone.Zone
		}
		if h.zoneProvider != nil {
			for _, match := range h.zoneProvider.FindZones(q.qname) {
				matchedZones = append(matchedZones, struct {
					name string
					z    *zone.Zone
				}{match.Origin, match.Zone})
			}
		}
		h.zonesMu.RUnlock()

		for _, m := range matchedZones {
			h.logger.Debugf("Checking zone %s for %s", m.name, q.qname)
			if h.handleAuthoritative(m.z, w, q.msg, q.q) {
				return true, nil
			}
		}
		return false, nil
	}
}

// cnameStage checks if a CNAME chain exists in local zones and resolves it.
// Only runs when the query name fell within a zone but had no direct record.
func cnameStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		// Only run if we had a zone match with no direct record.
		h.zonesMu.RLock()
		hasZoneMatch := false
		if h.zoneProvider != nil {
			matches := h.zoneProvider.FindZones(q.qname)
			hasZoneMatch = len(matches) > 0
		}
		h.zonesMu.RUnlock()

		if !hasZoneMatch {
			return false, nil // no zone match means this stage doesn't apply
		}

		result := h.chaseCNAMEInZones(q.qname)
		if result.loopDetected {
			h.logger.Warnf("CNAME loop detected for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDERecursiveLoop, "CNAME loop detected")
			return true, nil
		}
		if len(result.cnameRecords) > 0 {
			targetAnswers := h.resolveCNAMETarget(w, q.msg, q.q, result.targetName, q.qtype)
			resp := h.buildCNAMEResponse(q.msg, result.cnameRecords, targetAnswers)

			if h.applyRPZResponsePolicy(w, q.msg, q.q, resp, result.targetName) {
				return true, nil
			}

			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			reply(q.currentWriter, q.msg, resp)
			return true, nil
		}
		return false, nil
	}
}

// authoritativeOnlyStage short-circuits if server is authoritative-only.
// Returns REFUSED for names outside all local zones (no upstream leak).
func authoritativeOnlyStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.config != nil && h.config.Resolution.AuthoritativeOnly {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeRefused)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeRefused, protocol.EDENotAuthoritative, "authoritative-only server: name is outside all configured zones")
			return true, nil
		}
		return false, nil
	}
}

// resolverStage uses iterative recursive resolver if enabled.
func resolverStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.resolver == nil {
			return false, nil
		}

		h.logger.Debugf("Resolving %s iteratively", q.qname)
		resp, err := func() (*protocol.Message, error) {
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return h.resolver.Resolve(resolveCtx, q.qname, q.qtype)
		}()
		if err != nil {
			h.logger.Warnf("Iterative resolution failed for %s: %v", q.qname, err)
			// RFC 8767: Try serve-stale when resolution fails
			if stale := h.cache.GetStale(q.cacheKey); stale != nil && stale.Message != nil {
				h.logger.Debugf("Serving stale cache entry for %s (resolver failed)", q.qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				reply(q.currentWriter, q.msg, stale.Message)
				return true, nil
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "iterative resolution failed")
			return true, nil
		}

		resp.Header.ID = q.msg.Header.ID

		if h.applyRPZResponsePolicy(w, q.msg, q.q, resp, q.qname) {
			return true, nil
		}

		if h.tryDNS64Synthesis(w, q.msg, q.q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return true, nil
		}

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(q.currentWriter, q.msg, resp)
		return true, nil
	}
}

// upstreamStage forwards queries to configured upstream servers.
// This is the terminal stage when upstream is configured.
func upstreamStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.upstream == nil && h.loadBalancer == nil {
			return false, nil // fall through to noUpstreamStage
		}

		h.logger.Debugf("Forwarding query for %s to upstream", q.qname)
		if h.metrics != nil {
			if len(h.config.Upstream.Servers) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.Servers[0])
			} else if len(h.config.Upstream.AnycastGroups) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.AnycastGroups[0].AnycastIP + ":53")
			}
		}

		var resp *protocol.Message
		var err error
		origID := q.msg.Header.ID
		q.msg.Header.ID = upstream.RandomTXID()
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(q.msg)
		} else {
			resp, err = h.upstream.Query(q.msg)
		}
		if err != nil {
			q.msg.Header.ID = origID
			h.logger.Warnf("Upstream query failed for %s: %v", q.qname, err)
			if stale := h.cache.GetStale(q.cacheKey); stale != nil && stale.Message != nil {
				h.logger.Debugf("Serving stale cache entry for %s (upstream failed)", q.qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				reply(q.currentWriter, q.msg, stale.Message)
				return true, nil
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "upstream unavailable")
			return true, nil
		}

		if resp.Header.ID != q.msg.Header.ID {
			q.msg.Header.ID = origID
			h.logger.Warnf("Upstream response ID mismatch for %s: got %d, want %d", q.qname, resp.Header.ID, q.msg.Header.ID)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "invalid upstream response")
			return true, nil
		}
		q.msg.Header.ID = origID

		// DNSSEC validation
		dnssecValidated := false
		if h.validator != nil && dnssec.HasSignature(resp) {
			result, valErr := h.validator.ValidateResponse(ctx, resp, q.qname)
			if valErr != nil {
				h.logger.Warnf("DNSSEC validation error for %s: %v", q.qname, valErr)
			}
			switch result {
			case dnssec.ValidationSecure:
				h.logger.Debugf("DNSSEC validation secure for %s", q.qname)
				resp.Header.Flags.AD = true
				dnssecValidated = true
			case dnssec.ValidationBogus:
				h.logger.Warnf("DNSSEC validation failed (bogus) for %s", q.qname)
				if h.config.DNSSEC.Enabled {
					if h.metrics != nil {
						h.metrics.RecordResponse(protocol.RcodeServerFailure)
					}
					sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDEDNSSECBogus, "DNSSEC validation failed")
					return true, nil
				}
			case dnssec.ValidationInsecure:
				h.logger.Debugf("DNSSEC insecure zone for %s", q.qname)
			case dnssec.ValidationIndeterminate:
				h.logger.Debugf("DNSSEC indeterminate for %s", q.qname)
				if h.config.DNSSEC.Enabled {
					if h.metrics != nil {
						h.metrics.RecordResponse(protocol.RcodeServerFailure)
					}
					sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDEDNSSECIndeterminate, "DNSSEC indeterminate")
					return true, nil
				}
			}
		}

		if h.applyRPZResponsePolicy(w, q.msg, q.q, resp, q.qname) {
			return true, nil
		}

		if h.tryDNS64Synthesis(w, q.msg, q.q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return true, nil
		}

		// Cache the response
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			ttl := extractTTL(resp)
			h.cache.Set(q.cacheKey, resp, ttl)
		} else if resp.Header.Flags.RCODE == protocol.RcodeNameError ||
			(resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) == 0) {
			negTTL := uint32(300)
			for _, rr := range resp.Authorities {
				if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
					if soa.Minimum > 0 {
						negTTL = soa.Minimum
					}
					break
				}
			}
			h.cache.SetNegative(q.cacheKey, resp.Header.Flags.RCODE)
			h.logger.Debugf("Cached negative response for %s (rcode=%d, negTTL=%d)", q.qname, resp.Header.Flags.RCODE, negTTL)

			if h.nsecCache != nil && resp.Header.Flags.RCODE == protocol.RcodeNameError {
				h.nsecCache.AddFromResponse(resp, dnssecValidated)
			}
		}

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}

		// RRL check
		if h.rrl != nil {
			clientIP := w.ClientInfo().IP()
			if clientIP != nil {
				qtype := uint16(0)
				if len(resp.Questions) > 0 {
					qtype = resp.Questions[0].QType
				}
				queryLen := q.msg.WireLength()
				responseLen := resp.WireLength()
				h.rrl.LogSuperlative(clientIP, qtype, resp.Header.Flags.RCODE, queryLen, responseLen)
				if allowed, suppressed := h.rrl.Allow(clientIP, qtype, resp.Header.Flags.RCODE); !allowed {
					if suppressed {
						h.sendRefused(q.currentWriter, q.msg)
						return true, nil
					}
				}
			}
		}

		reply(q.currentWriter, q.msg, resp)
		return true, nil
	}
}

// noUpstreamStage is the terminal stage when no upstream is configured.
// Returns NXDOMAIN with EDE per RFC 8914 §4.21.
func noUpstreamStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		h.logger.Debugf("No upstream configured, returning NXDOMAIN for %s", q.qname)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeNameError)
		}
		sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeNameError, protocol.EDENotAuthoritative, "no upstream configured")
		return true, nil
	}
}

// cookieStage handles RFC 7873 DNS Cookie validation.
// Wraps the response writer to inject server cookies into every response.
func cookieStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.cookieJar == nil {
			return false, nil
		}
		clientIP := w.ClientInfo().IP()
		if clientIP == nil {
			return false, nil
		}
		cookieData, valid := h.processCookies(q.msg, clientIP)
		if !valid {
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:    q.msg.Header.ID,
					Flags: protocol.NewResponseFlags(protocol.RcodeBadCookie),
				},
				Questions: q.msg.Questions,
			}
			resp.SetEDNS0(4096, false)
			if opt := resp.GetOPT(); opt != nil {
				if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
					optData.AddOption(protocol.OptionCodeCookie, cookieData)
				}
			}
			_, _ = q.currentWriter.Write(resp)
			return true, nil
		}
		if cookieData != nil {
			q.currentWriter = &cookieResponseWriter{inner: q.currentWriter, cookieData: cookieData}
		}
		return false, nil
	}
}

// anyStage handles RFC 8482 ANY query. For UDP, set TC=1 to force TCP retry.
func anyStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.qtype == protocol.TypeANY {
			if w.ClientInfo().Protocol == "udp" {
				h.handleANYTruncated(q.currentWriter, q.msg, q.q)
				return true, nil
			}
		}
		return false, nil
	}
}

// transferStage handles AXFR, IXFR, NOTIFY, and UPDATE requests.
func transferStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.qtype == protocol.TypeAXFR {
			h.handleAXFR(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		if q.qtype == protocol.TypeIXFR {
			h.handleIXFR(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		if transfer.IsNOTIFYRequest(q.msg) {
			h.handleNOTIFY(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		if transfer.IsUpdateRequest(q.msg) {
			h.handleUPDATE(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		return false, nil
	}
}
