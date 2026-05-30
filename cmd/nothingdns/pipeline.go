// NothingDNS - DNS query pipeline
// Decomposed ServeDNS into individually-testable Stage funcs.

package main

import (
	"context"
	"net"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// query holds all derived state for a DNS request.
// Created once at the top of ServeDNS and passed through every stage.
type query struct {
	reqID    string
	start    time.Time

	// Parsed from the incoming message
	msg   *protocol.Message
	q     *protocol.Question // first question; never nil after validation stage
	qname string
	qtype uint16

	// Client context (populated early, used throughout)
	clientIP net.IP

	// DO bit for cache key (RFC 8914 §4.6)
	doBit bool

	// Cache key including DO bit
	cacheKey string

	// Audit/tracing fields (written by stages)
	qtypeStr   string // human qtype for metrics/tracing
	qnameAudit string // qname for audit log (set once)
	cacheHit   bool   // set by cache stage

	// Response state (written by final stages)
	resp *protocol.Message
}

// Stage is a single processing step in the DNS pipeline.
// Return handled=true to stop pipeline and return immediately.
// Return handled=false to continue to next stage.
type Stage func(ctx context.Context, q *query, w server.ResponseWriter) (handled bool, err error)

// Pipeline runs a sequence of stages until one signals handled or all complete.
type Pipeline struct {
	stages []Stage
}

// ServeDNS runs all stages in order.
func (p *Pipeline) ServeDNS(ctx context.Context, h *integratedHandler, w server.ResponseWriter, r *protocol.Message) {
	q := &query{msg: r, start: time.Now()}

	for _, stage := range p.stages {
		handled, err := stage(ctx, q, w)
		if handled || err != nil {
			return
		}
	}
}

// AppendStage adds a stage to the pipeline.
func (p *Pipeline) AppendStage(s Stage) {
	p.stages = append(p.stages, s)
}

// NewPipeline builds a fully configured DNS query pipeline for h.
// Stages are registered in the order they execute in ServeDNS.
func NewPipeline(h *integratedHandler) *Pipeline {
	p := &Pipeline{}
	p.AppendStage(setupStage(h))
	p.AppendStage(validationStage(h))
	p.AppendStage(metricsStage(h))
	p.AppendStage(aclStage(h))
	p.AppendStage(rpzClientStage(h))
	p.AppendStage(rateLimitStage(h))
	p.AppendStage(cookieStage(h))
	p.AppendStage(anyStage(h))
	p.AppendStage(transferStage(h))
	p.AppendStage(doBitStage(h))
	p.AppendStage(cacheStage(h))
	p.AppendStage(nsecCacheStage(h))
	p.AppendStage(blocklistStage(h))
	p.AppendStage(rpzQnameStage(h))
	p.AppendStage(splitHorizonStage(h))
	p.AppendStage(authoritativeStage(h))
	p.AppendStage(cnameStage(h))
	p.AppendStage(authoritativeOnlyStage(h))
	p.AppendStage(resolverStage(h))
	p.AppendStage(upstreamStage(h))
	p.AppendStage(noUpstreamStage(h))
	return p
}