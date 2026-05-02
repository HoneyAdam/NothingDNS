# NothingDNS Production Readiness Guide

## Overview

This guide covers production deployment best practices for NothingDNS DNS server.

## Architecture Recommendations

### Single Node (Development/Staging)

```
┌─────────────────────────────────────┐
│         NothingDNS Instance          │
│                                      │
│  UDP/53 → Handler → Cache → Upstream │
│  TCP/53   (21-stage)   └→ KVStore    │
│  TLS/853                          │
│  HTTP/8080 (API, DoH)               │
└─────────────────────────────────────┘
```

### High Availability (Production)

```
┌────────────────────────────────────────────────────────┐
│                    Load Balancer                        │
│                 (GeoDNS/Anycast)                        │
└──────────────┬──────────────┬──────────────┬───────────┘
               │              │              │
    ┌──────────▼──────┐  ┌────▼────┐  ┌─────▼──────┐
    │  NothingDNS     │  │ Node 2  │  │  Node 3    │
    │  Node 1         │  │         │  │            │
    │                 │  │         │  │            │
    │  SWIM/Raft ←─── │  │ ←───── Cluster Gossip ──→   │
    │                 │  │                              │
    └────────┬────────┘  └───┬────┘  └──────┬───────┘
             │               │              │
             └───────────────┴──────────────┘
                       │
                  KVStore/WAL
                  (Shared)
```

## Sizing Guidelines

### Resource Requirements

| QPS | CPU Cores | Memory | Disk IOPS |
|-----|-----------|--------|-----------|
| 1,000 | 2 | 2 GB | 1,000 |
| 5,000 | 4 | 4 GB | 2,500 |
| 10,000 | 8 | 8 GB | 5,000 |
| 50,000 | 16 | 16 GB | 10,000 |
| 100,000+ | 32+ | 32 GB+ | 20,000+ |

### Cache Sizing

```yaml
cache:
  size: 10000        # Entries per GB memory
  max_ttl: 86400     # 24 hours
  prefetch: true
```

Rule of thumb: 1 cache entry ≈ 1 KB memory

## Performance Tuning

### Kernel Parameters

```bash
# /etc/sysctl.d/50-nothingdns.conf

# Network
net.core.rmem_max = 134217728    # 128MB receive buffer
net.core.wmem_max = 134217728    # 128MB send buffer
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# File descriptors
fs.file-max = 65536

# TCP tuning
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
```

### Worker Pool Sizing

```yaml
server:
  workers:
    udp: 32           # CPU * 4
    tcp: 16           # CPU * 2
```

### Upstream Tuning

```yaml
upstream:
  timeout: 5
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
    - 9.9.9.9:53
```

## Security Hardening

### 1. TLS Configuration

```yaml
server:
  http:
    tls:
      enabled: true
      profiles:
        strict:
          min_version: "1.3"
          cipher_suites:
            - TLS_AES_256_GCM_SHA384
            - TLS_CHACHA20_POLY1305_SHA256
            - TLS_AES_128_GCM_SHA256
```

### 2. DNSSEC Configuration

```yaml
dnssec:
  enabled: true
  signing:
    enabled: true
    algorithm: ecdsap256sha256  # Faster than RSA
    signature_validity: 7
    signature_refresh: 5
```

### 3. Access Control

```yaml
security:
  acl:
    default_action: deny
    rules:
      - action: allow
        cidr: "10.0.0.0/8"
      - action: allow
        cidr: "172.16.0.0/12"
      - action: allow
        cidr: "192.168.0.0/16"
      - action: deny
        cidr: "0.0.0.0/0"
```

### 4. Rate Limiting

```yaml
security:
  rate_limit:
    enabled: true
    queries_per_second: 100
    burst: 200

  rrl:
    enabled: true
    rate_limit: 100
    max_table_size: 100000
```

## High Availability

### Cluster Configuration

```yaml
cluster:
  enabled: true
  consensus_mode: "swim"      # or "raft" for strong consistency
  encryption_key: "${ENCRYPTION_KEY}"
  cache_sync: true
  gossip_port: 7946
```

### Health Checks

Configure load balancer health checks:

```bash
# HTTP API health
curl http://node:8080/health

# DNS health (TCP probe)
dig @node:53 +tcp +time=3 +tries=1 google.com
```

### Failover Configuration

```yaml
# Kubernetes-style health checks
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Monitoring & Alerting

### Key Metrics

```promql
# Query rate
rate(nothingdns_queries_total[5m])

# Cache hit ratio
sum(rate(nothingdns_cache_hits_total[5m])) / sum(rate(nothingdns_cache_queries_total[5m]))

# Latency p99
histogram_quantile(0.99, rate(nothingdns_latency_seconds_bucket[5m]))

# Error rate
rate(nothingdns_errors_total[5m])

# Cluster node health
nothingdns_cluster_node_health
```

### Alert Rules

```yaml
# prometheus/alerts/nothingdns.yaml
groups:
  - name: nothingdns
    rules:
      - alert: NothingDNSDown
        expr: up{job="nothingdns"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "NothingDNS instance down"

      - alert: NothingDNSHighLatency
        expr: histogram_quantile(0.99, rate(nothingdns_latency_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "NothingDNS high latency"

      - alert: NothingDNSCacheHitRatioLow
        expr: rate(nothingdns_cache_hits_total[5m]) / rate(nothingdns_cache_queries_total[5m]) < 0.5
        for: 10m
        labels:
          severity: warning

      - alert: NothingDNSHighErrorRate
        expr: rate(nothingdns_errors_total[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
```

## Backup & Recovery

### Configuration Backup

```bash
# Backup config
tar -czf nothingdns-config-backup.tar.gz \
  /etc/nothingdns/nothingdns.yaml \
  /etc/nothingdns/zones/ \
  /etc/nothingdns/tls/
```

### KVStore Backup

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
tar -czf /backup/nothingdns-kvstore-$DATE.tar.gz /data/nothingdns/*.kv
```

### Zone File Backup

```bash
# Using dnsctl
./dnsctl zone export example.com > example.com.zone.bak
```

## Capacity Planning

### Growth Projections

| Metric | Current | 6 months | 12 months |
|--------|---------|----------|-----------|
| QPS | 1,000 | 3,000 | 10,000 |
| Cache entries | 10,000 | 30,000 | 100,000 |
| Zones | 5 | 15 | 50 |
| Nodes | 1 | 3 | 5 |

### Scaling Triggers

```yaml
# Scale up when:
# - CPU > 70% sustained
# - Memory > 80%
# - Cache hit ratio < 60%
# - P99 latency > 100ms
```

## Operational Procedures

### Configuration Reload

```bash
# Send SIGHUP (zero-downtime reload)
kill -HUP $(pidof nothingdns)

# Verify reload
curl http://localhost:8080/api/v1/config | jq '.version'
```

### Cache Flush

```bash
# Via API
curl -X POST http://localhost:8080/api/v1/cache/flush

# Via dnsctl
./dnsctl cache flush
```

### Log Analysis

```bash
# Real-time query debugging
tail -f /var/log/nothingdns/query.log | jq 'select(.rcode == "SERVFAIL")'

# Cache analysis
grep "cache" /var/log/nothingdns/*.log | jq '.action, .key'
```

## Troubleshooting

### High Memory Usage

1. Check cache size vs. configured limit
2. Enable memory monitor:
   ```yaml
   memory:
     monitor:
       enabled: true
       threshold: 0.8
   ```
3. Reduce cache size if needed

### High CPU Usage

1. Check if DNSSEC signing is the cause
2. Consider pre-signed zones
3. Scale horizontally

### Slow Responses

1. Check upstream latency
2. Enable query logging:
   ```yaml
   logging:
     level: debug
     query_log:
       enabled: true
   ```
3. Check for RRL suppression

## Compliance

### GDPR Considerations

- Query logs may contain PII (client IPs)
- Configure log retention policy
- Consider disabling query logging if not needed

### SOC 2 Requirements

- Enable audit logging
- Configure access controls
- Regular backups
- Incident response procedures

### PCI-DSS

- Disable vULN-059/VULN-060 mitigations if not needed
- Enable TLS for all management interfaces
- Regular security updates