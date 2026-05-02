# NothingDNS Helm Chart

A production-grade DNS server with support for all major DNS protocols.

## TL;DR

```bash
helm repo add nothingdns https://nothingdns.github.io/helm
helm install my-release nothingdns/nothingdns
```

## Introduction

NothingDNS is a zero-dependency DNS server written in pure Go, implementing:
- **Authoritative DNS** with zone management and DNSSEC signing/validation
- **Recursive Resolution** with Qname minimization and 0x20 encoding
- **DNS Security** with DNSSEC, Cookies, ACLs, Rate Limiting, Blocklists, RPZ
- **All Standard Transports**: UDP, TCP, TLS (DoT), HTTPS (DoH), QUIC (DoQ), WebSocket, XoT

## Features

- **21-Stage Request Pipeline** for comprehensive DNS query processing
- **Hot Config Reload** without downtime (SIGHUP)
- **High Availability** with SWIM gossip or Raft consensus
- **Multi-Transport Support**: DoT, DoH, DoQ, XoT, WebSocket
- **Zero External Dependencies** (Go stdlib only)
- **Embedded Dashboard** with real-time stats

## Requirements

- Kubernetes 1.19+
- Helm 3.2.0+

## Installation

### Add Helm Repository

```bash
helm repo add nothingdns https://nothingdns.github.io/helm
helm repo update
```

### Install Chart

```bash
helm install my-release nothingdns/nothingdns
```

### Configuration

See [NothingDNS Configuration Reference](https://github.com/nothingdns/NothingDNS/blob/main/docs/CONFIG_REFERENCE.md) for all available options.

#### Basic Configuration

```yaml
server:
  port: 53
  bind:
    - 0.0.0.0

upstream:
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53

cache:
  size: 10000
  prefetch: true
```

#### Production Configuration with DNSSEC

```yaml
server:
  port: 53
  http:
    enabled: true
    bind: "0.0.0.0:8080"
    dashboard: true

upstream:
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53

dnssec:
  enabled: true
  signing:
    enabled: true
    algorithm: ecdsap256sha256

zones:
  - /etc/nothingdns/zones/example.com.zone

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
```

#### High Availability Cluster

```yaml
cluster:
  enabled: true
  node_id: "node-1"
  bind_addr: "0.0.0.0"
  gossip_port: 7946
  consensus_mode: "swim"
  encryption_key: "YOUR_32_BYTE_BASE64_KEY"
  cache_sync: true
  seed_nodes:
    - 172.28.0.10:7946
    - 172.28.0.11:7946
```

## Parameters

### General Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/nothingdns/nothingdns` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag | `latest` |

### Server Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `server.port` | DNS port | `53` |
| `server.http.enabled` | Enable HTTP API | `true` |
| `server.http.bind` | HTTP bind address | `0.0.0.0:8080` |
| `server.http.dashboard` | Enable dashboard | `true` |

### Upstream Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `upstream.strategy` | Load balancing strategy | `round_robin` |
| `upstream.servers` | Upstream DNS servers | `[]` |
| `upstream.timeout` | Query timeout (seconds) | `5` |

### Cache Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `cache.size` | Maximum cache entries | `10000` |
| `cache.min_ttl` | Minimum TTL (seconds) | `300` |
| `cache.max_ttl` | Maximum TTL (seconds) | `86400` |
| `cache.prefetch` | Enable prefetch | `true` |

### Security Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.acl.default_action` | Default ACL action | `allow` |
| `security.rate_limit.enabled` | Enable rate limiting | `true` |
| `security.rate_limit.queries_per_second` | Queries per second per IP | `100` |

### Cluster Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `cluster.enabled` | Enable clustering | `false` |
| `cluster.node_id` | Unique node ID | `` |
| `cluster.consensus_mode` | SWIM or Raft | `swim` |
| `cluster.gossip_port` | Gossip port | `7946` |

## Persistence

The chart mounts a PersistentVolumeClaim at `/data` for:
- Cache persistence
- Session storage
- Zone modifications
- WAL journals

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable persistence | `true` |
| `persistence.storageClass` | Storage class | `default` |
| `persistence.size` | Volume size | `1Gi` |

## Dashboard

The embedded React dashboard is served at the HTTP port (default: 8080). It provides:
- Real-time query statistics
- Cache hit/miss ratios
- Zone management
- Cluster status
- Log viewer

## Metrics

Prometheus metrics are exposed at `/metrics` on the HTTP port.

### Recommended Prometheus Rules

```yaml
prometheusRule:
  enabled: true
  groups:
    - name: nothingdns
      rules:
        - alert: NothingDNSErrors
          expr: rate(nothingdns_errors_total[5m]) > 0
          for: 5m
          labels:
            severity: warning
          annotations:
            description: NothingDNS error rate is elevated
```

## Security

### Network Policies

The chart includes network policies by default. Update `networkPolicy.enabled` to `false` to disable.

### Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE
```

## Troubleshooting

### DNS Queries Not Working

1. Check if the server is running:
   ```bash
   kubectl logs -l app.kubernetes.io/name=nothingdns
   ```

2. Verify the service is exposed:
   ```bash
   kubectl get svc -l app.kubernetes.io/name=nothingdns
   ```

3. Test DNS resolution:
   ```bash
   kubectl run -it --rm dns-test --image=busybox --restart=Never -- \
     nslookup kubernetes.default.svc.cluster.local
   ```

### Cluster Not Forming

1. Verify all nodes have unique `node_id` values
2. Check gossip port (default 7946) is accessible
3. Ensure `encryption_key` is set (required for multi-node)
4. Check cluster status via dashboard or API:
   ```bash
   curl http://<node>:8080/api/v1/cluster/status
   ```

### DNSSEC Validation Failing

1. Verify `dnssec.enabled: true` in configuration
2. Check trust anchors are configured correctly
3. Verify system time is correct
4. Check logs for specific validation errors

## Development

### Local Development with Helm

```bash
# Clone repository
git clone https://github.com/nothingdns/NothingDNS.git
cd NothingDNS

# Install dependencies
helm dependency update deploy/helm/nothingdns

# Dry run installation
helm install my-release deploy/helm/nothingdns \
  --dry-run \
  --debug \
  -f deploy/config-node1.yaml
```

### Building the Chart

```bash
helm package deploy/helm/nothingdns
```

## License

Copyright 2024 NothingDNS Authors. Apache License 2.0.