# NothingDNS Deployment Checklist

## Pre-Deployment

### Infrastructure Requirements

- [ ] **CPU**: 2+ cores recommended (4+ for high QPS)
- [ ] **Memory**: 2GB minimum (4GB+ for caching)
- [ ] **Disk**: SSD for KVStore/WAL performance
- [ ] **Network**: Low-latency connectivity to upstream DNS servers

### Port Requirements

| Port | Protocol | Purpose | Required |
|------|----------|---------|----------|
| 53 | UDP/TCP | DNS queries | Yes |
| 53 | TCP | Zone transfers (AXFR) | Yes |
| 853 | TCP | DNS over TLS (DoT) | Optional |
| 443 | TCP | DNS over HTTPS (DoH) | Optional |
| 8080 | TCP | HTTP API + Dashboard | Yes |
| 7946 | UDP/TCP | Cluster gossip | Cluster only |
| 9153 | TCP | Prometheus metrics | Optional |

### Firewall Configuration

```bash
# DNS (required)
sudo firewall-cmd --add-port=53/udp --add-port=53/tcp
sudo firewall-cmd --add-port=853/tcp  # DoT
sudo firewall-cmd --add-port=443/tcp  # DoH

# API (required for management)
sudo firewall-cmd --add-port=8080/tcp

# Cluster (if multi-node)
sudo firewall-cmd --add-port=7946/udp --add-port=7946/tcp

# Metrics (optional)
sudo firewall-cmd --add-port=9153/tcp
```

## Installation

### 1. Binary Installation

```bash
# Download latest release
curl -LO https://github.com/nothingdns/NothingDNS/releases/latest/download/nothingdns_linux_amd64.tar.gz
tar -xzf nothingdns_linux_amd64.tar.gz

# Install
sudo cp nothingdns /usr/local/bin/
sudo cp dnsctl /usr/local/bin/
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/nothingdns

# Verify
./nothingdns --version
```

### 2. Docker Installation

```bash
# Pull image
docker pull ghcr.io/nothingdns/nothingdns:latest

# Or use Docker Compose (see docker-compose.yml)
docker-compose up -d
```

### 3. Kubernetes Installation

```bash
# Add Helm repo
helm repo add nothingdns https://nothingdns.github.io/helm
helm repo update

# Install
helm install my-release nothingdns/nothingdns \
  --set server.port=53 \
  --set upstream.servers[0]=1.1.1.1:53 \
  --set upstream.servers[1]=8.8.8.8:53
```

### 4. Configuration

- [ ] Copy `config.example.yaml` to `/etc/nothingdns/nothingdns.yaml`
- [ ] Configure bind addresses
- [ ] Set up upstream DNS servers
- [ ] Configure cache settings
- [ ] Enable security features (ACL, rate limiting)

### 5. Directory Setup

```bash
# Create directories
sudo mkdir -p /etc/nothingdns/zones
sudo mkdir -p /etc/nothingdns/tls
sudo mkdir -p /var/log/nothingdns
sudo mkdir -p /data/nothingdns

# Set permissions
sudo chown -R 1000:1000 /etc/nothingdns
sudo chown -R 1000:1000 /var/log/nothingdns
sudo chown -R 1000:1000 /data/nothingdns
```

### 6. Zone File Setup

```bash
# Copy example zones
cp examples/zones/example.com.zone /etc/nothingdns/zones/

# Update config
# zones:
#   - /etc/nothingdns/zones/example.com.zone
```

## Security Hardening

### 1. File Permissions

```bash
# Config file
chmod 600 /etc/nothingdns/nothingdns.yaml

# Zone files
chmod 644 /etc/nothingdns/zones/*.zone

# TLS certificates
chmod 600 /etc/nothingdns/tls/*.key
```

### 2. Enable TLS

```yaml
# /etc/nothingdns/nothingdns.yaml
server:
  http:
    tls:
      enabled: true
      cert_file: /etc/nothingdns/tls/server.crt
      key_file: /etc/nothingdns/tls/server.key
```

### 3. Configure ACL

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
```

### 4. Enable Rate Limiting

```yaml
security:
  rate_limit:
    enabled: true
    queries_per_second: 100
    burst: 200
```

### 5. Enable DNSSEC

```yaml
dnssec:
  enabled: true
  trust_anchors:
    - type: hint
      value: "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
```

## Monitoring Setup

### 1. Prometheus Metrics

```yaml
metrics:
  enabled: true
  prometheus:
    enabled: true
    path: /metrics
```

### 2. Health Checks

```bash
# Liveness probe
curl http://localhost:8080/health

# Readiness probe
curl http://localhost:8080/readyz
```

### 3. Log Rotation

```bash
# /etc/logrotate.d/nothingdns
/var/log/nothingdns/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root root
    postrotate
        kill -HUP $(pidof nothingdns)
    endscript
}
```

## Pre-Launch Validation

### 1. Configuration Validation

```bash
./nothingdns -validate-config -config /etc/nothingdns/nothingdns.yaml
```

### 2. Test DNS Resolution

```bash
# Test basic query
dig @localhost example.com

# Test with DNSSEC
dig @localhost example.com +dnssec

# Test TCP
dig @localhost example.com +tcp

# Test zone transfer
dig @localhost example.com AXFR
```

### 3. Check Logs

```bash
# Look for errors
journalctl -u nothingdns --no-pager -n 50

# Watch live logs
tail -f /var/log/nothingdns/*.log
```

### 4. Verify Ports

```bash
# Check listening ports
ss -tulpn | grep nothingdns
```

## Launch

### 1. Systemd Service

```bash
# Copy service file
sudo cp deploy/nothingdns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nothingdns
sudo systemctl start nothingdns

# Check status
sudo systemctl status nothingdns
```

### 2. Docker Launch

```bash
docker run -d \
  --name nothingdns \
  --cap-add NET_BIND_SERVICE \
  -p 53:53/udp -p 53:53/tcp \
  -p 853:853/tcp \
  -p 443:443/tcp \
  -p 8080:8080 \
  -v /etc/nothingdns:/etc/nothingdns:ro \
  -v /data:/data \
  ghcr.io/nothingdns/nothingdns:latest
```

## Post-Launch Verification

### 1. DNS Tests

```bash
# Query from localhost
dig @localhost example.com +short

# Query from external
dig @your-dns-server.com example.com +short

# Test DNSSEC validation
dig @localhost wikipedia.org A +dnssec

# Test DoH
curl -H 'accept: application/dns-json' 'https://localhost/dns-query?name=example.com&type=A'
```

### 2. API Tests

```bash
# Health check
curl http://localhost:8080/health

# Get stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/cache/stats

# Check metrics
curl http://localhost:8080/metrics | grep nothingdns_
```

### 3. Load Testing (Optional)

```bash
# Using dnsperf or similar
dnsperf -s localhost -d query.txt -c 100 -T 10
```

## Cluster Setup (Multi-Node)

### 1. First Node (Seed)

```yaml
cluster:
  enabled: true
  node_id: "node-1"
  bind_addr: "0.0.0.0"
  gossip_port: 7946
  consensus_mode: "swim"
  encryption_key: "YOUR_32_BYTE_BASE64_KEY"
  cache_sync: true
  seed_nodes: []
```

### 2. Additional Nodes

```yaml
cluster:
  enabled: true
  node_id: "node-2"
  bind_addr: "0.0.0.0"
  gossip_port: 7946
  consensus_mode: "swim"
  encryption_key: "YOUR_32_BYTE_BASE64_KEY"
  cache_sync: true
  seed_nodes:
    - 172.28.0.10:7946
```

### 3. Verify Cluster

```bash
curl http://localhost:8080/api/v1/cluster/status
curl http://localhost:8080/api/v1/cluster/nodes
```

## Rollback Plan

### 1. Keep Previous Binary

```bash
# Before upgrade, backup current binary
sudo cp /usr/local/bin/nothingdns /usr/local/bin/nothingdns.backup
```

### 2. Quick Rollback

```bash
# Stop service
sudo systemctl stop nothingdns

# Restore previous binary
sudo cp /usr/local/bin/nothingdns.backup /usr/local/bin/nothingdns

# Restart
sudo systemctl start nothingdns
```

### 3. Docker Rollback

```bash
# Stop and remove
docker stop nothingdns
docker rm nothingdns

# Pull previous version
docker pull ghcr.io/nothingdns/nothingdns:v0.x.x

# Start with previous version
docker run ...
```

## Documentation Handoff

- [ ] Update runbook with NothingDNS specifics
- [ ] Document custom RPZ rules
- [ ] Document cluster node IPs
- [ ] Document escalation contacts
- [ ] Test failover procedures