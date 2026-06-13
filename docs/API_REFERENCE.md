# NothingDNS API Reference

REST API for managing NothingDNS server, zones, cache, cluster, and authentication.

**Base URL**: `http://localhost:8080`

**Authentication**: Bearer token (JWT) in `Authorization` header, or session cookie.

## Table of Contents

1. [Authentication](#1-authentication)
2. [Health & Status](#2-health--status)
3. [Zones](#3-zones)
4. [Cache](#4-cache)
5. [Cluster](#5-cluster)
6. [Blocklist & RPZ](#6-blocklist--rpz)
7. [Security (ACL)](#7-security-acl)
8. [DNSSEC](#8-dnssec)
9. [Upstreams](#9-upstreams)
10. [Config](#10-config)
11. [Metrics & Logs](#11-metrics--logs)
12. [Dashboard](#12-dashboard)

---

## 1. Authentication

### Login

Authenticate and obtain JWT token.

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "yourpassword"
}
```

**Response** (200 OK):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-05-02T12:00:00Z",
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

### Bootstrap

Create initial admin user (only works when no users exist).

```http
POST /api/v1/auth/bootstrap
Content-Type: application/json

{
  "username": "admin",
  "password": "SecurePassword123!",
  "email": "admin@example.com"
}
```

### Logout

Invalidate current session.

```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

### Get Users

List all users.

```http
GET /api/v1/auth/users
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "users": [
    {
      "username": "admin",
      "role": "admin",
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-05-02T10:30:00Z"
    }
  ]
}
```

### Create User

```http
POST /api/v1/auth/users
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "operator",
  "password": "Password123!",
  "role": "operator"
}
```

### Delete User

```http
DELETE /api/v1/auth/users/{username}
Authorization: Bearer <token>
```

### Get Roles

Requires operator or admin role.

```http
GET /api/v1/auth/roles
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "roles": [
    {"name": "admin", "description": "Full access to all resources"},
    {"name": "operator", "description": "Can modify zones and view operational data"},
    {"name": "viewer", "description": "Read-only access"}
  ]
}
```

---

## 2. Health & Status

### Health Check

Basic liveness check.

```http
GET /health
```

**Response** (200 OK):
```json
{"status": "ok"}
```

### Readiness Check

```http
GET /readyz
```

**Response** (200 OK):
```json
{"status": "ready", "checks": {"api": "ok", "dns": "ok"}}
```

### Liveness Check

```http
GET /livez
```

### Server Status

```http
GET /api/v1/status
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "version": "1.0.0",
  "uptime": 86400,
  "start_time": "2024-05-01T12:00:00Z",
  "build": {
    "go_version": "1.25.0",
    "compiler": "gc",
    "arch": "amd64"
  }
}
```

---

## 3. Zones

### List Zones

```http
GET /api/v1/zones
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "zones": [
    {
      "name": "example.com.",
      " ttl": 3600,
      "records_count": 45,
      "loaded_at": "2024-05-01T12:00:00Z",
      "signed": true,
      "dnssec_status": "signed"
    }
  ]
}
```

### Get Zone Records

```http
GET /api/v1/zones/{zone}/records
Authorization: Bearer <token>
```

### Add Zone

```http
POST /api/v1/zones
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "example.com.",
  "nameservers": ["ns1.example.com."],
  "admin_email": "admin.example.com.",
  "ttl": 3600
}
```

### Delete Zone

```http
DELETE /api/v1/zones/{zone}
Authorization: Bearer <token>
```

### Reload a Zone

```http
POST /api/v1/zones/reload?zone={zone}
Authorization: Bearer <token>
```

### Zone Actions

```http
GET    /api/v1/zones/{zone}           - Get zone details
DELETE /api/v1/zones/{zone}           - Delete zone
GET    /api/v1/zones/{zone}/records   - List records
POST   /api/v1/zones/{zone}/records   - Add record
PUT    /api/v1/zones/{zone}/records   - Update record
DELETE /api/v1/zones/{zone}/records   - Delete record
GET    /api/v1/zones/{zone}/export    - Export zone file
```

### Zone Transfers (AXFR/IXFR)

```http
GET /api/v1/zones/transfers
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "slave_zones": [
    {
      "zone": "example.com.",
      "masters": "192.0.2.53:53",
      "serial": 2024050101,
      "last_transfer": "2026-05-24T12:00:00Z",
      "status": "synced",
      "records": 42
    }
  ]
}
```

---

## 4. Cache

### Get Cache Stats

```http
GET /api/v1/cache/stats
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "hits": 15234,
  "misses": 1234,
  "size": 5432,
  "capacity": 10000,
  "hit_ratio": 0.925,
  "evictions": 12,
  "stale_hits": 45
}
```

### Flush Cache

Clear all cached entries.

```http
POST /api/v1/cache/flush
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{"flushed": 5432}
```

---

## 5. Cluster

### Get Cluster Status

```http
GET /api/v1/cluster/status
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "enabled": true,
  "mode": "swim",
  "node_id": "node-1",
  "nodes": 3,
  "leader": "node-1",
  "cache_sync": true,
  "gossip_port": 7946
}
```

### Get Cluster Nodes

```http
GET /api/v1/cluster/nodes
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "nodes": [
    {
      "id": "node-1",
      "addr": "172.28.0.10:7946",
      "state": "alive",
      "region": "us-east",
      "health": {
        "queries_per_sec": 1000,
        "cache_hit_ratio": 0.95,
        "latency_ms_p99": 5,
        "uptime_seconds": 86400
      },
      "last_seen": "2024-05-02T10:30:00Z"
    },
    {
      "id": "node-2",
      "addr": "172.28.0.11:7946",
      "state": "alive",
      "region": "us-west",
      "health": {...}
    }
  ]
}
```

### Join Cluster

Requires admin role. Supported for SWIM/gossip clusters.

```http
POST /api/v1/cluster/join
Authorization: Bearer <token>
Content-Type: application/json

{
  "seed_address": "node-1.example.com:7946"
}
```

**Response** (200 OK):
```json
{
  "message": "Joined cluster via node-1.example.com:7946"
}
```

### Leave Cluster

Requires admin role. The node drains in-flight work before leaving.

```http
DELETE /api/v1/cluster/leave
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "message": "Node left cluster gracefully"
}
```

---

## 6. Blocklist & RPZ

### List Blocklists

```http
GET /api/v1/blocklists
Authorization: Bearer <token>
```

### Get Blocklist

```http
GET /api/v1/blocklists/{name}
Authorization: Bearer <token>
```

### Add Blocklist Source

```http
POST /api/v1/blocklists
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "ads",
  "type": "hosts",
  "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "refresh": 86400
}
```

### Delete Blocklist

```http
DELETE /api/v1/blocklists/{name}
Authorization: Bearer <token>
```

### Blocklist Actions

```http
POST   /api/v1/blocklists/{name}/reload - Reload blocklist
GET    /api/v1/blocklists/{name}/stats   - Get blocklist stats
```

### RPZ Status

```http
GET /api/v1/rpz
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "enabled": true,
  "zones": [
    {
      "name": "rpz.example.com",
      "rules_count": 1500,
      "policy": "nxdomain"
    }
  ]
}
```

### RPZ Rules

```http
GET /api/v1/rpz/rules
Authorization: Bearer <token>
```

### Add RPZ Rule

```http
POST /api/v1/rpz/rules
Authorization: Bearer <token>
Content-Type: application/json

{
  "zone": "rpz.example.com",
  "rule": "ads.example.com",
  "action": "nxdomain"
}
```

### RPZ Actions

```http
GET    /api/v1/rpz/{zone}     - Get RPZ zone details
DELETE /api/v1/rpz/{zone}     - Delete RPZ zone
POST   /api/v1/rpz/{zone}/reload - Reload RPZ zone
```

---

## 7. Security (ACL)

### Get ACL

```http
GET /api/v1/acl
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "rules": [
    {"name": "allow-rfc1918-a", "action": "allow", "networks": ["10.0.0.0/8"], "types": ["ANY"]},
    {"name": "allow-rfc1918-b", "action": "allow", "networks": ["172.16.0.0/12"], "types": ["ANY"]},
    {"name": "deny-test-net", "action": "deny", "networks": ["192.0.2.0/24"], "types": ["ANY"]}
  ]
}
```

### Update ACL

```http
PUT /api/v1/acl
Authorization: Bearer <token>
Content-Type: application/json

{
  "rules": [
    {"name": "allow-rfc1918-a", "action": "allow", "networks": ["10.0.0.0/8"], "types": ["ANY"]},
    {"name": "allow-rfc1918-b", "action": "allow", "networks": ["172.16.0.0/12"], "types": ["ANY"]}
  ]
}
```

---

## 8. DNSSEC

### Get DNSSEC Status

```http
GET /api/v1/dnssec/status
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "enabled": true,
  "signing_enabled": true,
  "algorithm": "ecdsap256sha256",
  "zones": [
    {
      "zone": "example.com",
      "signed": true,
      "dnskey_count": 2,
      "ds_count": 1,
      "nsec3": false,
      "next_rollover": "2024-06-01T00:00:00Z"
    }
  ]
}
```

### Get DNSSEC Keys

```http
GET /api/v1/dnssec/keys
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "keys": [
    {
      "zone": "example.com",
      "key_type": "ksk",
      "algorithm": "ecdsap256sha256",
      "key_tag": 12345,
      "bits": 256,
      "created": "2024-01-01T00:00:00Z",
      "active": true
    }
  ]
}
```

---

## 9. Upstreams

### Get Upstreams

```http
GET /api/v1/upstreams
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "strategy": "round_robin",
  "upstreams": [
    {
      "addr": "1.1.1.1:53",
      "status": "healthy",
      "latency_ms": 15,
      "queries": 5000,
      "errors": 0
    },
    {
      "addr": "8.8.8.8:53",
      "status": "healthy",
      "latency_ms": 25,
      "queries": 4500,
      "errors": 2
    }
  ]
}
```

### GeoDNS Stats

```http
GET /api/v1/geoip/stats
Authorization: Bearer <token>
```

---

## 10. Config

### Get Config

```http
GET /api/v1/config
Authorization: Bearer <token>
```

### Reload Config

```http
POST /api/v1/config/reload
Authorization: Bearer <token>
```

### Update Logging Config

```http
PUT /api/v1/config/logging
Authorization: Bearer <token>
Content-Type: application/json

{
  "level": "debug",
  "format": "json"
}
```

### Update RRL Config

```http
PUT /api/v1/config/rrl
Authorization: Bearer <token>
Content-Type: application/json

{
  "enabled": true,
  "rate": 100,
  "burst": 200
}
```

### Update Cache Config

```http
PUT /api/v1/config/cache
Authorization: Bearer <token>
Content-Type: application/json

{
  "size": 10000,
  "min_ttl": 300,
  "max_ttl": 86400
}
```

### Get Server Config

```http
GET /api/v1/server/config
Authorization: Bearer <token>
```

---

## 11. Metrics & Logs

### Prometheus Metrics

```http
GET /metrics
```

**Response** (200 OK, text/plain):
```
# HELP nothingdns_queries_total Total DNS queries
# TYPE nothingdns_queries_total counter
nothingdns_queries_total{qtype="A"} 15234
nothingdns_queries_total{qtype="AAAA"} 5234

# HELP nothingdns_cache_hits_total Cache hits
# TYPE nothingdns_cache_hits_total counter
nothingdns_cache_hits_total 14200

# HELP nothingdns_latency_seconds DNS query latency
# TYPE nothingdns_latency_seconds histogram
nothingdns_latency_seconds_bucket{le="0.005"} 10000
nothingdns_latency_seconds_bucket{le="0.01"} 15000
```

### Historical Metrics

```http
GET /api/v1/metrics/history?from=2024-05-01T00:00:00Z&to=2024-05-02T00:00:00Z
Authorization: Bearer <token>
```

### Query Log

```http
GET /api/v1/queries?limit=100&offset=0
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "queries": [
    {
      "id": "abc123",
      "timestamp": "2024-05-02T10:30:00Z",
      "client": "192.168.1.100",
      "qname": "example.com",
      "qtype": "A",
      "rcode": "NOERROR",
      "latency_ms": 5,
      "cached": true
    }
  ],
  "total": 1500
}
```

### Top Domains

```http
GET /api/v1/topdomains?limit=10&period=1h
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "domains": [
    {"qname": "api.example.com", "count": 5000},
    {"qname": "cdn.example.com", "count": 3500}
  ],
  "period": "1h"
}
```

---

## 12. Dashboard

### Dashboard Stats

```http
GET /api/dashboard/stats
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "queries_total": 25000,
  "queries_per_sec": 15,
  "cache_hit_ratio": 0.92,
  "uptime": 86400,
  "nodes": 3,
  "zones": 12,
  "blocked": 150
}
```

### Dashboard Queries (WebSocket)

Real-time query feed via WebSocket.

```http
GET /ws
```

**WebSocket Message**:
```json
{
  "type": "query",
  "data": {
    "qname": "example.com",
    "qtype": "A",
    "client": "192.168.1.100",
    "rcode": "NOERROR",
    "cached": false,
    "latency_ms": 12
  }
}
```

### Dashboard Zones

```http
GET /api/dashboard/zones
Authorization: Bearer <token>
```

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "invalid_request",
  "message": "Invalid zone name format"
}
```

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Invalid or expired token"
}
```

### 403 Forbidden
```json
{
  "error": "forbidden",
  "message": "Insufficient permissions"
}
```

### 404 Not Found
```json
{
  "error": "not_found",
  "message": "Zone not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "internal_error",
  "message": "Failed to reload zones"
}
```

---

## Rate Limiting

- **Login**: 5 attempts per 5 minutes per IP
- **API**: 100 requests per minute per IP
- **Exceed limit**: `429 Too Many Requests`

---

## OpenAPI Spec

JSON OpenAPI specification available at:
```http
GET /api/openapi.json
```

Swagger UI available at:
```http
GET /api/docs
```
