# NothingDNS Zone Management API Reference

> Complete reference for zone management endpoints
> Base URL: `http://localhost:8080/api/v1`
> Authentication: Bearer token required (see [Authentication](#authentication))

---

## Authentication

All zone management endpoints require authentication via Bearer token.

**Header:**
```
Authorization: Bearer <token>
```

**Roles:**
| Role | Permissions |
|------|-------------|
| `admin` | Full access to all zone operations |
| `operator` | Can create/modify/delete zones and records |
| `viewer` | Read-only access |

---

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/zones` | List all zones |
| `POST` | `/zones` | Create a new zone |
| `GET` | `/zones/{name}` | Get zone details |
| `DELETE` | `/zones/{name}` | Delete a zone |
| `GET` | `/zones/{name}/records` | List zone records |
| `POST` | `/zones/{name}/records` | Add a record |
| `PUT` | `/zones/{name}/records` | Update a record |
| `DELETE` | `/zones/{name}/records` | Delete a record |
| `GET` | `/zones/{name}/export` | Export zone (BIND format) |
| `POST` | `/zones/{name}/ptr-bulk` | Bulk PTR record generation |
| `GET` | `/zones/{name}/ptr6-lookup` | IPv6 reverse lookup |
| `POST` | `/zones/reload` | Reload a zone |

---

## GET /zones

List all configured zones.

### Request

```http
GET /api/v1/zones
Authorization: Bearer <token>
```

### Response

**200 OK**
```json
{
  "zones": [
    {
      "name": "example.com.",
      "serial": 2026050401,
      "records": 47
    },
    {
      "name": "example.net.",
      "serial": 2026050301,
      "records": 23
    }
  ],
  "total": 2,
  "truncated": false
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `zones` | array | Zone entries returned by the request, capped at 5000 |
| `zones[].name` | string | Zone origin (FQDN with trailing dot) |
| `zones[].serial` | uint32 | Current SOA serial number |
| `zones[].records` | int | Total number of records in zone |
| `total` | int | Unfiltered zone count |
| `truncated` | bool | Present/true when the response was capped |

---

## POST /zones

Create a new authoritative zone.

### Request

```http
POST /api/v1/zones
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "example.com.",
  "ttl": 3600,
  "admin_email": "admin@example.com",
  "nameservers": ["ns1.example.com.", "ns2.example.com."]
}
```

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Zone origin (FQDN, should end with `.`) |
| `ttl` | uint32 | No | Default TTL for records (default: 3600) |
| `admin_email` | string | No | RNAME field (default: `admin.@`) |
| `nameservers` | array | **Yes** | List of nameservers (at least 1 required) |

### Response

**201 Created**
```json
{
  "message": "Zone example.com. created",
  "name": "example.com."
}
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `400` | `Zone name is required` | Missing zone name |
| `400` | `At least one nameserver is required` | No nameservers provided |
| `401` | `Unauthorized` | Missing or invalid token |
| `403` | `Forbidden` | Insufficient role permissions |
| `409` | `Failed to create zone` | Zone already exists or other error |

---

## GET /zones/{name}

Get detailed information about a specific zone.

### Request

```http
GET /api/v1/zones/example.com.
Authorization: Bearer <token>
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Zone name (URL-encoded) |

### Response

**200 OK**
```json
{
  "name": "example.com.",
  "serial": 2026050401,
  "records": 47,
  "soa": {
    "mname": "ns1.example.com.",
    "rname": "admin.example.com.",
    "serial": 2026050401,
    "refresh": 3600,
    "retry": 600,
    "expire": 604800,
    "minimum": 86400
  },
  "nameservers": ["ns1.example.com.", "ns2.example.com."]
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Zone origin |
| `serial` | uint32 | Current SOA serial |
| `records` | int | Total record count |
| `soa` | object | SOA record details (if present) |
| `soa.mname` | string | Primary nameserver |
| `soa.rname` | email | Responsible person (RFC 1035) |
| `soa.refresh` | uint32 | Refresh interval (seconds) |
| `soa.retry` | uint32 | Retry interval (seconds) |
| `soa.expire` | uint32 | Expire interval (seconds) |
| `soa.minimum` | uint32 | Minimum TTL (seconds) |
| `nameservers` | array | Delegated nameservers |

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `404` | `Zone example.com. not found` | Zone does not exist |

---

## DELETE /zones/{name}

Delete a zone and all its records.

### Request

```http
DELETE /api/v1/zones/example.com.
Authorization: Bearer <token>
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Zone name (URL-encoded) |

### Response

**200 OK**
```json
{
  "message": "Zone example.com. deleted"
}
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `404` | `Failed to delete zone` | Zone does not exist |
| `403` | `Forbidden` | Operator role required |

---

## GET /zones/{name}/records

List all records in a zone, optionally filtered by name.

### Request

```http
GET /api/v1/zones/example.com./records?name=www
Authorization: Bearer <token>
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Zone name (URL-encoded) |

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | No | Filter records by name prefix |

### Response

**200 OK**
```json
{
  "records": [
    {
      "name": "www.example.com.",
      "type": "A",
      "ttl": 3600,
      "class": "IN",
      "data": "192.0.2.1"
    },
    {
      "name": "www.example.com.",
      "type": "AAAA",
      "ttl": 3600,
      "class": "IN",
      "data": "2001:db8::1"
    }
  ]
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `records` | array | List of DNS records |
| `records[].name` | string | Record name (FQDN) |
| `records[].type` | string | Record type (A, AAAA, CNAME, etc.) |
| `records[].ttl` | uint32 | Time-to-live in seconds |
| `records[].class` | string | DNS class (IN, CH, HS) |
| `records[].data` | string | Record data (RDATA) |

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `404` | `Zone not found` | Zone does not exist |

---

## POST /zones/{name}/records

Add a new DNS record to a zone.

### Request

```http
POST /api/v1/zones/example.com./records
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "www.example.com.",
  "type": "A",
  "ttl": 3600,
  "data": "192.0.2.1"
}
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Zone name (URL-encoded) |

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Record name (FQDN) |
| `type` | string | **Yes** | Record type (A, AAAA, CNAME, MX, TXT, etc.) |
| `ttl` | uint32 | No | TTL in seconds (default: zone's default TTL or 3600) |
| `data` | string | **Yes** | Record data (RDATA) |

### Supported Record Types

| Type | Data Format | Example |
|------|-------------|---------|
| `A` | IPv4 address | `192.0.2.1` |
| `AAAA` | IPv6 address | `2001:db8::1` |
| `CNAME` | FQDN | `www.example.com.` |
| `MX` | Priority + FQDN | `10 mail.example.com.` |
| `TXT` | Quoted string | `"v=spf1 include:_spf.example.com -all"` |
| `NS` | FQDN | `ns1.example.com.` |
| `PTR` | FQDN | `www.example.com.` |
| `SOA` | See zone creation | (auto-created) |
| `SRV` | Priority Weight Port Target | `10 5 5269 xmpp.example.com.` |
| `CAA` | Flags Tag Value | `0 issue "letsencrypt.org"` |
| `DNAME` | FQDN | `alias.example.com.` |

### Response

**201 Created**
```json
{
  "message": "Record added"
}
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `400` | `name, type, and data are required` | Missing required fields |
| `400` | `Invalid JSON` | Malformed request body |
| `403` | `Forbidden` | Operator role required |
| `404` | `Not found` | Zone not found |

---

## PUT /zones/{name}/records

Update an existing DNS record.

### Request

```http
PUT /api/v1/zones/example.com./records
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "www.example.com.",
  "type": "A",
  "old_data": "192.0.2.1",
  "ttl": 7200,
  "data": "192.0.2.2"
}
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Zone name (URL-encoded) |

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Record name (FQDN) |
| `type` | string | **Yes** | Record type |
| `old_data` | string | **Yes** | Current RDATA value (for matching) |
| `ttl` | uint32 | No | New TTL (0 = unchanged) |
| `data` | string | **Yes** | New RDATA value |

### Response

**200 OK**
```json
{
  "message": "Record updated"
}
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `400` | `name and type are required` | Missing required fields |
| `403` | `Forbidden` | Operator role required |
| `404` | `Not found` | Zone or record not found |

---

## DELETE /zones/{name}/records

Delete all records matching name and type.

### Request

```http
DELETE /api/v1/zones/example.com./records
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "www.example.com.",
  "type": "A"
}
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Zone name (URL-encoded) |

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Record name (FQDN) |
| `type` | string | **Yes** | Record type |

### Response

**200 OK**
```json
{
  "message": "Record deleted"
}
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `400` | `name and type are required` | Missing required fields |
| `403` | `Forbidden` | Operator role required |
| `404` | `Not found` | Zone or record not found |

---

## GET /zones/{name}/export

Export a zone in BIND (standard zone file) format.

### Request

```http
GET /api/v1/zones/example.com./export
Authorization: Bearer <token>
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Zone name (URL-encoded) |

### Response

**200 OK**
```http
Content-Type: text/plain; charset=utf-8
Content-Disposition: attachment; filename="example.com.zone"

$ORIGIN example.com.
$TTL 3600

@       IN      SOA     ns1.example.com. admin.example.com. (
                        2026050401 ; serial
                        3600       ; refresh
                        600        ; retry
                        604800     ; expire
                        86400      ; minimum
                        )

@       IN      NS      ns1.example.com.
@       IN      NS      ns2.example.com.
@       IN      A       192.0.2.1
www     IN      A       192.0.2.1
www     IN      AAAA    2001:db8::1
mail    IN      A       192.0.2.2
@       IN      MX      10 mail.example.com.
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `404` | `Not found` | Zone not found |

---

## POST /zones/{name}/ptr-bulk

Generate PTR (and optionally A) records for an IPv4 CIDR range using a pattern.

### Request (Preview Mode)

```http
POST /api/v1/zones/2.0.192.in-addr.arpa./ptr-bulk
Authorization: Bearer <token>
Content-Type: application/json

{
  "cidr": "192.0.2.0/24",
  "pattern": "host-[D].[C].[B].[A].static.example.com",
  "addA": true,
  "preview": true
}
```

### Request (Apply Mode)

```http
POST /api/v1/zones/2.0.192.in-addr.arpa./ptr-bulk
Authorization: Bearer <token>
Content-Type: application/json

{
  "cidr": "192.0.2.0/24",
  "pattern": "host-[D].[C].[B].[A].static.example.com",
  "addA": true,
  "override": false
}
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Reverse zone name (e.g., `2.0.192.in-addr.arpa.`) |

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cidr` | string | **Yes** | IPv4 CIDR range (max /16) |
| `pattern` | string | **Yes** | PTR name pattern with `[A]`, `[B]`, `[C]`, `[D]` placeholders |
| `addA` | bool | No | Also create forward A records (default: false) |
| `override` | bool | No | Overwrite existing records (default: false) |
| `preview` | bool | No | Return changes without applying (default: false) |

### Pattern Placeholders

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `[A]` | First octet | `192` from `192.0.2.1` |
| `[B]` | Second octet | `0` from `192.0.2.1` |
| `[C]` | Third octet | `2` from `192.0.2.1` |
| `[D]` | Fourth octet | `1` from `192.0.2.1` |

### Preview Response

**200 OK**
```json
{
  "preview": true,
  "total": 256,
  "willAdd": 256,
  "willAddA": 256,
  "willSkip": 0,
  "willOverride": 0,
  "changes": [
    {
      "ip": "192.0.2.1",
      "ptrName": "host-1.2.0.192.static.example.com",
      "aName": "host-1.2.0.192.static.example.com",
      "action": "add",
      "ptrExist": false,
      "aExist": false,
      "revRecord": "1.2.0.192.in-addr.arpa."
    }
  ]
}
```

### Apply Response

**200 OK**
```json
{
  "added": 256,
  "addedA": 256,
  "exists": 0,
  "existsA": 0,
  "skipped": 0
}
```

### Response Fields (Apply)

| Field | Type | Description |
|-------|------|-------------|
| `added` | int | PTR records created |
| `addedA` | int | A records created |
| `exists` | int | PTR records already existed |
| `existsA` | int | A records already existed |
| `skipped` | int | Records skipped (existing, no override) |

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `400` | `cidr and pattern are required` | Missing fields |
| `400` | `Only IPv4 CIDR is supported` | IPv6 not supported |
| `400` | `CIDR too large (max /16)` | Exceeds 65536 IPs |
| `400` | `Pattern must contain [A], [B], [C], [D]` | Invalid pattern |
| `403` | `Forbidden` | Operator role required |
| `404` | `Zone not found` | Zone does not exist |

---

## GET /zones/{name}/ptr6-lookup

Perform IPv6 reverse DNS lookup query (does not create records).

### Request

```http
GET /api/v1/zones/1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa./ptr6-lookup?ip=2001:db8::1
Authorization: Bearer <token>
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | IPv6 reverse zone (must end with `ip6.arpa.`) |

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | **Yes** | IPv6 address to lookup |

### Response (Found)

**200 OK**
```json
{
  "ip": "2001:db8::1",
  "ptr": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
  "ptrFQDN": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
  "target": "www.example.com.",
  "ttl": 3600,
  "found": true
}
```

### Response (Not Found)

**200 OK**
```json
{
  "ip": "2001:db8::1",
  "ptr": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
  "ptrFQDN": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
  "found": false
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | Input IPv6 address |
| `ptr` | string | Computed PTR record name |
| `ptrFQDN` | string | Fully-qualified PTR name |
| `target` | string | PTR target (if found) |
| `ttl` | uint32 | Record TTL (if found) |
| `found` | bool | Whether PTR record exists |

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `400` | `IP parameter is required` | Missing IP parameter |
| `400` | `Invalid IPv6 address` | Not a valid IPv6 |
| `400` | `Zone is not an IPv6 reverse zone` | Zone name doesn't end with `ip6.arpa.` |
| `404` | `Zone not found` | Zone does not exist |

---

## POST /zones/reload

Hot-reload a zone file from disk without restarting the server.

### Request

```http
POST /api/v1/zones/reload?zone=example.com.
Authorization: Bearer <token>
```

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `zone` | string | **Yes** | Zone name to reload |

### Response

**200 OK**
```json
{
  "message": "Zone example.com. reloaded"
}
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `400` | `Missing zone parameter` | No zone specified |
| `403` | `Forbidden` | Admin role required |
| `404` | `Failed to reload zone` | Zone not found or reload failed |

---

## Common Error Response Format

All endpoints return errors in this format:

```json
{
  "error": "Error description"
}
```

### HTTP Status Codes

| Status | Meaning |
|--------|---------|
| `200` | Success |
| `201` | Created |
| `400` | Bad Request (invalid input) |
| `401` | Unauthorized (missing token) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Not Found |
| `405` | Method Not Allowed |
| `409` | Conflict (e.g., zone already exists) |
| `413` | Payload Too Large (body exceeds 1MB limit) |
| `500` | Internal Server Error |
| `503` | Service Unavailable (zone manager not ready) |

---

## Security Notes

- **Global RBAC**: All operators have access to all zones. There is no per-zone isolation.
- **Input Validation**: Zone names are URL-decoded and sanitized before use.
- **Path Traversal**: Zone export filenames are sanitized (non-alphanumeric chars replaced with `_`).
- **Body Limits**: Request bodies are limited to 1MB via `MaxBytesReader`.
- **Audit Logging**: All zone operations are logged with client IP and request ID.

---

## Example: Complete Zone Workflow

### 1. Create a zone

```bash
curl -X POST http://localhost:8080/api/v1/zones \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com.",
    "ttl": 3600,
    "admin_email": "dns@example.com",
    "nameservers": ["ns1.example.com.", "ns2.example.com."]
  }'
```

### 2. Add records

```bash
# Add A record
curl -X POST http://localhost:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "www.example.com.", "type": "A", "ttl": 3600, "data": "192.0.2.1"}'

# Add MX record
curl -X POST http://localhost:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com.", "type": "MX", "ttl": 3600, "data": "10 mail.example.com."}'

# Add TXT record
curl -X POST http://localhost:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com.", "type": "TXT", "ttl": 3600, "data": "\"v=spf1 include:_spf.example.com -all\""}'
```

### 3. List zones and records

```bash
# List all zones
curl http://localhost:8080/api/v1/zones \
  -H "Authorization: Bearer $TOKEN"

# Get zone details
curl http://localhost:8080/api/v1/zones/example.com. \
  -H "Authorization: Bearer $TOKEN"

# List all records in zone
curl http://localhost:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN"

# Filter records by name
curl "http://localhost:8080/api/v1/zones/example.com./records?name=www" \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Export zone

```bash
curl http://localhost:8080/api/v1/zones/example.com./export \
  -H "Authorization: Bearer $TOKEN" \
  -o example.com.zone
```

### 5. Delete a record

```bash
curl -X DELETE http://localhost:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "www.example.com.", "type": "A"}'
```

### 6. Delete zone

```bash
curl -X DELETE http://localhost:8080/api/v1/zones/example.com. \
  -H "Authorization: Bearer $TOKEN"
```