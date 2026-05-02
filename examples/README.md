# Zone File Examples

This directory contains example zone files for NothingDNS. Copy them to your zone directory (default: `/etc/nothingdns/zones/`) and reference them in your `config.yaml`.

## Files

| File | Description |
|------|-------------|
| `example.com.zone` | Forward zone for public domain with standard DNS records |
| `internal.example.com.zone` | Split-horizon zone for internal/private network |
| `10.0.0.0-8.rev.zone` | Reverse zone for RFC 1918 private network 10.0.0.0/8 |

## Quick Start

```bash
# Copy zones to the zone directory
cp examples/zones/example.com.zone /etc/nothingdns/zones/
cp examples/zones/internal.example.com.zone /etc/nothingdns/zones/
cp examples/zones/10.0.0.0-8.rev.zone /etc/nothingdns/zones/

# Reference in config.yaml
zones:
  - name: example.com
    file: /etc/nothingdns/zones/example.com.zone
  - name: internal.example.com
    file: /etc/nothingdns/zones/internal.example.com.zone
  - name: 0.0.10.in-addr.arpa
    file: /etc/nothingdns/zones/10.0.0.0-8.rev.zone

# Validate configuration
./nothingdns --config /etc/nothingdns/nothingdns.yaml --validate-config

# Reload zones (if server already running)
./dnsctl zone reload example.com
```

## Zone File Format

All zone files use standard BIND format (RFC 1035). See `docs/CONFIG_REFERENCE.md` for full syntax documentation.

### Key Elements

- `$ORIGIN` — sets the default domain for relative names
- `$TTL` — default TTL for all records
- `SOA` — Start of Authority record (serial, refresh, retry, expire, minimum)
- `NS` — Name Server records
- `A` — IPv4 address records
- `AAAA` — IPv6 address records
- `CNAME` — Canonical name aliases
- `MX` — Mail exchange records
- `TXT` — Text records (SPF, DKIM, etc.)
- `$GENERATE` — range-based record generation

## Record Types Reference

| Type | Purpose | Example |
|------|---------|---------|
| A | IPv4 address | `www IN A 192.0.2.1` |
| AAAA | IPv6 address | `www IN AAAA 2001:db8::1` |
| CNAME | Alias | `www IN CNAME web.svc.local` |
| MX | Mail exchange | `@ IN MX 10 mail.example.com.` |
| NS | Nameserver | `@ IN NS ns1.example.com.` |
| TXT | Text data | `@ IN TXT "v=spf1 mx ~all"` |
| PTR | Reverse DNS | `1.0.0.10.in-addr.arpa. IN PTR host.example.com.` |
| SRV | Service locator | `_http._tcp IN SRV 0 5 80 web.svc.local.` |
| CAA | Certificate authority authorization | `@ IN CAA 0 issue "letsencrypt.org"` |

## Split-Horizon DNS

`internal.example.com.zone` demonstrates split-horizon configuration. The same domain resolves to different addresses depending on the requesting client IP:

```
; Public view: returns public IPs
www IN A 203.0.113.10

; Internal view (configured via views.yaml): returns RFC 1918 addresses
; 10.0.0.0/8 clients get 10.0.1.50
```

Configure split-horizon views in `config.yaml`:

```yaml
views:
  - name: internal
    match-clients: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
    zones:
      - name: internal.example.com
        file: /etc/nothingdns/zones/internal.example.com.zone
```

## Dynamic Updates

Zone files support RFC 2136 Dynamic Updates. Use `dnsctl record add` for programmatic updates:

```bash
# Add a record
dnsctl record add example.com newhost A 192.0.2.50

# Remove a record
dnsctl record remove example.com oldhost A

# Update a record
dnsctl record update example.com existinghost A 192.0.2.100
```

## DNSSEC Signing

Sign zones using the dnssec commands:

```bash
# Generate keys
dnsctl dnssec generate-key --algorithm 13 --type ZSK --zone example.com
dnsctl dnssec generate-key --algorithm 13 --type KSK --zone example.com

# Sign the zone
dnsctl dnssec sign-zone --zone example.com

# Publish DS records to your parent zone
dnsctl dnssec ds-from-dnskey --zone example.com
```

## Zone Transfer (AXFR)

NothingDNS supports AXFR (RFC 5936) for secondary nameservers:

```bash
# Allow transfer from secondary servers
# In config.yaml:
zones:
  - name: example.com
    file: /etc/nothingdns/zones/example.com.zone
    allow-transfer:
      - 198.51.100.0/24
      - 203.0.113.0/24

# Trigger a zone transfer
dig @localhost example.com AXFR
```

## Monitoring Zone Status

```bash
# List all zones
dnsctl zone list

# Export zone to BIND format
dnsctl zone export example.com

# Reload a zone after manual edits
dnsctl zone reload example.com

# Check server status
dnsctl server status
```

## See Also

- `docs/CONFIG_REFERENCE.md` — Full configuration reference
- `docs/CLI_REFERENCE.md` — dnsctl command documentation
- `docs/ARCHITECTURE.md` — Zone management in the request pipeline