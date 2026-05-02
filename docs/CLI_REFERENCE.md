# NothingDNS CLI Reference

`dnsctl` is the command-line management tool for NothingDNS. It communicates with the NothingDNS server via REST API.

## Usage

```bash
dnsctl [global-flags] <command> [command-flags] [arguments]
```

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `http://localhost:8080` | NothingDNS API server URL |
| `-api-key` | (empty) | API key for authentication |

### Examples

```bash
# Connect to local server (default)
dnsctl zone list

# Connect to remote server
dnsctl -server http://192.168.1.100:8080 zone list

# Use API key
dnsctl -api-key my-secret-key zone list
```

---

## zone — Zone Management

```bash
dnsctl zone [subcommand]
```

### zone list

List all configured zones.

```bash
dnsctl zone list
```

**Output**:
```
example.com.          3600    45 records   signed
internal.example.com. 1800    120 records  unsigned
```

### zone add

Add a new zone.

```bash
dnsctl zone add <zone-name> [--file=<zone-file>] [--ttl=<seconds>]
```

**Examples**:
```bash
dnsctl zone add example.com
dnsctl zone add example.com --file=/etc/nothingdns/zones/example.com.zone
dnsctl zone add example.com --ttl=3600
```

### zone remove

Remove a zone.

```bash
dnsctl zone remove <zone-name>
```

```bash
dnsctl zone remove example.com
```

### zone reload

Reload all zones from disk.

```bash
dnsctl zone reload
```

### zone export

Export zone to BIND format.

```bash
dnsctl zone export <zone-name> [--output=<file>]
```

```bash
dnsctl zone export example.com
dnsctl zone export example.com --output=example.com.bak
```

### zone verify

Verify zone configuration.

```bash
dnsctl zone verify <zone-name>
```

---

## record — Record Management

```bash
dnsctl record [subcommand]
```

### record add

Add a DNS record.

```bash
dnsctl record add <zone> <name> <type> <value> [--ttl=<seconds>]
```

**Examples**:
```bash
dnsctl record add example.com www A 192.168.1.100 --ttl=3600
dnsctl record add example.com @ MX "10 mail.example.com." --ttl=3600
dnsctl record add example.com _sip._tcp SRV "10 60 5060 sip.example.com."
dnsctl record add example.com mail TXT "v=spf1 mx ~all"
```

### record remove

Remove a DNS record.

```bash
dnsctl record remove <zone> <name> <type> [value]
```

```bash
dnsctl record remove example.com www A
dnsctl record remove example.com @ MX "10 mail.example.com."
```

### record update

Update a DNS record.

```bash
dnsctl record update <zone> <name> <type> <value> [--ttl=<seconds>]
```

### record list

List records in a zone.

```bash
dnsctl record list <zone> [--type=<type>] [--name=<pattern>]
```

```bash
dnsctl record list example.com
dnsctl record list example.com --type=A
dnsctl record list example.com --name="www*"
```

---

## cache — Cache Operations

```bash
dnsctl cache [subcommand]
```

### cache stats

Show cache statistics.

```bash
dnsctl cache stats
```

**Output**:
```
Cache Statistics
-----------------
Hits:         15,234
Misses:       1,234
Size:         5,432 / 10,000
Hit Ratio:    92.5%
Evictions:    12
Stale Hits:   45
```

### cache flush

Flush (clear) the cache.

```bash
dnsctl cache flush
```

### cache warm

Warm cache with popular domains.

```bash
dnsctl cache warm --file=<domain-list>
```

```bash
dnsctl cache warm --file=popular-domains.txt
```

---

## cluster — Cluster Management

```bash
dnsctl cluster [subcommand]
```

### cluster status

Show cluster status.

```bash
dnsctl cluster status
```

**Output**:
```
Cluster Status
--------------
Enabled:      Yes
Mode:         SWIM
Node ID:      node-1
Nodes:        3
Leader:       node-1
Cache Sync:   Enabled
```

### cluster nodes

List cluster nodes.

```bash
dnsctl cluster nodes
```

**Output**:
```
NODE     ADDR              STATE    REGION    QUERIES/S  CACHE-HIT  LATENCY
node-1   172.28.0.10:7946  Alive    us-east   1,000      95%        2ms
node-2   172.28.0.11:7946  Alive    us-west   950        94%        3ms
node-3   172.28.0.12:7946  Alive    eu-west   980        93%        4ms
```

### cluster join

Join a cluster (from seed node).

```bash
dnsctl cluster join <seed-node-addr>
```

### cluster leave

Leave the cluster gracefully.

```bash
dnsctl cluster leave
```

---

## blocklist — Blocklist Management

```bash
dnsctl blocklist [subcommand]
```

### blocklist status

Show blocklist status.

```bash
dnsctl blocklist status
```

### blocklist list

List configured blocklists.

```bash
dnsctl blocklist list
```

### blocklist add

Add a blocklist source.

```bash
dnsctl blocklist add <name> --url=<url> [--type=<type>]
```

**Examples**:
```bash
dnsctl blocklist add ads --url=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts --type=hosts
dnsctl blocklist add malware --url=https://urlhaus.abuse.ch/downloads/json/ --type=domain
```

### blocklist remove

Remove a blocklist.

```bash
dnsctl blocklist remove <name>
```

### blocklist reload

Reload all blocklists.

```bash
dnsctl blocklist reload
```

---

## config — Configuration

```bash
dnsctl config [subcommand]
```

### config get

Get current configuration.

```bash
dnsctl config get
```

### config set

Update configuration (partial update).

```bash
dnsctl config set <key>=<value> [--key=<value>...]
```

**Examples**:
```bash
dnsctl config set cache.size=20000
dnsctl config set logging.level=debug --key=cache.prefetch=true
```

### config reload

Reload configuration from file.

```bash
dnsctl config reload
```

### config validate

Validate configuration file.

```bash
dnsctl config validate [--file=<path>]
```

---

## dig — DNS Query Tool

A `dig`-compatible DNS query tool.

```bash
dnsctl dig [@server] [name] [type] [class] [options]
```

### Basic Queries

```bash
# A record
dnsctl dig example.com A

# AAAA record
dnsctl dig example.com AAAA

# MX record
dnsctl dig example.com MX

# TXT record
dnsctl dig example.com TXT

# SOA record
dnsctl dig example.com SOA
```

### Query Options

```bash
# Specific DNS server
dnsctl dig @1.1.1.1 example.com A

# DNSSEC validation
dnsctl dig +dnssec example.com A

# Check AD (Authentic Data) bit
dnsctl dig +ad example.com DNSKEY

# Short output
dnsctl dig +short example.com A

# TCP instead of UDP
dnsctl dig +tcp example.com A

# Trace delegation
dnsctl dig +trace example.com NS

# Reverse lookup
dnsctl dig -x 1.2.3.4
```

### Examples

```bash
# Full dig-compatible output
dnsctl dig example.com MX +multiline

# Time out after 5 seconds
dnsctl dig example.com A +time=5

# Use TCP
dnsctl dig example.com AXFR +tcp
```

---

## dnssec — DNSSEC Operations

```bash
dnsctl dnssec [subcommand]
```

### dnssec status

Show DNSSEC status.

```bash
dnsctl dnssec status
```

### dnssec generate-key

Generate DNSSEC key pair.

```bash
dnsctl dnssec generate-key --zone=<zone> [--algorithm=<algo>] [--bits=<size>] [--ksk|--zsk]
```

**Algorithms**: `rsasha256` (default), `rsasha512`, `ecdsap256sha256`, `ecdsap384sha384`, `ed25519`

**Examples**:
```bash
# Generate KSK
dnsctl dnssec generate-key --zone=example.com --ksk --algorithm=ecdsap256sha256

# Generate ZSK
dnsctl dnssec generate-key --zone=example.com --zsk --bits=1024
```

### dnssec sign-zone

Sign a zone.

```bash
dnsctl dnssec sign-zone --zone=<zone> [--active-keys]
```

```bash
dnsctl dnssec sign-zone --zone=example.com
```

### dnssec ds-from-dnskey

Get DS record from DNSKEY.

```bash
dnsctl dnssec ds-from-dnskey --zone=<zone> [--digest=<algorithm>]
```

**Algorithms**: `sha256` (default), `sha384`

```bash
dnsctl dnssec ds-from-dnskey --zone=example.com
dnsctl dnssec ds-from-dnskey --zone=example.com --digest=sha384
```

### dnssec verify

Verify DNSSEC signatures.

```bash
dnsctl dnssec verify --zone=<zone>
```

### dnssec key

Manage DNSSEC keys.

```bash
dnsctl dnssec key list --zone=<zone>
dnsctl dnssec key activate --zone=<zone> --key-id=<id>
dnsctl dnssec key deactivate --zone=<zone> --key-id=<id>
dnsctl dnssec key remove --zone=<zone> --key-id=<id>
```

---

## server — Server Operations

```bash
dnsctl server [subcommand]
```

### server status

Show server status.

```bash
dnsctl server status
```

**Output**:
```
NothingDNS Server Status
------------------------
Version:      1.0.0
Uptime:       2 days, 14:32:15
Go Version:   go1.26.2
Build Date:   2024-05-01
```

### server stats

Show server statistics.

```bash
dnsctl server stats
```

**Output**:
```
Server Statistics
------------------
Queries:       2,543,210
Cache Hits:    2,388,657 (93.9%)
Queries/Sec:   125
Uptime:        2 days
```

### server health

Check server health.

```bash
dnsctl server health
```

### server reload

Send SIGHUP to reload configuration.

```bash
dnsctl server reload
```

---

## Global Commands

### version

Show version information.

```bash
dnsctl version
```

**Output**:
```
dnsctl version 1.0.0
NothingDNS version 1.0.0
Go version go1.26.2
```

### help

Show help.

```bash
dnsctl help
dnsctl help <command>
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (see error message) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NOTHINGDNS_SERVER` | Default server URL |
| `NOTHINGDNS_API_KEY` | Default API key |

---

## Configuration File

`dnsctl` can read defaults from `~/.config/dnsctl/config.yaml`:

```yaml
server: http://localhost:8080
api_key: your-api-key
timeout: 30s
```

---

## Examples

### Common Workflows

```bash
# Check server is running
dnsctl server health

# View all zones
dnsctl zone list

# Add a new record
dnsctl record add example.com api A 192.168.1.50 --ttl=3600

# Check cache performance
dnsctl cache stats

# View cluster status
dnsctl cluster status

# Flush cache after config change
dnsctl cache flush

# Reload zones after editing zone file
dnsctl zone reload

# Verify DNSSEC is working
dnsctl dig +dnssec +ad example.com DNSKEY
```

### Scripting Examples

```bash
# Monitor queries per second
watch -n1 'dnsctl server stats | grep Queries'

# List all A records
dnsctl record list example.com --type=A

# Backup all zones
for zone in $(dnsctl zone list | awk '{print $1}'); do
  dnsctl zone export "$zone" > "${zone}.zone.bak"
done

# Check cache hit ratio
dnsctl cache stats | grep "Hit Ratio"
```