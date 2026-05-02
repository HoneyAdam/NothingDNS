# DNSSEC Package

DNSSEC validation, signing, and key management following RFC 4033/4034/4035.

## Overview

Full DNSSEC support for authoritative zones and recursive resolution:
- **Validation**: Verify signatures on responses
- **Signing**: Sign zones with NSEC or NSEC3
- **Key Rollover**: ZSK and KSK key management

## Validation

### Validator

```go
type Validator struct {
    trustAnchors []*TrustAnchor
    clock        clock.Clock
    cache        *ValidationCache
}
```

**Validation Result**:
```go
type ValidationResult int
const (
    Secure       ValidationResult = iota  // Validated successfully
    Bogus                                // Validation failed
    Insecure                             // No chain to trust anchor
    Indeterminate                        // Cannot determine
)
```

### Trust Anchors

```go
type TrustAnchor struct {
    Type     AnchorType  // Hint, KSK, DS
    KeyTag   uint16
    Algorithm uint8
    Digest   []byte      // For DS type
    DNSKEY   []byte      // For KSK type
}
```

**RFC 5011 Maintenance**: Automatic trust anchor updates for the root zone.

## Signing

### Signer

```go
type Signer struct {
    zone       *zone.Zone
    keys       []*DNSKEY
    nsec3      *NSEC3Config
    sigValid   time.Duration
    sigRefresh time.Duration
}
```

**NSEC vs NSEC3**:
- **NSEC**: Plaintext denial of existence (RFC 4034)
- **NSEC3**: Hashed denial with opt-out (RFC 5155)

### NSEC3 Configuration

```go
type NSEC3Config struct {
    Enabled    bool
    HashAlg    uint8      // SHA-1 (1)
    Iterations int         // RFC 9276 guidance
    SaltLength int
    OptOut     bool        // For large delegations
}
```

## Key Management

### Key Store

```go
type KeyStore struct {
    keys   map[uint16]*DNSKEY  // keytag -> key
    policy KeyPolicy
}
```

### Key Rollover

Supported methods:

**ZSK Rollover**:
- **Pre-Publish** (RFC 7583): Publish new key before activating
- **Double-Signature**: Sign with both old and new, then remove old

**KSK Rollover**:
- **Double-RRset**: Add new KSK to DNSKEY, update DS in parent

### Key Generation

```go
type KeyGenConfig struct {
    Algorithm  string  // rsasha256, rsasha512, ecdsap256sha256, ecdsap384sha384, ed25519
    KSKSize    int     // For RSA
    ZSKSize    int
}
```

## Supported Algorithms

| Algorithm | Code | DNSSEC Profile |
|-----------|------|----------------|
| RSASHA256 | 8 | Mandatory |
| RSASHA512 | 10 | Recommended |
| ECDSAP256SHA256 | 13 | Mandatory |
| ECDSAP384SHA384 | 14 | Optional |
| ED25519 | 15 | Recommended |

## Validation Process

```
1. Extract DNSKEY RRset from response
2. Match DNSKEY to known trust anchor (via DS or hint)
3. Verify DNSKEY signature using DNSKEY
4. Find relevant RRsets for query
5. Verify RRSIG for each RRset
6. Check NSEC/NSEC3 for negative validation
7. Return Secure/Bogus/Insecure/Indeterminate
```

## Signature Validation

```go
func (v *Validator) VerifySignature(rrsig *RRSIG, rrset []RR, dnskey *DNSKEY) error {
    // RFC 4035 §5.3.3
    // 1. Check inception/expiration
    // 2. Check algorithm matches
    // 3. Check key tag matches
    // 4. Verify cryptographic signature
}
```

## NSEC/NSEC3 Validation

### NSEC (RFC 4034)

```
Query: nx.example.com

NSEC: example.com → ns1.example.com (next)
      (no A record for nx.example.com)

Result: NXDOMAIN (proven by NSEC)
```

### NSEC3 (RFC 5155)

```
Query: nx.example.com

NSEC3: 0p9hc000000... → 0p9hc999999... (covers nx)
       (labels: 3 hash iterations + salt)

Result: NXDOMAIN (proven by NSEC3)
```

## Validation Cache

```go
type ValidationCache struct {
    cache *ttlcache.Cache
}
```

Caches validation results to avoid repeated validation:
- Key: `qname|qtype|qclass|result`
- TTL: Same as response TTL

## Performance

- **Validation caching**: Avoid re-validating same queries
- **NSEC3 iteration limit**: RFC 9276 recommends ≤ 150
- **Precomputed NSEC3 hashes**: For frequently queried names
- **Batch signature verification**: For large RRsets

## Integration

```go
// In handler.go
if h.validator != nil {
    result, ad := h.validator.Validate(ctx, response, q)
    if result == Bogus {
        return SERVFAIL
    }
    if ad {
        header.Flags |= AD
    }
}
```

## Security Considerations

- **Algorithm security**: Only modern algorithms (RSA 2048+, ECDSA, Ed25519)
- **Key generation**: Secure random number generation
- **Signature timing**: Constant-time verification to prevent timing attacks
- **NSEC3 opt-out**: Reduces cost for unsigned delegations