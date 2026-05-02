# Protocol Package

DNS wire protocol implementation following RFC 1035 and extensions.

## Overview

This package provides the core DNS message parsing and serialization functionality used by all transport layers (UDP, TCP, TLS, DoH, DoQ).

## Key Components

### Message (`message.go`)

The central `Message` struct represents a complete DNS message:

```go
type Message struct {
    Header      Header
    Questions  []*Question
    Answers    []*ResourceRecord
    Authorities []*ResourceRecord
    Additionals []*ResourceRecord
}
```

**Key Methods**:
- `Pack([]byte) (int, error)` — Serialize to wire format with name compression
- `UnpackMessage([]byte) error` — Parse wire format message
- `WireLength() int` — Calculate wire format size
- `Truncate(int) error` — RFC 7767 truncation (record-boundary-aware)
- `Release()` — Return to `sync.Pool` for reuse

### Header (`header.go`)

DNS header structure (12 bytes):

```go
type Header struct {
    ID      uint16      // Transaction ID
    Flags   HeaderFlags // QR, OPCODE, AA, TC, RD, RA, Z, RCODE
    QDCount uint16      // Question count
    ANCount uint16      // Answer count
    NSCount uint16      // Authority count
    ARCount uint16      // Additional count
}
```

### Name (`labels.go`, `wire.go`)

Domain name handling with:
- Label compression (pointer support)
- Canonical Wire Format encoding (RFC 4034)
- `CanonicalWireName()` for DNSSEC

### Question (`question.go`)

Single question in a DNS query:
```go
type Question struct {
    Name  *Name
    QType uint16   // A, AAAA, MX, TXT, etc.
    Class uint16   // IN (Internet), etc.
}
```

### Resource Records (`record.go`)

Standard DNS resource records with RDATA handling.

## Performance Features

- **`sync.Pool`** for message and buffer reuse
- **Compression map pooling** via `compressionPool`
- **Per-section record limits**: 256 questions, 512 answers/authorities/additionals
- **Maximum message size** validation during parsing

## Record Types Supported

### Standard Types
`A`, `NS`, `CNAME`, `SOA`, `MB`, `MG`, `MR`, `NULL`, `WKS`, `PTR`, `HINFO`, `MINFO`, `MX`, `TXT`, `SPF`, `AAAA`, `SRV`, `NAPTR`, `OPT`

### DNSSEC Types
`DNSKEY` (48), `RRSIG` (46), `NSEC` (47), `NSEC3` (50), `NSEC3PARAM` (51), `DS` (43), `TLSA` (52)

### EDNS0 Types
`OPT` (41) with options: `Cookie` (10), `ClientSubnet` (8), `Padding` (12), `Chain` (13)

## Extended DNS Errors

RFC 8914 Extended DNS Errors (EDE) with info codes from `ede.go`.

## Constants

All record type, RCODE, and option constants are defined in `constants.go`:
- `TypeA`, `TypeAAAA`, `TypeMX`, `TypeNS`, `TypeSOA`, etc.
- `RcodeSuccess`, `RcodeFormatError`, `RcodeServerFailure`, etc.
- `OptionCodeCookie`, `OptionCodeClientSubnet`, etc.

## Security Considerations

- **VULN-059**: TXID is re-randomized before upstream forwarding
- **VULN-060**: DO bit included in cache key
- Per-record TTL validation
- Bounds checking on all wire format parsing