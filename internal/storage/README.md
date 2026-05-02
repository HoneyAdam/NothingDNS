# Storage Package

ACID key-value store with Write-Ahead Log (WAL) for durability and TLV serialization.

## Overview

Persistent storage for zones, cache, and runtime state with optional HMAC integrity protection.

## Components

### KVStore

BoltDB-style bucket-based key-value store:

```go
type KVStore struct {
    path     string
    dataFile string
    root     *bucketData
    txid     uint64
    hmacKey  []byte  // nil = legacy JSON mode
}
```

**Features**:
- Read/Write transactions
- Atomic save via temp file + rename
- Optional SHA-256 HMAC integrity protection
- Bucket-based organization

### WAL

Write-Ahead Log for crash recovery:

```go
type WAL struct {
    dir      string
    segments []string
    current  *os.File
}
```

**Entry Format**:
```
[4 bytes CRC32][1 byte type][4 bytes length][N bytes data]
```

**Entry Types**:
- `EntryTypePut` (0x01)
- `EntryTypeDelete` (0x02)
- `EntryTypeBegin` (0x10)
- `EntryTypeCommit` (0x11)
- `EntryTypeAbort` (0x12)
- `EntryTypeCheckpoint` (0x20)

**Features**:
- Segment rotation (64MB default)
- Preallocation for segment files
- Periodic sync (100ms default)
- VULN-020: Rejects entries > MaxSegmentSize

## File Formats

### Legacy JSON Mode
KVStore starts with `{` → plain JSON

### TLV+HMAC Mode (Default)
```
[0xDB magic][version 2][payloadLen 4 bytes][JSON payload][HMAC-SHA256 32 bytes]
```

## Transaction Model

```go
// Write transaction
err := kv.Update(func(tx *Tx) error {
    bucket := tx.GetBucket("zones")
    return bucket.Put("example.com", data)
})

// Read transaction
err := kv.View(func(tx *Tx) error {
    data := tx.GetBucket("zones").Get("example.com")
    return nil
})
```

## Security

### HMAC Integrity Protection

```go
type Config struct {
    HMACKey []byte  // 32 bytes for SHA-256
}
```

When configured:
- Each save computes SHA-256 HMAC
- Each load verifies HMAC before use
- `ErrDataTampered` on verification failure

### VULN-020 Prevention

```go
// wal.go
if entry.Length > MaxSegmentSize {
    return ErrEntryTooLarge
}
```

## ZoneStore

Zone-specific storage with ZONEMD support (RFC 8976):

```go
type ZoneStore struct {
    kv   *KVStore
    path string
}
```

## ZoneStore Usage

```go
zs, err := NewZoneStore("/data/zones")
err = zs.PutZone("example.com", records)
records, err = zs.GetZone("example.com")
```

## TLV Serialization

Type-Length-Value encoding for efficient storage:

```go
type Encoder struct {
    buf []byte
}

func (e *Encoder) Encode(t Type, v interface{}) error
func (e *Decoder) Decode() (Type, []byte, error)
```

## Persistence

### Atomic Save

```go
func (kv *KVStore) save() error {
    tmp := kv.path + ".tmp"
    err := writeFileAtomic(tmp, data, 0644)
    return os.Rename(tmp, kv.path)
}
```

Windows-compatible rename semantics.

### WAL Recovery

On startup:
1. Open WAL
2. Replay committed entries
3. Truncate WAL after checkpoint
4. Open KVStore data file

## Performance

- `sync.Pool` for transaction objects
- Batch appends for WAL
- Memory-mapped I/O for KVStore (future)
- Preallocated segments for WAL

## Integration

Used by:
- `ZoneManager` for zone persistence
- `CacheManager` for cache persistence
- `TransferManager` for IXFR journal