# NothingDNS Implementation Tasks

> Kapsamlı implementasyon planı — tüm eksiklikler, task'ler ve implementasyon detayları
> Oluşturulma: 2026-05-03
> Durum: Kısmi tamamlandı (TASK-001 mDNS ✅, TASK-002 Raft Snapshot ✅)

---

## Genel Bakış

Bu doküman NothingDNS projesindeki tüm eksiklikleri, boş implementasyonları ve test edilmemiş alanları kapsar. Her task detaylı implementasyon adımları içerir.

| Kategori | Task Sayısı | Öncelik | Durum |
|----------|-------------|---------|-------|
| mDNS (Multicast DNS) | 5 | Yüksek | ✅ TAMAMLANDI |
| Raft Snapshot | 1 | Orta | ✅ TAMAMLANDI |
| GOST DS Digest | 1 | Düşük |
| Cluster Dynamic Join | 1 | Orta |
| XoT Test Coverage | 1 | Düşük |
| KVJournalStore Test Coverage | 1 | Düşük |
| ODoH Target Wiring | 1 | Orta |
| Server Config API | 2 | Düşük |
| API Response Types | 1 | Düşük |

---

## TASK-001: mDNS (Multicast DNS) Implementasyonu

**Öncelik:** Yüksek
**Tahmini Süre:** 5-7 gün
**Dosya:** `internal/mdns/mdns.go`
**Durum:** ✅ **TAMAMLANDI** — 63 test fonksiyonu, tüm testler geçiyor

> mDNS implementasyonu tamamlanmıştır. `sendARecord`, `sendSRVRecord`, `sendTXTRecord`, `sendQuery`, ve `sendGoodbye` fonksiyonlarının tümü çalışır durumdadır. Stub fonksiyon kalmamıştır.

### Eksik Fonksiyonlar
1. `sendARecord()` (satır 383-386)
2. `sendSRVRecord()` (satır 389-391)
3. `sendTXTRecord()` (satır 394-396)
4. `sendQuery()` (satır 399-401)
5. `sendGoodbye()` (satır 423-425)

### Implementasyon Adımları

#### Adım 1: mDNS Multicast Katmanı
```
1. multicast.go oluştur
2. multicastIPv4 (224.0.0.251:5353) ve IPv6 (ff02::fb:5353) adresleri
3. Multicast socket oluşturma (IP_MULTICAST_LOOP, IP_MULTICAST_TTL)
4. Join/leave multicast group
```

**Multicast Socket Setup:**
```go
// Pseudo-code
conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 5353})
if err != nil {
    // Set SO_REUSEPORT for multiple instances
}
iface, _ := net.Interfaces()
// Join multicast group on each eligible interface
```

#### Adım 2: DNS Record Oluşturma
```go
// sendARecord - RFC 1035
func (m *MDNSResponder) sendARecord(r *dns.Question, src net.IP) error {
    // 1. Build A record (A = 1, AAAA = 28)
    // 2. Set TTL = 120 seconds (RFC 6762 suggests 120-450)
    // 3. Fill authority section if needed
    // 4. Send to multicast group
    msg := new(dns.Msg)
    msg.SetReply(r)
    msg.Answer = append(msg.Answer, &dns.A{
        Hdr: dns.RR_Header{Name: r.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
        A:   src,
    })
    return m.sendMulticast(msg)
}
```

#### Adım 3: Service Discovery (DNS-SD) PTR Queries
```go
// sendQuery - Handle PTR queries for service discovery
// e.g., _http._tcp.local -> return SRV + TXT records
func (m *MDNSResponder) sendQuery(svc string) error {
    // 1. Parse service name (_service._proto.local)
    // 2. Look up registered services in m.services map
    // 3. Send PTR response with service instances
    // 4. Include additional records (SRV, TXT) in Additional section
}
```

#### Adım 4: Goodbye Packets (TTL=0)
```go
// sendGoodbye - Send ANU/RNU for departing services
func (m *MDNSResponder) sendGoodbye(service string) error {
    // 1. Mark all records for this service with TTL=0
    // 2. Send as unsolicited multicast
    // 3. Use same multicast group
}
```

#### Adım 5: Integration with Main Handler
- `cmd/nothingdns/handler.go`'da `.local` zone kontrolü
- mDNS responder'a delege et

#### Test Planı
```
1. Unit tests: record encoding, multicast send
2. Integration tests: two instances, service discovery
3. Mock network: simulate multicast group
```

---

## TASK-002: Raft Snapshot Data Streaming

**Öncelik:** Orta
**Tahmini Süre:** 2-3 gün
**Dosya:** `internal/cluster/raft/snapshot.go` (475 satır)
**Durum:** ✅ **TAMAMLANDI** — tüm Raft testleri geçiyor

> Raft snapshot pipeline tamamlanmıştır. 475 satırlık `snapshot.go` dosyası `Snapshotter` API'si ile snapshot'ların kaydedilmesi, yüklenmesi, AES-256-GCM ile isteğe bağlı şifrelenmesi ve geri yüklenmesini sağlar. `ZoneStateMachine.Restore()` snapshot verisini state machine'e uygular. Ek olarak `Snapshotter.Load()` hem düz hem de şifreli dosyaları otomatik tanır.

### Mevcut Kod (Satır 696-702)
```go
// Install snapshot
// (Simplified — real implementation would stream the snapshot)
n.lastSnapshot = req.LastIndex
n.lastApplied = req.LastIndex
n.commitIndex = req.LastIndex
n.log = make([]entry, 0)
```

### Implementasyon Adımları

#### Adım 1: Snapshot State Machine Tanımı
```go
// snapshot.go
type SnapshotStateMachine interface {
    Apply(snapshot []byte) error  // Apply snapshot data to state
    Snapshot() ([]byte, error)    // Take snapshot of current state
}
```

#### Adım 2: Snapshot Serialization
```go
// raft.go - Snapshot types
type Snapshot struct {
    LastIndex   uint64
    LastTerm    uint64
    StateMachine []byte  // Serialized state
    Membership   []string // Cluster nodes
    Timestamp    time.Time
}

// Persist snapshot to disk before installing
func (n *RaftNode) persistSnapshot(snap Snapshot) error {
    // Use storage package TLV format
}
```

#### Adım 3: InstallSnapshot RPC Handler
```go
// Handle InstallSnapshot RPC (Figure 7 in Raft paper)
func (n *RaftNode) handleInstallSnapshot(req InstallSnapshotRequest) error {
    // 1. If req.LastIndex <= commitIndex, ignore (already applied)
    // 2. Truncate state machine to req.LastIndex
    // 3. Save snapshot to disk
    // 4. Apply snapshot data to state machine via Apply()
    // 5. Update lastSnapshot, lastApplied, commitIndex
    // 6. Truncate log (discard log entries before LastIndex)

    // Stream implementation for large snapshots
    // Chunk the snapshot data for memory efficiency
}
```

#### Adım 4: Log Truncation After Snapshot
```go
// Log truncation after snapshot install
func (n *RaftNode) maybeTruncateLog(snapshotIndex uint64) {
    if len(n.log) > 0 && n.log[0].Index < snapshotIndex {
        // Keep only entries after snapshotIndex
        newLog := make([]entry, 0)
        for _, e := range n.log {
            if e.Index >= snapshotIndex {
                newLog = append(newLog, e)
            }
        }
        n.log = newLog
    }
}
```

#### Adım 5: Snapshot Transportation
```go
// Streaming snapshot for network efficiency
func (n *RaftNode) sendSnapshot(to uint64) {
    // 1. Take local snapshot
    snap, _ := n.stateMachine.Snapshot()
    // 2. Stream chunks to follower
    // 3. Follower applies each chunk
    // 4. Final commit only after all chunks received
}
```

#### Test Planı
```
1. Test snapshot creation and restoration
2. Test log truncation after snapshot
3. Test InstallSnapshot RPC with network partition
4. Test leader failover during snapshot transfer
```

---

## TASK-003: GOST R 34.11-94 DS Digest Implementasyonu

**Öncelik:** Düşük
**Tahmini Süre:** 1-2 gün
**Dosya:** `internal/protocol/dnssec_ds.go:166-167`

### Durum
GOST digest type 3 desteklenmiyor, error dönüyor.

### Mevcut Kod
```go
case 3: // GOST (not implemented)
    return nil, fmt.Errorf("GOST digest type is not supported")
```

### Implementasyon Adımları

#### Adım 1: GOST Digest Implementation
```go
// dnssec_ds.go
// GOST R 34.11-94 (Streebog) - Russian standard hash
// Using golang.org/x/crypto/gost3411

import "golang.org/x/crypto/gost3411"

func (d *DSDigest) hashGOST(data []byte) ([]byte, error) {
    // GOST 34.311-94 is not in standard Go crypto
    // Use golang.org/x/crypto/gost3411
    hasher := gost3411.New()
    hasher.Write(data)
    return hasher.Sum(nil), nil
}

// Wire into digest type switch
case 3:
    return d.hashGOST(keyData)
```

#### Adım 2: Alternative Pure Go Implementation
```go
// If external dependency not allowed, implement STRIBOG algorithm
// RFC 6986 - Streebog is the new GOST hash standard

type Streebog struct {
    h [8]uint64
    m []byte
    N uint64
}

func NewStreebog() *Streebog {
    // Initialize with GOST constants
    // Matrix B and IV
}
```

#### Test Vectors
```go
// RFC 8493 test vectors for GOST DS digest
func TestGOSTDigestVectors(t *testing.T) {
    // Known-answer test vectors
}
```

---

## TASK-004: Raft Dynamic Node Joining

**Öncelik:** Orta
**Tahmini Süre:** 2-3 gün
**Dosya:** `internal/cluster/cluster.go:716`

### Durum
`JoinCluster` fonksiyonu Raft modunda explicit olarak reddediyor.

### Mevcut Kod
```go
return fmt.Errorf("dynamic node joining not supported in Raft consensus mode")
```

### Implementasyon Adımları

#### Adım 1: Raft Joint Consensus Membership Change
```go
// cluster.go - Implement RFC 6584 joint consensus
// AddServer/RemoveServer RPC

func (c *ClusterManager) handleAddNode(ctx context.Context, addr string) error {
    // 1. Validate address format
    // 2. Check if node already exists
    // 3. If leader exists, propose cluster membership change
    // 4. Use joint consensus (old + new configuration)
    // 5. Once joined, transition to new configuration

    if c.consensus == "raft" {
        return c.raftAddNode(ctx, addr)
    }
    // Gossip mode already supports dynamic join
}
```

#### Adım 2: Raft Propose Configuration Change
```go
// cluster_raft.go
func (n *RaftNode) proposeAddNode(addr string) error {
    // 1. Create AddNode RPC
    // 2. Propose as joint consensus configuration
    // 3. Wait for log replication (majority)
    // 4. Transition to new config
    // 5. Return node ID

    confChange := &ConfigurationChange{
        Type:     AddNode,
        NodeID:   generateNodeID(addr),
        Address:  addr,
        JointConfig: true,
    }
    return n.proposeConfChange(confChange)
}
```

#### Adım 3: Learner Node Support
```go
// Allow nodes to join as learners (non-voting)
// Then promote to voting member after catch-up
func (n *RaftNode) addLearner(addr string) error {
    // Learner catches up via log replication
    // No voting rights until promoted
}
```

---

## TASK-005: XoT Test Coverage

**Öncelik:** Düşük
**Tahmini Süre:** 2-3 gün
**Dosya:** `internal/transfer/xot.go`

### Durum
XoT (DNS over TLS, RFC 9103) implementasyonu var ama neredeyse hiç test yok.

### Implementasyon Adımları

#### Adım 1: XoT Server Tests
```go
// xot_test.go
func TestXoTServerHandshake(t *testing.T) {
    // 1. Start XoT server with TLS config
    // 2. Connect with TLS client
    // 3. Send DNS query over TLS
    // 4. Verify response
}

func TestXoTMultipleQueries(t *testing.T) {
    // 1. Single connection, multiple queries
    // 2. Verify pipelining works
    // 3. Check connection reuse
}
```

#### Adım 2: XoT Transfer Tests
```go
func TestXoTAXFRTransfer(t *testing.T) {
    // 1. Initiate AXFR over TLS
    // 2. Verify all records received
    // 3. Check streaming behavior
}
```

#### Adım 3: Error Handling Tests
```go
func TestXoTTLSHandshakeFailure(t *testing.T) {}
func TestXoTConnectionTimeout(t *testing.T) {}
func TestXoTInvalidQuery(t *testing.T) {}
```

---

## TASK-006: KVJournalStore Test Coverage

**Öncelik:** Düşük
**Tahmini Süre:** 1-2 gün
**Dosya:** `internal/transfer/kvjournal.go`

### Durum
IXFR journal storage neredeyse test edilmiş değil.

### Implementasyon Adımları

#### Adım 1: Store Tests
```go
// kvjournal_test.go
func TestKVJournalStorePut(t *testing.T) {
    store := NewKVJournalStore(t.TempDir())
    err := store.Put([]byte("key1"), []byte("value1"))
    // Verify
}

func TestKVJournalStoreGet(t *testing.T) {}
func TestKVJournalStoreDelete(t *testing.T) {}
func TestKVJournalStoreIterate(t *testing.T) {}
```

#### Adım 2: Journal Recovery Tests
```go
func TestKVJournalRecovery(t *testing.T) {
    // 1. Write entries
    // 2. Force crash (simulate with temp dir removal)
    // 3. Reopen store
    // 4. Verify data integrity
}
```

#### Adım 3: Concurrency Tests
```go
func TestKVJournalConcurrentWrites(t *testing.T) {}
func TestKVJournalCompaction(t *testing.T) {}
```

---

## TASK-007: ODoH Target Wiring

**Öncelik:** Orta
**Tahmini Süre:** 1-2 gün
**Dosya:** `internal/api/api_health.go:13-16`

### Durum
ODoH (Oblivious DNS over HTTPS, RFC 9230) target endpoint'i nil kontrolü yapıyor ama wiring eksik.

### Implementasyon Adımları

#### Adım 1: ODoH Server Setup
```go
// odoh.go
type ODoHTarget struct {
    server *odoh.Server  // Oblivious DoH target
    config *ODoHConfig
}

func (s *Server) setupODoHTarget(config ODoHConfig) error {
    // 1. Create ODoH target server
    // 2. Set up encryption keys (HPKE)
    // 3. Register handler
    // 4. Wire into main server
}
```

#### Adım 2: HPKE Key Management
```go
// ODoH uses Hybrid Public Key Encryption
// Create target's private/public key pair
func setupHPKEKeys() ([]byte, []byte, error) {
    // Use crypto/kem package
}
```

#### Adım 3: Target Registration
```go
// Wire ODoH target into server
func (s *Server) RegisterODoHTarget(target *odoh.Server) {
    s.odohTarget = target
    // Now handleODoHConfig will return 200 instead of 503
}
```

---

## TASK-008: Server Config API Düzeltmesi

**Öncelik:** Düşük
**Tahmini Süre:** 1 gün
**Dosya:** `internal/api/api_config.go`

### Durum
`handleServerConfig` döndüğü struct'ta `ListenPort: 0` ve `LogLevel: ""` görünüyor.

### Implementasyon Adımları

#### Adım 1: HTTPConfig'e Eksik Alanları Ekle
```go
// api_config.go - ServerConfigResponse
type ServerConfigResponse struct {
    ListenPort  int    `json:"listenPort"`   // Currently returns 0
    LogLevel    string `json:"logLevel"`    // Currently returns ""
    // ... other fields
}
```

#### Adım 2: Değerleri Doldur
```go
func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
    resp := ServerConfigResponse{
        ListenPort: s.httpServer.Addr.Port,  // Parse from httpServer.Addr
        LogLevel:   s.config.Logging.Level,   // From server config
        // ... populate all fields
    }
    json.NewEncoder(w).Encode(resp)
}
```

---

## TASK-009: API Response Type Standardization

**Öncelik:** Düşük
**Tahmini Süre:** 2 gün
**Dosya:** Birkaç dosya

### Durum
Bazı endpoint'ler `map[string]interface{}` dönüyor, typed response gerekli.

### Implementasyon Adımları

#### Adım 1: Tüm API Response'larını Tipli Yap
```go
// Her endpoint için typed response struct

// Before
func handler(w, r) {
    json.NewEncoder(w).Encode(map[string]interface{}{"data": x})
}

// After
type PTRPreviewResponse struct {
    Domains []string `json:"domains"`
    Count   int      `json:"count"`
}

func handler(w, r) {
    json.NewEncoder(w).Encode(PTRPreviewResponse{Domains: domains, Count: len(domains)})
}
```

#### Adım 2: Affected Endpoints
- `bulk-ptr-preview` → `BulkPTRPreviewResponse`
- `ptr6-lookup` → `PTR6LookupResponse`
- `geoip-stats` → `GeoIPStatsResponse`

---

## Öncelik Sıralaması

| Task | Öncelik | Süre | Kriter |
|------|---------|------|--------|
| TASK-001 mDNS | Yüksek | 5-7 gün | Feature complete |
| TASK-002 Raft Snapshot | Orta | 2-3 gün | Data loss risk |
| TASK-003 GOST | Düşük | 1-2 gün | Rarely used |
| TASK-004 Dynamic Join | Orta | 2-3 gün | Cluster elasticity |
| TASK-005 XoT Tests | Düşük | 2-3 gün | Coverage |
| TASK-006 KVJournal Tests | Düşük | 1-2 gün | Coverage |
| TASK-007 ODoH Wiring | Orta | 1-2 gün | Privacy feature |
| TASK-008 Server Config | Düşük | 1 gün | Cosmetic |
| TASK-009 API Types | Düşük | 2 gün | Code quality |

---

## Başlangıç Talimatları

Her task için:
1. Branch oluştur: `git checkout -b task/TASK-XXX`
2. Implementasyonu tamamla
3. Testleri yaz/testleri geçir
4. PR aç ve review'e gönder

Build komutları:
```bash
go build -o nothingdns ./cmd/nothingdns
go build -o dnsctl ./cmd/dnsctl
go vet ./...
go test ./... -count=1 -short
```

---

*Son güncelleme: 2026-05-03*