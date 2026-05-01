# Contributing to NothingDNS

NothingDNS'e katkı sağladığınız için teşekkürler. Bu rehber geliştirme ortamı,
kod stili, test gereksinimleri ve PR sürecini açıklar.

## Geliştirme Ortamı

### Gereksinimler

- **Go**: 1.25.0 veya üzeri (toolchain go1.26.2)
- **Node + pnpm**: web/ dashboard'u derlemek için (yalnızca dashboard üzerinde
  çalışıyorsanız gereklidir)
- **Git**: Kod kontrolü ve commit için
- **Docker** (opsiyonel): Container build doğrulaması için

### Build

```bash
# Sunucu binary'si
go build -o nothingdns ./cmd/nothingdns

# CLI
go build -o dnsctl ./cmd/dnsctl

# Statik build (CGO_ENABLED=0)
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -extldflags '-static'" -o nothingdns ./cmd/nothingdns
```

### Web Dashboard

```bash
cd web
pnpm install
pnpm run build   # Çıktı: ../internal/dashboard/static/dist/
```

`internal/dashboard/static/dist/` `go:embed` ile derlemeye gömülür; bu yüzden
git'te tracked olarak kalır. Dashboard'u değiştirdiyseniz, build çıktısını da
commit'leyin.

## Kod Stili

### Bağımlılık Politikası — Strict Zero

NothingDNS yalnızca Go stdlib + `golang.org/x/sys` (platform soket çağrıları)
kullanır. Bu çekirdek bir tasarım kısıtlamasıdır:

- Yeni third-party import **eklemeyin**.
- DNS protokolü, YAML parser, JWT, Raft, Gossip — hepsi bu repo içinde
  hand-rolled.

### Paylaşılan Yardımcılar

Yeniden yazmak yerine var olanı kullanın:

- `protocol.CanonicalWireName()` — canonical name encoder
- `internal/config/` parser'ı — `advance()` ve `peek()` `TokenComment`'ı
  otomatik atlar; comment'ı parse mantığında ele almayın

### Gotcha'lar

[CLAUDE.md](CLAUDE.md)'deki "Known Gotchas" bölümünde toplananları okuyun.
Önemli noktalar:

- `sync.Pool` buffer'ları `defer pool.Put()`'tan önce **kopyalanmalıdır**;
  referans geri alınabilir.
- Upstream TCP mesajları için `len(packed) > 65535` kontrolü zorunlu.
- UDP truncation **record-boundary-aware** olmalı, byte düzeyinde kesim
  yapılmamalı.
- Health-check goroutine'leri **tur başına ayrı** `sync.WaitGroup` kullanır;
  ana WG paylaşılmaz.

### Commit Mesajları

Conventional commits tarzı kısa prefix kullanın:

- `feat:` yeni özellik
- `fix:` hata düzeltme
- `docs:` yalnızca doküman
- `chore:` build/araç değişikliği, kaynak kodu etkilemeyen
- `security:` güvenlik düzeltmesi
- `perf:` performans optimizasyonu
- `refactor:` davranış değiştirmeyen yeniden yapılandırma
- `test:` yalnızca test eklemek/düzeltmek

Atomic commit kuralı: bir commit, mantıksal olarak tek bir değişikliği temsil
etmeli ve build'i kırmamalı.

## Test

### Komutlar

```bash
go vet ./...                              # Lint, sıfır uyarı
go test ./... -count=1 -short             # Hızlı testler (kısa mod)
go test ./internal/protocol/ -run TestX   # Tek test
go test ./internal/e2e/... -v             # End-to-end testler
go test -race ./...                       # Race detection (yavaş)
```

### RTK ile Token Tasarrufu

[RTK](https://github.com/nothingdns/rtk) kompakt çıktı sağlar:

```bash
rtk go build ./...      # kompakt build çıktısı
rtk go test ./...       # yalnızca başarısızlıklar (90%+ token tasarrufu)
rtk go vet ./...        # gruplandırılmış ihlaller
rtk git status          # kompakt git çıktısı
```

### Test Gereksinimleri

- Yeni bir public API → unit test gerekli
- Yeni bir DNS özelliği → e2e test (`internal/e2e/`) gerekli
- Bug fix → regression test, fix'le aynı commit'te

## PR Kontrol Listesi

PR açmadan önce:

- [ ] `go vet ./...` temiz çıkıyor
- [ ] `go test ./... -count=1 -short` geçiyor
- [ ] `go build ./...` ve `go build -o nothingdns ./cmd/nothingdns` çalışıyor
- [ ] Dashboard değiştiyse `pnpm run build` çıktısı commit'lendi
- [ ] Yeni bir public alan/komut/config → ilgili dokümante belge güncellendi
  ([docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md),
  [docs/SPECIFICATION.md](docs/SPECIFICATION.md), CLI'da
  [cmd/dnsctl/README.md](cmd/dnsctl/README.md))
- [ ] [docs/CHANGELOG.md](docs/CHANGELOG.md) "Unreleased" bölümüne özet
  eklendi
- [ ] Commit mesajı conventional prefix kullanıyor

## Güvenlik

Güvenlik açığı bulduysanız [docs/SECURITY.md](docs/SECURITY.md) yönergelerini
takip edin. Public issue açmayın.

## Lisans

Katkılarınız [LICENSE](LICENSE) (MIT) kapsamında lisanslanır.
