# Operations Guide

Bu rehber NothingDNS'in production'da çalıştırılması için deployment, hot
reload, backup/recovery, monitoring ve cluster operasyonlarını kapsar.

## 1. Deployment

### 1.1 Binary

```bash
go build -o nothingdns ./cmd/nothingdns
sudo install -m 0755 nothingdns /usr/local/bin/

# Config dizini
sudo install -d -m 0755 /etc/nothingdns
sudo install -m 0644 config.example.yaml /etc/nothingdns/nothingdns.yaml
sudo install -d -m 0750 /var/lib/nothingdns/data
```

Varsayılan config yolu: `/etc/nothingdns/nothingdns.yaml`. `--config` bayrağı
ile özelleştirin.

### 1.2 Docker

```bash
docker build -t nothingdns:local .
docker run --rm -p 5354:53/udp -p 5354:53/tcp \
  -v $PWD/config.example.yaml:/etc/nothingdns/nothingdns.yaml:ro \
  nothingdns:local
```

`Dockerfile` çoklu aşamalıdır: `golang:1.26.2-alpine` ile derler ve `FROM
scratch` üzerine kopyalar.

### 1.3 Docker Compose

[docker-compose.yml](../docker-compose.yml) tek-node geliştirme için yapılandırılmıştır.

### 1.4 Kubernetes / Helm

[deploy/](../deploy/) altında staging ve production manifestleri ile Helm
chart bulunur:

```bash
helm install nothingdns deploy/helm/nothingdns/ \
  -n dns --create-namespace -f deploy/helm/values-prod.yaml
```

## 2. systemd Unit

```ini
# /etc/systemd/system/nothingdns.service
[Unit]
Description=NothingDNS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nothingdns
Group=nothingdns
ExecStart=/usr/local/bin/nothingdns --config /etc/nothingdns/nothingdns.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Port 53 ayrıcalığı (root yerine capability)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Sertleştirme
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/nothingdns

[Install]
WantedBy=multi-user.target
```

Etkinleştir:

```bash
sudo useradd -r -s /usr/sbin/nologin nothingdns
sudo chown -R nothingdns:nothingdns /var/lib/nothingdns
sudo systemctl daemon-reload
sudo systemctl enable --now nothingdns
```

## 3. Hot Reload

### 3.1 Config Reload

```bash
# systemd ile
sudo systemctl reload nothingdns

# Manuel
sudo kill -HUP $(pidof nothingdns)
```

SIGHUP zone dosyalarını, blocklist'leri, RPZ kurallarını, split-horizon
view'larını ve TLS sertifikalarını **downtime olmadan** yeniden yükler.

### 3.2 Reload Öncesi Doğrulama

```bash
nothingdns --config /etc/nothingdns/nothingdns.yaml --validate-config
```

Reload tetiklemeden önce her zaman doğrulayın; geçersiz config çalışan
sürecin durumunu etkilemez ama servis yeniden başlatılırsa açılmaz.

### 3.3 Yeniden Başlatma Gerektirenler

Bu alanlar hot-reload tarafından **alınmaz**, full restart gerekir:

- Bind adresleri (IP/port)
- Worker sayıları (UDP/TCP)
- Cluster `node_id`, `gossip_port`, `seed_nodes`
- Storage dizini (`--data-dir`)

## 4. Backup ve Recovery

### 4.1 Veri Konumları

| Bileşen | Varsayılan yol | Amaç |
|---|---|---|
| KV Store | `data/nothingdns.db` | Birincil veri deposu |
| WAL | `data/nothingdns.wal` | Crash recovery için Write-Ahead Log |

`--data-dir` bayrağı ile değiştirilebilir (varsayılan: `./data`).

### 4.2 Online Backup (önerilen)

NothingDNS SIGUSR1 sinyali ile hot-backup'ı destekler:

```bash
kill -USR1 $(pidof nothingdns)
# Çıktı: data/nothingdns-backup-{timestamp}.db
```

Sunucuyu durdurmadan KV store'un anlık görüntüsünü alır.

### 4.3 Filesystem Snapshot

Production'da filesystem snapshot'ı tercih edin:

```bash
# Btrfs
btrfs subvolume snapshot /var/lib/nothingdns /var/lib/nothingdns/backups/$(date +%Y%m%d)

# ZFS
zfs snapshot tank/nothingdns@$(date +%Y%m%d)

# LVM
lvcreate --snapshot --size=1G --name=nothingdns-backup /dev/vg0/nothingdns
```

### 4.4 Otomatik Backup Scripti

```bash
#!/bin/bash
# /etc/cron.d/nothingdns-backup
BACKUP_DIR="/backups/nothingdns"
DATA_DIR="/var/lib/nothingdns/data"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"
kill -USR1 $(pidof nothingdns) 2>/dev/null || true
cp "$DATA_DIR/nothingdns.db" "$BACKUP_DIR/nothingdns-$(date +%Y%m%d).db"
find "$BACKUP_DIR" -name "nothingdns-*.db" -mtime +$RETENTION_DAYS -delete
cp "$DATA_DIR"/nothingdns.wal* "$BACKUP_DIR/"
echo "Backup completed: $(date)" >> "$BACKUP_DIR/backup.log"
```

Crontab: `0 2 * * * /etc/cron.d/nothingdns-backup`

### 4.5 Recovery

**Point-in-time recovery:**

```bash
sudo systemctl stop nothingdns
cp data/nothingdns-backup-20260411.db data/nothingdns.db
rm data/nothingdns.wal*    # WAL'ı sil ki replay backup noktasından başlasın
sudo systemctl start nothingdns
```

**Crash recovery:** NothingDNS başlangıçta WAL'ı otomatik replay eder. Manuel
işlem gerekmez.

**Disaster recovery:**

```bash
cp /backup/nothingdns-20260410.db /var/lib/nothingdns/data/nothingdns.db
sudo systemctl start nothingdns
dnsctl zone list
dnsctl zone verify example.com
```

### 4.6 Backup Doğrulama

Yeniden yükleme garantisi için izole bir ortamda test edin:

```bash
nothingdns --config /etc/nothingdns/test-restore.yaml --data-dir /tmp/test-restore
dnsctl zone list
```

### 4.7 Cluster Replikasyonu Backup'ı Kaldırmaz

`cluster.cache_sync: true` ile veri node'lar arası kopyalanır, ancak bu **offline
backup'ın yerini almaz**. Hala ayrı backup tutun.

## 5. Monitoring

### 5.1 Prometheus Metrikleri

Config'de etkinleştirin:

```yaml
metrics:
  enabled: true
  bind: ":9153"
  path: /metrics
```

Prometheus scrape config:

```yaml
- job_name: nothingdns
  static_configs:
    - targets: ['nothingdns.example.com:9153']
```

### 5.2 Audit Log

```yaml
logging:
  query_log: true
  query_log_file: /var/log/nothingdns/queries.log
```

Yapılandırılmış audit kaydı: client IP, sorgu, latency, cache durumu. JSON
format için `logging.format: json`.

### 5.3 Sağlık Kontrolü

HTTP API'yi etkinleştirdiyseniz:

```bash
curl http://localhost:8080/api/v1/health
```

## 6. Cluster Operasyonu

### 6.1 Bootstrap

İlk node:

```yaml
cluster:
  enabled: true
  node_id: dns-1
  bind_addr: 10.0.1.10
  gossip_port: 7946
  seed_nodes: []   # ilk node, kendisi seed
```

İkinci ve sonraki node'lar:

```yaml
cluster:
  enabled: true
  node_id: dns-2
  bind_addr: 10.0.1.11
  gossip_port: 7946
  seed_nodes:
    - 10.0.1.10:7946
```

### 6.2 Raft TLS

İletişim için Raft RPC TLS'i tercih edilir; production'da loopback olmayan
seed'lerle `allow_insecure` kullanmayın (geçen sürümde uyarı eklendi).

### 6.3 Ölçeklendirme

- **Recommended quorum**: 3 veya 5 node (tek sayı)
- **Cache sync**: `cluster.cache_sync: true` cache'leri yayınlar; yüksek
  trafikte `false` deneyin ve gözleyin.
- **Geographic load balancing**: `cluster.region` ve `cluster.zone` ile
  topology hint sağlanır.

### 6.4 Sağlık

```bash
dnsctl cluster members
dnsctl cluster status
```

## 7. Hızlı Referans

| Eylem | Komut |
|---|---|
| Hot backup | `kill -USR1 $(pidof nothingdns)` |
| Config reload | `kill -HUP $(pidof nothingdns)` |
| Validate config | `nothingdns --config <path> --validate-config` |
| Veri dizinini kontrol | `dnsctl info` |
| Zone bütünlüğü | `dnsctl zone verify <zone>` |
| Zone export | `dnsctl zone export <zone> --format=bind -o zone.txt` |
| Cluster üyeleri | `dnsctl cluster members` |
| Sağlık | `curl http://localhost:8080/api/v1/health` |
