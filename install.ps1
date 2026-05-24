# NothingDNS Windows Installation Script
# Downloads latest release, creates config, and sets up the server

param(
    [string]$InstallPath = "$env:ProgramFiles\NothingDNS",
    [string]$ConfigPath = "$env:ProgramData\NothingDNS\config.yaml"
)

$ErrorActionPreference = "Stop"

$REPO = "NothingDNS/NothingDNS"
$BINARY_NAME = "nothingdns"
$DNSCTL_NAME = "dnsctl"

# Colors
function Write-Info($message) { Write-Host "[INFO] $message" -ForegroundColor Green }
function Write-Warn($message) { Write-Host "[WARN] $message" -ForegroundColor Yellow }
function Write-Err($message) { Write-Host "[ERROR] $message" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  NothingDNS Install Script v1.1" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Detect architecture
$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "amd64" } else { "arm64" }
$PLATFORM = "windows-$ARCH"

Write-Info "Platform: $PLATFORM"

# Get latest release
Write-Info "Fetching latest release info..."
$RELEASE_URL = "https://api.github.com/repos/$REPO/releases/latest"
try {
    $RELEASE = Invoke-RestMethod -Uri $RELEASE_URL -UseBasicParsing
    $VERSION = $RELEASE.tag_name
    $ASSETS = $RELEASE.assets
} catch {
    Write-Err "Could not fetch latest release: $_"
}
Write-Info "Latest version: $VERSION"

# Create install directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}
Write-Info "Install directory: $InstallPath"

# Download binary
$BINARY_URL = $ASSETS | Where-Object { $_.name -eq "$BINARY_NAME-$PLATFORM.exe" } | Select-Object -First 1 -ExpandProperty browser_download_url
if (!$BINARY_URL) {
    Write-Err "Binary not found for $PLATFORM"
}

Write-Info "Downloading nothingdns..."
$BINARY_PATH = "$InstallPath\$BINARY_NAME.exe"
Invoke-WebRequest -Uri $BINARY_URL -OutFile $BINARY_PATH -UseBasicParsing | Out-Null
Write-Info "Downloaded to $BINARY_PATH"

# Download dnsctl
$DNSCTL_URL = $ASSETS | Where-Object { $_.name -eq "$DNSCTL_NAME-$PLATFORM.exe" } | Select-Object -First 1 -ExpandProperty browser_download_url
if ($DNSCTL_URL) {
    Write-Info "Downloading dnsctl..."
    $DNSCTL_PATH = "$InstallPath\$DNSCTL_NAME.exe"
    Invoke-WebRequest -Uri $DNSCTL_URL -OutFile $DNSCTL_PATH -UseBasicParsing | Out-Null
    Write-Info "Downloaded to $DNSCTL_PATH"
}

# Create default config
function Create-DefaultConfig {
    param([string]$Path)

    $CONFIG_DIR = Split-Path $Path -Parent
    if (!(Test-Path $CONFIG_DIR)) {
        New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null
    }

    if (Test-Path $Path) {
        Write-Warn "Config already exists at $Path"
        $overwrite = Read-Host "Overwrite? (y/N)"
        if ($overwrite -ne "y" -and $overwrite -ne "Y") {
            Write-Info "Keeping existing config"
            return
        }
    }

    Write-Info "Creating default config at $Path..."

    # Generate a random auth secret
    $AUTH_SECRET = [System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))

    $CONFIG = @"
# NothingDNS Configuration
# https://github.com/NothingDNS/NothingDNS
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")

server:
  port: 53
  bind:
    - 0.0.0.0
    - "::"
  http:
    enabled: true
    bind: "0.0.0.0:8080"
    auth_secret: "${AUTH_SECRET}"

upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
    - 8.8.4.4:53
  timeout: 5s
  health_check: 30s

cache:
  enabled: true
  size: 10000
  default_ttl: 3600
  max_ttl: 86400
  min_ttl: 300
  negative_ttl: 60
  prefetch: true
  prefetch_threshold: 60
  serve_stale: true
  stale_grace_secs: 86400

dnssec:
  enabled: true

logging:
  level: info
  format: text
  output: stdout
  query_log: false

metrics:
  enabled: true
  bind: ":9153"
  path: /metrics

rrl:
  enabled: true
  rate: 100
  burst: 200

cookie:
  enabled: true

zones: []
transfer:
  allow_list: []
  require_tsig: false
cluster:
  enabled: false
"@

    $CONFIG | Out-File -FilePath $Path -Encoding UTF8
    Write-Info "Config created at $Path"
    Write-Warn "Auth secret generated. Save this secret for API access:"
    Write-Warn "  $AUTH_SECRET"
}

Create-DefaultConfig -Path $ConfigPath

# Create data directory
$DATA_DIR = "$env:ProgramData\NothingDNS\data"
if (!(Test-Path $DATA_DIR)) {
    New-Item -ItemType Directory -Path $DATA_DIR -Force | Out-Null
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Edit config: notepad $ConfigPath"
Write-Host "  2. Start server:"
Write-Host "       $BINARY_PATH --config $ConfigPath"
Write-Host ""
Write-Host "Dashboard: http://localhost:8080"
Write-Host ""
Write-Host "To run as Windows Service, install NSSM:"
Write-Host "  choco install nssm"
Write-Host "  nssm install NothingDNS $BINARY_PATH '--config $ConfigPath'"
Write-Host "  nssm start NothingDNS"
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
