param(
  [string]$EnvFile = ".env",
  [string]$ImageTag = "",
  [string]$BaseUrl = "",
  [switch]$SkipBackup,
  [switch]$KeepOldRunning
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile
$ComposeFile = Join-Path $Root "deploy\docker-compose.yml"
$ActiveProxyFile = Join-Path $Root "deploy\active_proxy.conf"
$ActiveTlsAskFile = Join-Path $Root "deploy\active_tls_ask.conf"
$ReleaseHistoryFile = Join-Path $Root "data\release-history.jsonl"

if (-not (Test-Path -LiteralPath $EnvPath)) {
  throw "Missing $EnvFile. Copy .env.example to $EnvFile and set required values."
}

& (Join-Path $PSScriptRoot "validate-env.ps1") -EnvFile $EnvFile

if (-not $ImageTag) {
  $ImageTag = Get-Date -Format "yyyyMMdd-HHmmss"
}

function Get-EnvValue {
  param([string]$Name)
  $line = Get-Content -LiteralPath $EnvPath -Encoding UTF8 |
    Where-Object { $_ -match "^\s*$Name\s*=" } |
    Select-Object -First 1
  if (-not $line) {
    return ""
  }
  return ($line -split "=", 2)[1].Trim().Trim('"').Trim("'")
}

function Get-ImageRepo {
  param([string]$Image)
  $lastSlash = $Image.LastIndexOf("/")
  $lastColon = $Image.LastIndexOf(":")
  if ($lastColon -gt $lastSlash) {
    return $Image.Substring(0, $lastColon)
  }
  return $Image
}

function Get-ActiveColor {
  if (-not (Test-Path -LiteralPath $ActiveProxyFile)) {
    return "blue"
  }
  $content = Get-Content -LiteralPath $ActiveProxyFile -Raw -Encoding UTF8
  if ($content -match "app_green:3000") {
    return "green"
  }
  return "blue"
}

function Get-InactiveColor {
  param([string]$Color)
  if ($Color -eq "blue") {
    return "green"
  }
  return "blue"
}

function Get-ServiceName {
  param([string]$Color)
  return "app_$Color"
}

function Get-ImageName {
  param([string]$Color)
  $name = Get-EnvValue "APP_IMAGE_$($Color.ToUpperInvariant())"
  if ($name) {
    return $name
  }
  return "ab-app:$Color"
}

function Write-ActiveTarget {
  param([string]$Color)
  Set-Content -LiteralPath $ActiveProxyFile -Value "to app_$($Color):3000" -Encoding UTF8
  Set-Content -LiteralPath $ActiveTlsAskFile -Value "ask http://app_$($Color):3000/api/tls-check" -Encoding UTF8
}

function Invoke-ContainerHealth {
  param([string]$Service)
  docker compose --env-file $EnvPath -f $ComposeFile exec -T caddy wget -qO- "http://$Service`:3000/health" | Out-Null
}

function Invoke-Smoke {
  $smokeArgs = @("-File", (Join-Path $PSScriptRoot "smoke.ps1"), "-EnvFile", $EnvFile)
  if ($BaseUrl) {
    $smokeArgs += @("-BaseUrl", $BaseUrl)
  }
  powershell @smokeArgs
}

function Write-ReleaseHistory {
  param(
    [string]$Status,
    [string]$Message
  )
  $dir = Split-Path -Parent $ReleaseHistoryFile
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $record = [ordered]@{
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    status = $Status
    from_color = $activeColor
    to_color = $targetColor
    target_service = $targetService
    image = $releaseImage
    image_tag = $ImageTag
    keep_old_running = [bool]$KeepOldRunning
    message = $Message
  }
  ($record | ConvertTo-Json -Compress) | Add-Content -LiteralPath $ReleaseHistoryFile -Encoding UTF8
}

$activeColor = Get-ActiveColor
$targetColor = Get-InactiveColor $activeColor
$activeService = Get-ServiceName $activeColor
$targetService = Get-ServiceName $targetColor
$targetImage = Get-ImageName $targetColor
$targetRepo = Get-ImageRepo $targetImage
$releaseImage = "${targetRepo}:$ImageTag"

Write-Host "Active app: $activeService"
Write-Host "Target app: $targetService"
Write-ReleaseHistory -Status "started" -Message "Release started."

if (-not $SkipBackup) {
  powershell -File (Join-Path $PSScriptRoot "backup.ps1") -EnvFile $EnvFile
}

docker compose --env-file $EnvPath -f $ComposeFile up -d postgres caddy
docker compose --env-file $EnvPath -f $ComposeFile build $targetService
$newImageId = docker compose --env-file $EnvPath -f $ComposeFile images -q $targetService
if ($newImageId) {
  docker tag $newImageId $releaseImage
  Write-Host "Tagged target image as $releaseImage"
}

docker compose --env-file $EnvPath -f $ComposeFile up -d --force-recreate $targetService
Invoke-ContainerHealth $targetService

$previousColor = $activeColor
try {
  Write-ActiveTarget $targetColor
  docker compose --env-file $EnvPath -f $ComposeFile exec -T caddy caddy reload --config /etc/caddy/Caddyfile
  Invoke-Smoke

  if (-not $KeepOldRunning) {
    docker compose --env-file $EnvPath -f $ComposeFile stop $activeService
  }
  Write-ReleaseHistory -Status "completed" -Message "Release completed."
  Write-Host "Release completed. Active app is now $targetService."
} catch {
  Write-Warning "Release smoke check failed. Switching traffic back to app_$previousColor."
  Write-ActiveTarget $previousColor
  docker compose --env-file $EnvPath -f $ComposeFile exec -T caddy caddy reload --config /etc/caddy/Caddyfile
  Invoke-Smoke
  Write-ReleaseHistory -Status "rolled_back" -Message $_.Exception.Message
  throw "Release rolled back. Failed target was $targetService ($releaseImage). Original error: $($_.Exception.Message)"
}
