param(
  [string]$EnvFile = ".env",
  [string]$BaseUrl = "",
  [string]$Service = "",
  [int]$Retries = 10,
  [int]$DelaySeconds = 3
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile
$ComposeFile = Join-Path $Root "deploy\docker-compose.yml"

function Get-EnvValue {
  param([string]$Name)
  if (-not (Test-Path -LiteralPath $EnvPath)) {
    return ""
  }
  $line = Get-Content -LiteralPath $EnvPath -Encoding UTF8 |
    Where-Object { $_ -match "^\s*$Name\s*=" } |
    Select-Object -First 1
  if (-not $line) {
    return ""
  }
  return ($line -split "=", 2)[1].Trim().Trim('"').Trim("'")
}

if ($Service) {
  $BaseUrl = "http://$Service`:3000"
}

if (-not $BaseUrl) {
  $domain = Get-EnvValue "APP_BASE_DOMAIN"
  if ($domain) {
    $BaseUrl = "https://$domain"
  } else {
    $port = Get-EnvValue "APP_PORT"
    if (-not $port) {
      $port = "3000"
    }
    $BaseUrl = "http://127.0.0.1:$port"
  }
}

$healthUrl = $BaseUrl.TrimEnd("/") + "/health"
Write-Host "Checking $healthUrl"

$lastError = $null
for ($i = 1; $i -le $Retries; $i++) {
  try {
    if ($Service) {
      $raw = docker compose --env-file $EnvPath -f $ComposeFile exec -T caddy wget -qO- $healthUrl
      $response = $raw | ConvertFrom-Json
    } else {
      $response = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 10
    }
    if ($response.ok -eq $true) {
      docker compose --env-file $EnvPath -f $ComposeFile ps
      Write-Host "Smoke check passed."
      exit 0
    }
    $lastError = "Health response is not ok: $($response | ConvertTo-Json -Compress)"
  } catch {
    $lastError = $_.Exception.Message
  }

  if ($i -lt $Retries) {
    Start-Sleep -Seconds $DelaySeconds
  }
}

Write-Error "Smoke check failed: $lastError"
