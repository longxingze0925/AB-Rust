param(
  [string]$EnvFile = ".env",
  [switch]$ProductionOnly
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile

if (-not (Test-Path -LiteralPath $EnvPath)) {
  throw "Missing $EnvFile. Copy .env.example to $EnvFile and set required values."
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

$appEnv = Get-EnvValue "APP_ENV"
if (-not $appEnv) {
  $appEnv = "development"
}
$isProduction = $appEnv.Equals("production", [System.StringComparison]::OrdinalIgnoreCase)

if ($ProductionOnly -and -not $isProduction) {
  Write-Host "APP_ENV=$appEnv. Production env checks skipped."
  exit 0
}

$adminPassword = Get-EnvValue "ADMIN_PASSWORD"
$postgresPassword = Get-EnvValue "POSTGRES_PASSWORD"
$databaseUrl = Get-EnvValue "DATABASE_URL"
$baseDomain = Get-EnvValue "APP_BASE_DOMAIN"
$metaTokenKey = Get-EnvValue "META_TOKEN_KEY"

if (-not $postgresPassword -or $postgresPassword -eq "ab_password" -or $postgresPassword -eq "change_me_postgres") {
  throw "POSTGRES_PASSWORD must be set in $EnvFile and must not use a default placeholder."
}
if (-not $databaseUrl) {
  throw "DATABASE_URL must be set in $EnvFile."
}
if ($databaseUrl -match "ab_password|change_me_postgres") {
  throw "DATABASE_URL must not contain a default placeholder password."
}

if ($isProduction) {
  if (-not $adminPassword -or $adminPassword -eq "change_me" -or $adminPassword.Length -lt 12) {
    throw "APP_ENV=production requires ADMIN_PASSWORD with at least 12 characters and no default placeholder."
  }
  if (-not $baseDomain -or $baseDomain -eq "admin.example.com") {
    throw "APP_ENV=production requires APP_BASE_DOMAIN to be a real admin domain."
  }
  if (-not $metaTokenKey -or $metaTokenKey -eq "change_me_meta_token_key_at_least_32_bytes" -or $metaTokenKey.Length -lt 32) {
    throw "APP_ENV=production requires META_TOKEN_KEY with at least 32 characters and no default placeholder."
  }
}

Write-Host "Environment check passed for $EnvFile."
