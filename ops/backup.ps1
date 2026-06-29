param(
  [string]$EnvFile = ".env",
  [string]$OutDir = "backups"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile
$ComposeFile = Join-Path $Root "deploy\docker-compose.yml"
$BackupDir = Join-Path $Root $OutDir
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$SqlFile = Join-Path $BackupDir "ab-$Stamp.sql"

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

docker compose --env-file $EnvPath -f $ComposeFile exec -T postgres pg_dump -U ab -d ab | Set-Content -LiteralPath $SqlFile -Encoding UTF8
Write-Host "Wrote $SqlFile"
