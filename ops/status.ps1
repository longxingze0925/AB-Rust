param(
  [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile
$ComposeFile = Join-Path $Root "deploy\docker-compose.yml"
$ActiveProxyFile = Join-Path $Root "deploy\active_proxy.conf"
$ReleaseHistoryFile = Join-Path $Root "data\release-history.jsonl"

$active = "blue"
if (Test-Path -LiteralPath $ActiveProxyFile) {
  $content = Get-Content -LiteralPath $ActiveProxyFile -Raw -Encoding UTF8
  if ($content -match "app_green:3000") {
    $active = "green"
  }
}

Write-Host "Active app: app_$active"
if (Test-Path -LiteralPath $ReleaseHistoryFile) {
  Write-Host "Recent releases:"
  Get-Content -LiteralPath $ReleaseHistoryFile -Encoding UTF8 |
    Select-Object -Last 5 |
    ForEach-Object {
      $item = $_ | ConvertFrom-Json
      Write-Host "  $($item.timestamp) $($item.status) $($item.from_color)->$($item.to_color) $($item.image)"
    }
}
docker compose --env-file $EnvPath -f $ComposeFile ps
