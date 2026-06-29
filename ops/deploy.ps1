param(
  [string]$EnvFile = ".env",
  [switch]$Build,
  [switch]$Pull
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile
$ComposeFile = Join-Path $Root "deploy\docker-compose.yml"
$ActiveProxyFile = Join-Path $Root "deploy\active_proxy.conf"
$ActiveTlsAskFile = Join-Path $Root "deploy\active_tls_ask.conf"

if (-not (Test-Path -LiteralPath $EnvPath)) {
  throw "Missing $EnvFile. Copy .env.example to $EnvFile and set ADMIN_PASSWORD, POSTGRES_PASSWORD, APP_BASE_DOMAIN."
}

& (Join-Path $PSScriptRoot "validate-env.ps1") -EnvFile $EnvFile

if ($Pull) {
  docker compose --env-file $EnvPath -f $ComposeFile pull
}

if (-not (Test-Path -LiteralPath $ActiveProxyFile)) {
  Set-Content -LiteralPath $ActiveProxyFile -Value "to app_blue:3000" -Encoding UTF8
}
if (-not (Test-Path -LiteralPath $ActiveTlsAskFile)) {
  Set-Content -LiteralPath $ActiveTlsAskFile -Value "ask http://app_blue:3000/api/tls-check" -Encoding UTF8
}

$args = @("compose", "--env-file", $EnvPath, "-f", $ComposeFile, "up", "-d")
if ($Build) {
  $args += "--build"
}

docker @args
docker compose --env-file $EnvPath -f $ComposeFile ps
