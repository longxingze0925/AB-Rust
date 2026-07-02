param(
  [string]$EnvFile = ".env",
  [switch]$Build,
  [switch]$Pull,
  [switch]$Local
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile
$ComposeFile = Join-Path $Root "deploy\docker-compose.yml"
$LocalComposeFile = Join-Path $Root "deploy\docker-compose.local.yml"
$ActiveProxyFile = Join-Path $Root "deploy\active_proxy.conf"
$ActiveTlsAskFile = Join-Path $Root "deploy\active_tls_ask.conf"

if (-not (Test-Path -LiteralPath $EnvPath)) {
  throw "Missing $EnvFile. Copy .env.example to $EnvFile and set ADMIN_PASSWORD, POSTGRES_PASSWORD, APP_BASE_DOMAIN."
}

& (Join-Path $PSScriptRoot "validate-env.ps1") -EnvFile $EnvFile

$ComposeFiles = @($ComposeFile)
if ($Local) {
  if (-not (Test-Path -LiteralPath $LocalComposeFile)) {
    throw "Missing deploy\docker-compose.local.yml. Remove -Local or add the local override file."
  }
  $ComposeFiles += $LocalComposeFile
}

function Invoke-Docker {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DockerArgs)
  & docker @DockerArgs
  if ($LASTEXITCODE -ne 0) {
    throw "docker $($DockerArgs -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Get-ComposeBaseArgs {
  $args = @("compose", "--env-file", $EnvPath)
  foreach ($file in $ComposeFiles) {
    $args += @("-f", $file)
  }
  return $args
}

function Invoke-DockerCompose {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ComposeArgs)
  $dockerArgs = Get-ComposeBaseArgs
  $dockerArgs += $ComposeArgs
  Invoke-Docker @dockerArgs
}

function Get-EnvValue {
  param(
    [string]$Name,
    [string]$Default = ""
  )
  $escapedName = [regex]::Escape($Name)
  $line = Get-Content -LiteralPath $EnvPath -Encoding UTF8 |
    Where-Object { $_ -match "^\s*$escapedName\s*=" } |
    Select-Object -First 1
  if (-not $line) {
    return $Default
  }
  return ($line -split "=", 2)[1].Trim().Trim('"').Trim("'")
}

function Get-AppImage {
  param([string]$Color)
  $image = Get-EnvValue "APP_IMAGE_$($Color.ToUpperInvariant())"
  if ($image) {
    return $image
  }
  return "ghcr.io/longxingze0925/ab-rust:latest"
}

function Invoke-AppBuild {
  $blueImage = Get-AppImage "blue"
  $greenImage = Get-AppImage "green"

  if ($blueImage -eq $greenImage) {
    Write-Host "Building app image once via app_blue: $blueImage"
    Invoke-DockerCompose build app_blue
    return
  }

  Write-Host "Building app_blue image: $blueImage"
  Invoke-DockerCompose build app_blue
  Write-Host "Building app_green image: $greenImage"
  Invoke-DockerCompose build app_green
}

if ($Pull) {
  Invoke-DockerCompose pull
}

if (-not (Test-Path -LiteralPath $ActiveProxyFile)) {
  Set-Content -LiteralPath $ActiveProxyFile -Value "to app_blue:3000" -Encoding UTF8
}
if (-not (Test-Path -LiteralPath $ActiveTlsAskFile)) {
  Set-Content -LiteralPath $ActiveTlsAskFile -Value "ask http://app_blue:3000/api/tls-check" -Encoding UTF8
}

if ($Build) {
  Invoke-AppBuild
}

$upArgs = @("up", "-d")
if ($Build) {
  $upArgs += "--no-build"
}

Invoke-DockerCompose @upArgs
Invoke-DockerCompose ps
