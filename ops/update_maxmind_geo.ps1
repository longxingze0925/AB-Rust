param(
  [string]$EnvFile = ".env",
  [string]$WorkDir = "imports\maxmind",
  [string]$EditionCity = "GeoLite2-City-CSV",
  [string]$EditionAsn = "GeoLite2-ASN-CSV",
  [string]$LicenseKey = "",
  [string]$Locale = "en",
  [switch]$SkipDownload,
  [switch]$KeepWorkDir
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvPath = Join-Path $Root $EnvFile
$ComposeFile = Join-Path $Root "deploy\docker-compose.yml"
$TargetDir = Join-Path $Root $WorkDir
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$CityZip = Join-Path $TargetDir "$EditionCity-$Stamp.zip"
$AsnZip = Join-Path $TargetDir "$EditionAsn-$Stamp.zip"
$GeoCsv = Join-Path $TargetDir "ip_geo_maxmind-$Stamp.csv"
$SqlFile = Join-Path $TargetDir "ip_geo_maxmind-$Stamp.sql"

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

function Download-MaxMindEdition {
  param(
    [string]$Edition,
    [string]$OutFile
  )
  $url = "https://download.maxmind.com/app/geoip_download?edition_id=$Edition&license_key=$LicenseKey&suffix=zip"
  Write-Host "Downloading $Edition"
  Invoke-WebRequest -Uri $url -OutFile $OutFile -TimeoutSec 120
}

function Expand-Edition {
  param(
    [string]$ZipPath,
    [string]$Name
  )
  $dest = Join-Path $TargetDir $Name
  if (Test-Path -LiteralPath $dest) {
    Remove-Item -LiteralPath $dest -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Expand-Archive -LiteralPath $ZipPath -DestinationPath $dest -Force
  $inner = Get-ChildItem -LiteralPath $dest -Directory | Select-Object -First 1
  if ($inner) {
    return $inner.FullName
  }
  return $dest
}

if (-not (Test-Path -LiteralPath $EnvPath)) {
  throw "Missing $EnvFile. Copy .env.example to $EnvFile and set required values."
}

if (-not $LicenseKey) {
  $LicenseKey = Get-EnvValue "MAXMIND_LICENSE_KEY"
}

if (-not $SkipDownload -and -not $LicenseKey) {
  throw "MAXMIND_LICENSE_KEY is required unless -SkipDownload is used."
}

New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null

if (-not $SkipDownload) {
  Download-MaxMindEdition -Edition $EditionCity -OutFile $CityZip
  Download-MaxMindEdition -Edition $EditionAsn -OutFile $AsnZip
}

if (-not (Test-Path -LiteralPath $CityZip)) {
  $CityZip = (Get-ChildItem -LiteralPath $TargetDir -Filter "$EditionCity*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not (Test-Path -LiteralPath $AsnZip)) {
  $AsnZip = (Get-ChildItem -LiteralPath $TargetDir -Filter "$EditionAsn*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $CityZip -or -not (Test-Path -LiteralPath $CityZip)) {
  throw "City CSV zip not found in $TargetDir."
}
if (-not $AsnZip -or -not (Test-Path -LiteralPath $AsnZip)) {
  throw "ASN CSV zip not found in $TargetDir."
}

$CityDir = Expand-Edition -ZipPath $CityZip -Name "city"
$AsnDir = Expand-Edition -ZipPath $AsnZip -Name "asn"

python (Join-Path $PSScriptRoot "convert_maxmind_csv.py") --city-dir $CityDir --asn-dir $AsnDir --out $GeoCsv --locale $Locale --source maxmind
python (Join-Path $PSScriptRoot "import_ip_geo_csv.py") --csv $GeoCsv --out $SqlFile --source maxmind
Get-Content -LiteralPath $SqlFile -Encoding UTF8 | docker compose --env-file $EnvPath -f $ComposeFile exec -T postgres psql -U ab -d ab

Write-Host "Imported MaxMind IP geo data from $GeoCsv"

if (-not $KeepWorkDir) {
  Remove-Item -LiteralPath $CityDir -Recurse -Force
  Remove-Item -LiteralPath $AsnDir -Recurse -Force
}
