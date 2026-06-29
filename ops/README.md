# Ops

## Deploy

```powershell
Copy-Item .env.example .env
powershell -NoProfile -ExecutionPolicy Bypass -File ops/deploy.ps1 -Build
```

`ops/deploy.ps1` uses `deploy/docker-compose.yml`, starts PostgreSQL, the Rust app, and Caddy.
Before starting containers it runs `ops/validate-env.ps1`. Set `POSTGRES_PASSWORD` and `DATABASE_URL` to non-default values. For production, also set `APP_ENV=production`, a real `APP_BASE_DOMAIN`, an `ADMIN_PASSWORD` with at least 12 characters, and a `META_TOKEN_KEY` with at least 32 characters.

Run the environment check directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/validate-env.ps1
```

## Release With Smoke Check

Build the inactive app color, back up PostgreSQL, start the target container, run `/health`, switch Caddy traffic, and switch back if the smoke check fails:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/release.ps1
```

Useful options:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/release.ps1 -ImageTag 20260701-rc1
powershell -NoProfile -ExecutionPolicy Bypass -File ops/release.ps1 -BaseUrl https://admin.example.com
powershell -NoProfile -ExecutionPolicy Bypass -File ops/release.ps1 -SkipBackup
```

The Compose topology runs `app_blue` and `app_green` behind Caddy. `deploy/active_proxy.conf` and `deploy/active_tls_ask.conf` decide the active color. By default the release stops the old app after the new color passes smoke check; use `-KeepOldRunning` when you want a fast manual rollback window. Release history is appended to `data/release-history.jsonl` and shown in the admin settings page.

The Rust app runs SQLx migrations during startup. If a migration fails, the target container will not pass `/health`, `ops/release.ps1` will stop before switching traffic, and the previous active color remains in service. Before a production release that contains a new migration, run the release once against a staging database or start the target color internally and check its logs.

Check active color and container status:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/status.ps1
```

`ops/status.ps1` also prints the latest release history entries when `data/release-history.jsonl` exists.

## Smoke Check

Run the production health check directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/smoke.ps1 -BaseUrl https://admin.example.com
```

Check an internal color before switching traffic:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/smoke.ps1 -Service app_green
```

## Backup

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/backup.ps1
```

The backup script writes a PostgreSQL dump to `backups/ab-YYYYMMDD-HHMMSS.sql`.
Meta CAPI tokens are encrypted with `META_TOKEN_KEY` before being stored, but database dumps should still be treated as sensitive secrets. Existing plaintext tokens remain readable for compatibility; after `META_TOKEN_KEY` is configured, re-save each Meta route config once to write encrypted tokens back to PostgreSQL.

## Import Legacy SQLite

Generate SQL from the old Next.js SQLite database:

```powershell
python ops/import_legacy_sqlite.py --sqlite C:\Users\1\Desktop\ab\data\app.db --out imports\legacy.sql
```

Review `imports\legacy.sql`, then import it:

```powershell
Get-Content imports\legacy.sql | docker compose --env-file .env -f deploy/docker-compose.yml exec -T postgres psql -U ab -d ab
```

The importer maps legacy routes, targets, landing config, cloak config, Meta config, promos, visits, download flags, templates, IP blacklist, and domain allowlist. It does not copy uploaded files; copy legacy `DATA_DIR\uploads` and `DATA_DIR\landing-templates` manually if those directories exist.

## Import IP Geo CSV

Generate SQL for the local IP geo fallback table:

```powershell
python ops/import_ip_geo_csv.py --csv imports\ip_geo.csv --out imports\ip_geo.sql --source manual
```

CSV columns:

```text
cidr,country,province,city,isp,source
203.0.113.0/24,US,California,Los Angeles,Example ISP,manual
```

Import it:

```powershell
Get-Content imports\ip_geo.sql | docker compose --env-file .env -f deploy/docker-compose.yml exec -T postgres psql -U ab -d ab
```

## MaxMind IP Geo Update

Set `MAXMIND_LICENSE_KEY` in `.env`, then download GeoLite2 City/ASN CSV, convert it to the local IP geo format, generate SQL, and import it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/update_maxmind_geo.ps1
```

Useful options:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/update_maxmind_geo.ps1 -Locale en
powershell -NoProfile -ExecutionPolicy Bypass -File ops/update_maxmind_geo.ps1 -WorkDir imports\maxmind
powershell -NoProfile -ExecutionPolicy Bypass -File ops/update_maxmind_geo.ps1 -SkipDownload
```

Manual conversion is also available:

```powershell
python ops/convert_maxmind_csv.py --city-dir imports\maxmind\city --asn-dir imports\maxmind\asn --out imports\ip_geo_maxmind.csv
python ops/import_ip_geo_csv.py --csv imports\ip_geo_maxmind.csv --out imports\ip_geo_maxmind.sql --source maxmind
```

The first converter merges City blocks and locations, then fills ASN organization by checking whether an ASN network contains the City network. IPv4 and IPv6 ranges are indexed separately.
