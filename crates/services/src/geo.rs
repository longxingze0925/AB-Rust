use ab_db::DbPool;
use chrono::{DateTime, Utc};
use maxminddb::{geoip2, Reader};
use serde::Serialize;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct GeoIpRange {
    pub id: Uuid,
    pub cidr: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct GeoIpHit {
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
}

#[derive(Debug, Clone)]
pub struct SaveGeoIpRangeInput {
    pub cidr: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub source: String,
}

#[derive(Clone)]
pub struct GeoIpService {
    pool: DbPool,
    data_dir: Arc<PathBuf>,
    file_cache: Arc<Mutex<GeoFileCache>>,
}

impl GeoIpService {
    pub fn new(pool: DbPool, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            data_dir: Arc::new(data_dir.into()),
            file_cache: Arc::new(Mutex::new(GeoFileCache::default())),
        }
    }

    pub async fn lookup(&self, ip: &str) -> anyhow::Result<Option<GeoIpHit>> {
        let ip = ip.trim();
        if ip.is_empty() {
            return Ok(None);
        }

        let db_hit = sqlx::query_as::<_, GeoIpHit>(
            r#"
            SELECT country, province, city, isp
            FROM ip_geo_ranges
            WHERE $1::inet <<= cidr
            ORDER BY masklen(cidr) DESC, updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await?;

        let ip_addr = ip.parse::<IpAddr>().ok();
        let file_hit = ip_addr.and_then(|ip_addr| {
            let mut cache = self
                .file_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.lookup(&self.data_dir, ip_addr)
        });

        Ok(merge_geo_hits(db_hit, file_hit))
    }

    pub async fn list(&self) -> anyhow::Result<Vec<GeoIpRange>> {
        let rows = sqlx::query_as::<_, GeoIpRange>(
            r#"
            SELECT
              id,
              cidr::TEXT AS cidr,
              country,
              province,
              city,
              isp,
              source,
              created_at,
              updated_at
            FROM ip_geo_ranges
            ORDER BY updated_at DESC, created_at DESC
            LIMIT 500
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn save(&self, input: SaveGeoIpRangeInput) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO ip_geo_ranges (cidr, country, province, city, isp, source)
            VALUES ($1::cidr, $2, $3, $4, $5, $6)
            ON CONFLICT (cidr) DO UPDATE SET
              country = EXCLUDED.country,
              province = EXCLUDED.province,
              city = EXCLUDED.city,
              isp = EXCLUDED.isp,
              source = EXCLUDED.source,
              updated_at = now()
            "#,
        )
        .bind(input.cidr.trim())
        .bind(input.country.trim())
        .bind(input.province.trim())
        .bind(input.city.trim())
        .bind(input.isp.trim())
        .bind(input.source.trim())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM ip_geo_ranges WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Default)]
struct GeoFileCache {
    city_loaded: bool,
    city_reader: Option<Reader<Vec<u8>>>,
    asn: AsnCache,
}

impl GeoFileCache {
    fn lookup(&mut self, data_dir: &Path, ip: IpAddr) -> Option<GeoIpHit> {
        let mut hit = GeoIpHit {
            country: String::new(),
            province: String::new(),
            city: String::new(),
            isp: String::new(),
        };

        if let Some(asn) = self.asn.lookup(data_dir, ip) {
            hit.country = asn.country;
            hit.isp = normalize_isp(&asn.org);
        }

        if let Some(city_hit) = self.lookup_city(data_dir, ip) {
            if !city_hit.country.is_empty() {
                hit.country = city_hit.country;
            }
            hit.province = city_hit.province;
            hit.city = city_hit.city;
        }

        (!hit.country.is_empty()
            || !hit.province.is_empty()
            || !hit.city.is_empty()
            || !hit.isp.is_empty())
        .then_some(hit)
    }

    fn lookup_city(&mut self, data_dir: &Path, ip: IpAddr) -> Option<GeoIpHit> {
        if !self.city_loaded {
            self.city_reader = load_city_reader(data_dir);
            self.city_loaded = true;
        }

        let reader = self.city_reader.as_ref()?;
        let result = reader.lookup(ip).ok()?;
        let city = result.decode::<geoip2::City<'_>>().ok()??;
        Some(GeoIpHit {
            country: localized_name(&city.country.names).unwrap_or_default(),
            province: city
                .subdivisions
                .first()
                .and_then(|item| localized_name(&item.names))
                .unwrap_or_default(),
            city: localized_name(&city.city.names).unwrap_or_default(),
            isp: String::new(),
        })
    }
}

fn load_city_reader(data_dir: &Path) -> Option<Reader<Vec<u8>>> {
    let geodata_dir = data_dir.join("geodata");
    let entries = std::fs::read_dir(&geodata_dir).ok()?;
    let mut files = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("mmdb"))
        })
        .collect::<Vec<_>>();
    files.sort();
    files.reverse();

    for file in files {
        match Reader::open_readfile(&file) {
            Ok(reader) => {
                tracing::info!(path = %file.display(), "loaded mmdb city database");
                return Some(reader);
            }
            Err(err) => {
                tracing::warn!(error = %err, path = %file.display(), "failed to load mmdb city database");
            }
        }
    }
    None
}

fn localized_name(names: &geoip2::Names<'_>) -> Option<String> {
    names
        .simplified_chinese
        .or(names.english)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn merge_geo_hits(db_hit: Option<GeoIpHit>, file_hit: Option<GeoIpHit>) -> Option<GeoIpHit> {
    match (db_hit, file_hit) {
        (None, None) => None,
        (Some(hit), None) | (None, Some(hit)) => Some(hit),
        (Some(mut db), Some(file)) => {
            if db.country.is_empty() {
                db.country = file.country;
            }
            if db.province.is_empty() {
                db.province = file.province;
            }
            if db.city.is_empty() {
                db.city = file.city;
            }
            if db.isp.is_empty() {
                db.isp = file.isp;
            }
            Some(db)
        }
    }
}

#[derive(Default)]
struct AsnCache {
    v4_loaded: bool,
    v6_loaded: bool,
    v4: Vec<AsnRange>,
    v6: Vec<AsnRange>,
}

impl AsnCache {
    fn lookup(&mut self, data_dir: &Path, ip: IpAddr) -> Option<AsnHit> {
        let version = if ip.is_ipv4() { "v4" } else { "v6" };
        if ip.is_ipv4() && !self.v4_loaded {
            self.v4 = load_asn_ranges(data_dir, version);
            self.v4_loaded = true;
        }
        if ip.is_ipv6() && !self.v6_loaded {
            self.v6 = load_asn_ranges(data_dir, version);
            self.v6_loaded = true;
        }

        let target = ip_to_u128(ip)?;
        let ranges = if ip.is_ipv4() { &self.v4 } else { &self.v6 };
        let mut lo = 0_usize;
        let mut hi = ranges.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let item = &ranges[mid];
            if target < item.start {
                hi = mid;
            } else if target > item.end {
                lo = mid + 1;
            } else {
                return Some(AsnHit {
                    country: item.country.clone(),
                    org: item.org.clone(),
                });
            }
        }
        None
    }
}

struct AsnHit {
    country: String,
    org: String,
}

struct AsnRange {
    start: u128,
    end: u128,
    country: String,
    org: String,
}

fn load_asn_ranges(data_dir: &Path, version: &str) -> Vec<AsnRange> {
    let file = data_dir
        .join("geodata")
        .join(format!("ip2asn-{version}.tsv"));
    let Ok(content) = std::fs::read_to_string(&file) else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    for line in content.lines() {
        let mut fields = line.split('\t');
        let start = fields.next().and_then(|value| value.parse::<IpAddr>().ok());
        let end = fields.next().and_then(|value| value.parse::<IpAddr>().ok());
        let _asn = fields.next();
        let country = fields.next().unwrap_or("").trim();
        let org = fields.next().unwrap_or("").trim();
        let (Some(start), Some(end)) = (start, end) else {
            continue;
        };
        let expect_v4 = version == "v4";
        if start.is_ipv4() != expect_v4 || end.is_ipv4() != expect_v4 {
            continue;
        }
        let Some(start) = ip_to_u128(start) else {
            continue;
        };
        let Some(end) = ip_to_u128(end) else {
            continue;
        };
        if start <= end && (!country.is_empty() || !org.is_empty()) {
            ranges.push(AsnRange {
                start,
                end,
                country: country.to_string(),
                org: org.to_string(),
            });
        }
    }
    ranges.sort_by_key(|range| range.start);
    tracing::info!(path = %file.display(), count = ranges.len(), "loaded geo ip2asn ranges");
    ranges
}

fn normalize_isp(desc: &str) -> String {
    let value = desc.to_ascii_uppercase();
    if value.contains("CHINANET") || value.contains("CHINA TELECOM") {
        return "中国电信".to_string();
    }
    if value.contains("CHINA169")
        || value.contains("CHINA UNICOM")
        || value.contains("UNICOM")
        || value.contains("CNCGROUP")
    {
        return "中国联通".to_string();
    }
    if value.contains("CHINA MOBILE") || value.contains("CMNET") || value.contains("CHINAMOBILE") {
        return "中国移动".to_string();
    }
    if value.contains("CERNET") {
        return "教育网".to_string();
    }
    if value.contains("CHINA BROADCASTING") || value.contains("CHINA CABLE") {
        return "中国广电".to_string();
    }
    desc.chars().take(40).collect()
}

fn ip_to_u128(ip: IpAddr) -> Option<u128> {
    match ip {
        IpAddr::V4(ip) => Some(u32::from(ip) as u128),
        IpAddr::V6(ip) => Some(u128::from(ip)),
    }
}
