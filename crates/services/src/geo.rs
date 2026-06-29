use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::Serialize;
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
}

impl GeoIpService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn lookup(&self, ip: &str) -> anyhow::Result<Option<GeoIpHit>> {
        let ip = ip.trim();
        if ip.is_empty() {
            return Ok(None);
        }

        let hit = sqlx::query_as::<_, GeoIpHit>(
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
        Ok(hit)
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
