use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RecordVisitInput {
    pub route_id: Uuid,
    pub promo_id: Option<Uuid>,
    pub promo_code: String,
    pub page_variant: String,
    pub cloak_reason: String,
    pub entry_domain: String,
    pub exit_domain: String,
    pub ip: Option<String>,
    pub ip_source: String,
    pub cf_ray: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub os: String,
    pub os_version: String,
    pub device: String,
    pub browser: String,
    pub language: String,
    pub referer: String,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct RecordDownloadInput {
    pub route_id: Option<Uuid>,
    pub visit_id: Option<Uuid>,
    pub promo_id: Option<Uuid>,
    pub event_id: String,
    pub apk_url: String,
}

#[derive(Debug, Clone)]
pub struct UpdateVisitClientInput {
    pub visit_id: Uuid,
    pub screen: String,
    pub timezone: String,
    pub network: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct VisitListQuery {
    pub page: i64,
    pub page_size: i64,
    pub promo: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct VisitRow {
    pub id: Uuid,
    pub route_name: String,
    pub promo_code: String,
    pub page_variant: String,
    pub cloak_reason: String,
    pub entry_domain: String,
    pub exit_domain: String,
    pub ip: Option<String>,
    pub ip_source: String,
    pub cf_ray: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub os: String,
    pub os_version: String,
    pub device: String,
    pub browser: String,
    pub language: String,
    pub referer: String,
    pub user_agent: String,
    pub screen: String,
    pub timezone: String,
    pub network: String,
    pub fingerprint: String,
    pub downloaded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisitListResult {
    pub rows: Vec<VisitRow>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
    pub pages: i64,
    pub promo: String,
}

#[derive(Clone)]
pub struct VisitsService {
    pool: DbPool,
}

impl VisitsService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn record(&self, input: RecordVisitInput) -> anyhow::Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO visits (
              route_id, promo_code, page_variant, cloak_reason,
              promo_id, entry_domain, exit_domain, ip, ip_source, cf_ray,
              country, province, city, isp, os, os_version, device, browser,
              language, referer, user_agent
            )
            VALUES (
              $1, $2, $3, $4,
              $5, $6, $7, $8::inet, $9, $10,
              $11, $12, $13, $14, $15, $16, $17, $18,
              $19, $20, $21
            )
            RETURNING id
            "#,
        )
        .bind(input.route_id)
        .bind(input.promo_code)
        .bind(input.page_variant)
        .bind(input.cloak_reason)
        .bind(input.promo_id)
        .bind(input.entry_domain)
        .bind(input.exit_domain)
        .bind(input.ip)
        .bind(input.ip_source)
        .bind(input.cf_ray)
        .bind(input.country)
        .bind(input.province)
        .bind(input.city)
        .bind(input.isp)
        .bind(input.os)
        .bind(input.os_version)
        .bind(input.device)
        .bind(input.browser)
        .bind(input.language)
        .bind(input.referer)
        .bind(input.user_agent)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn record_download(&self, input: RecordDownloadInput) -> anyhow::Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO download_events (route_id, visit_id, promo_id, event_id, apk_url)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (route_id, visit_id, event_id)
              WHERE route_id IS NOT NULL AND visit_id IS NOT NULL AND event_id <> ''
              DO UPDATE SET
                promo_id = COALESCE(download_events.promo_id, EXCLUDED.promo_id),
                apk_url = COALESCE(NULLIF(EXCLUDED.apk_url, ''), download_events.apk_url)
            RETURNING id
            "#,
        )
        .bind(input.route_id)
        .bind(input.visit_id)
        .bind(input.promo_id)
        .bind(input.event_id)
        .bind(input.apk_url)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn update_client(&self, input: UpdateVisitClientInput) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO visit_client_updates (visit_id, screen, timezone, network, fingerprint, updated_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (visit_id) DO UPDATE SET
              screen = EXCLUDED.screen,
            timezone = EXCLUDED.timezone,
              network = LEFT(EXCLUDED.network, 2000),
              fingerprint = LEFT(EXCLUDED.fingerprint, 128),
              updated_at = now()
            "#,
        )
        .bind(input.visit_id)
        .bind(input.screen)
        .bind(input.timezone)
        .bind(input.network)
        .bind(input.fingerprint)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list(&self, query: VisitListQuery) -> anyhow::Result<VisitListResult> {
        let page = query.page.max(1);
        let page_size = query.page_size.clamp(10, 200);
        let promo = query.promo.unwrap_or_default().trim().to_uppercase();
        let promo_filter = if promo.is_empty() {
            None
        } else {
            Some(promo.as_str())
        };
        let offset = (page - 1) * page_size;

        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM visits v
            WHERE ($1::TEXT IS NULL OR v.promo_code = $1)
            "#,
        )
        .bind(promo_filter)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, VisitRow>(
            r#"
            SELECT
              v.id,
              COALESCE(NULLIF(r.name, ''), r.entry_domain, '') AS route_name,
              v.promo_code,
              v.page_variant,
              v.cloak_reason,
              v.entry_domain,
              v.exit_domain,
              v.ip::TEXT AS ip,
              v.ip_source,
              v.cf_ray,
              v.country,
              v.province,
              v.city,
              v.isp,
              v.os,
              v.os_version,
              v.device,
              v.browser,
              v.language,
              v.referer,
              v.user_agent,
              COALESCE(c.screen, '') AS screen,
              COALESCE(c.timezone, '') AS timezone,
              COALESCE(c.network, '') AS network,
              COALESCE(c.fingerprint, '') AS fingerprint,
              EXISTS(SELECT 1 FROM download_events d WHERE d.visit_id = v.id OR (d.visit_id IS NULL AND d.route_id = v.route_id AND d.promo_id IS NOT DISTINCT FROM v.promo_id)) AS downloaded,
              v.created_at
            FROM visits v
            LEFT JOIN routes r ON r.id = v.route_id
            LEFT JOIN visit_client_updates c ON c.visit_id = v.id
            WHERE ($1::TEXT IS NULL OR v.promo_code = $1)
            ORDER BY v.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(promo_filter)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let pages = ((total + page_size - 1) / page_size).max(1);
        Ok(VisitListResult {
            rows,
            total,
            page,
            page_size,
            pages,
            promo,
        })
    }
}
