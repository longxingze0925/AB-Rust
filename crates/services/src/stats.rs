use chrono::{DateTime, Utc};
use serde::Serialize;

use ab_db::DbPool;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DailyStat {
    pub day: String,
    pub visits: i64,
    pub downloads: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct VariantStat {
    pub page_variant: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RecentVisit {
    pub route_name: String,
    pub promo_code: String,
    pub page_variant: String,
    pub ip: Option<String>,
    pub downloaded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardStats {
    pub total_visits: i64,
    pub today_visits: i64,
    pub total_downloads: i64,
    pub today_downloads: i64,
    pub enabled_routes: i64,
    pub total_routes: i64,
    pub total_promos: i64,
    pub enabled_promos: i64,
    pub total_templates: i64,
    pub unique_devices: i64,
    pub fake_visits: i64,
    pub real_visits: i64,
    pub daily: Vec<DailyStat>,
    pub variants: Vec<VariantStat>,
    pub recent: Vec<RecentVisit>,
}

#[derive(Clone)]
pub struct StatsService {
    pool: DbPool,
}

impl StatsService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn dashboard(&self) -> anyhow::Result<DashboardStats> {
        let total_visits = scalar(&self.pool, "SELECT COUNT(*)::BIGINT FROM visits").await?;
        let today_visits = scalar(
            &self.pool,
            "SELECT COUNT(*)::BIGINT FROM visits WHERE created_at::DATE = CURRENT_DATE",
        )
        .await?;
        let total_downloads =
            scalar(&self.pool, "SELECT COUNT(*)::BIGINT FROM download_events").await?;
        let today_downloads = scalar(
            &self.pool,
            "SELECT COUNT(*)::BIGINT FROM download_events WHERE created_at::DATE = CURRENT_DATE",
        )
        .await?;
        let enabled_routes = scalar(
            &self.pool,
            "SELECT COUNT(*)::BIGINT FROM routes WHERE enabled = TRUE",
        )
        .await?;
        let total_routes = scalar(&self.pool, "SELECT COUNT(*)::BIGINT FROM routes").await?;
        let total_promos = scalar(&self.pool, "SELECT COUNT(*)::BIGINT FROM promo_codes").await?;
        let enabled_promos = scalar(
            &self.pool,
            "SELECT COUNT(*)::BIGINT FROM promo_codes WHERE enabled = TRUE",
        )
        .await?;
        let total_templates =
            scalar(&self.pool, "SELECT COUNT(*)::BIGINT FROM landing_templates").await?;
        let unique_devices = scalar(
            &self.pool,
            "SELECT COUNT(DISTINCT fingerprint)::BIGINT FROM visit_client_updates WHERE fingerprint <> ''",
        )
        .await?;
        let fake_visits = scalar(
            &self.pool,
            "SELECT COUNT(*)::BIGINT FROM visits WHERE page_variant = 'fake'",
        )
        .await?;
        let real_visits = scalar(
            &self.pool,
            "SELECT COUNT(*)::BIGINT FROM visits WHERE page_variant = 'real'",
        )
        .await?;

        let daily = sqlx::query_as::<_, DailyStat>(
            r#"
            WITH days AS (
              SELECT generate_series(CURRENT_DATE - INTERVAL '6 days', CURRENT_DATE, INTERVAL '1 day')::DATE AS day
            )
            SELECT
              to_char(days.day, 'MM-DD') AS day,
              COUNT(DISTINCT v.id)::BIGINT AS visits,
              COUNT(DISTINCT d.id)::BIGINT AS downloads
            FROM days
            LEFT JOIN visits v ON v.created_at::DATE = days.day
            LEFT JOIN download_events d ON d.created_at::DATE = days.day
            GROUP BY days.day
            ORDER BY days.day ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let variants = sqlx::query_as::<_, VariantStat>(
            r#"
            SELECT page_variant, COUNT(*)::BIGINT AS count
            FROM visits
            GROUP BY page_variant
            ORDER BY count DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let recent = sqlx::query_as::<_, RecentVisit>(
            r#"
            SELECT
              COALESCE(NULLIF(r.name, ''), r.entry_domain, '') AS route_name,
              v.promo_code,
              v.page_variant,
              v.ip::TEXT AS ip,
              EXISTS(SELECT 1 FROM download_events d WHERE d.visit_id = v.id) AS downloaded,
              v.created_at
            FROM visits v
            LEFT JOIN routes r ON r.id = v.route_id
            ORDER BY v.created_at DESC
            LIMIT 8
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(DashboardStats {
            total_visits,
            today_visits,
            total_downloads,
            today_downloads,
            enabled_routes,
            total_routes,
            total_promos,
            enabled_promos,
            total_templates,
            unique_devices,
            fake_visits,
            real_visits,
            daily,
            variants,
            recent,
        })
    }
}

async fn scalar(pool: &DbPool, sql: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar::<_, i64>(sql).fetch_one(pool).await?)
}
