use chrono::{DateTime, Utc};
use serde::Serialize;

use ab_db::DbPool;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DailyStat {
    pub day: String,
    pub visits: i64,
    pub downloads: i64,
    pub real_downloads: i64,
    pub fake_downloads: i64,
    pub unique_device_downloads: i64,
    pub unique_ip_downloads: i64,
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
    pub real_downloads: i64,
    pub today_real_downloads: i64,
    pub fake_downloads: i64,
    pub today_fake_downloads: i64,
    pub unique_device_downloads: i64,
    pub today_unique_device_downloads: i64,
    pub unique_ip_downloads: i64,
    pub today_unique_ip_downloads: i64,
    pub enabled_routes: i64,
    pub total_routes: i64,
    pub total_promos: i64,
    pub enabled_promos: i64,
    pub total_landing_profiles: i64,
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
            r#"
            SELECT COUNT(*)::BIGINT
            FROM visits
            WHERE created_at >= ((now() AT TIME ZONE 'Asia/Shanghai')::DATE::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND created_at < (((now() AT TIME ZONE 'Asia/Shanghai')::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
            "#,
        )
        .await?;
        let total_downloads =
            scalar(&self.pool, "SELECT COUNT(*)::BIGINT FROM download_events").await?;
        let today_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(*)::BIGINT
            FROM download_events
            WHERE created_at >= ((now() AT TIME ZONE 'Asia/Shanghai')::DATE::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND created_at < (((now() AT TIME ZONE 'Asia/Shanghai')::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
            "#,
        )
        .await?;
        let real_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(*)::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            WHERE v.page_variant = 'real'
            "#,
        )
        .await?;
        let today_real_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(*)::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            WHERE d.created_at >= ((now() AT TIME ZONE 'Asia/Shanghai')::DATE::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND d.created_at < (((now() AT TIME ZONE 'Asia/Shanghai')::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND v.page_variant = 'real'
            "#,
        )
        .await?;
        let fake_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(*)::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            WHERE v.page_variant = 'fake'
            "#,
        )
        .await?;
        let today_fake_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(*)::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            WHERE d.created_at >= ((now() AT TIME ZONE 'Asia/Shanghai')::DATE::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND d.created_at < (((now() AT TIME ZONE 'Asia/Shanghai')::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND v.page_variant = 'fake'
            "#,
        )
        .await?;
        let unique_device_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(DISTINCT COALESCE(NULLIF(c.fingerprint, ''), v.ip::TEXT || '|' || v.user_agent))::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            LEFT JOIN visit_client_updates c ON c.visit_id = v.id
            WHERE COALESCE(NULLIF(c.fingerprint, ''), v.ip::TEXT || '|' || v.user_agent) <> ''
            "#,
        )
        .await?;
        let today_unique_device_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(DISTINCT COALESCE(NULLIF(c.fingerprint, ''), v.ip::TEXT || '|' || v.user_agent))::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            LEFT JOIN visit_client_updates c ON c.visit_id = v.id
            WHERE d.created_at >= ((now() AT TIME ZONE 'Asia/Shanghai')::DATE::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND d.created_at < (((now() AT TIME ZONE 'Asia/Shanghai')::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND COALESCE(NULLIF(c.fingerprint, ''), v.ip::TEXT || '|' || v.user_agent) <> ''
            "#,
        )
        .await?;
        let unique_ip_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(DISTINCT v.ip)::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            WHERE v.ip IS NOT NULL
            "#,
        )
        .await?;
        let today_unique_ip_downloads = scalar(
            &self.pool,
            r#"
            SELECT COUNT(DISTINCT v.ip)::BIGINT
            FROM download_events d
            JOIN visits v ON v.id = d.visit_id
            WHERE d.created_at >= ((now() AT TIME ZONE 'Asia/Shanghai')::DATE::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND d.created_at < (((now() AT TIME ZONE 'Asia/Shanghai')::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
              AND v.ip IS NOT NULL
            "#,
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
        let total_landing_profiles =
            scalar(&self.pool, "SELECT COUNT(*)::BIGINT FROM landing_profiles").await?;
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
            WITH local_today AS (
              SELECT (now() AT TIME ZONE 'Asia/Shanghai')::DATE AS day
            ), days AS (
              SELECT generate_series(local_today.day - INTERVAL '6 days', local_today.day, INTERVAL '1 day')::DATE AS day
              FROM local_today
            )
            SELECT
              to_char(days.day, 'MM-DD') AS day,
              COUNT(DISTINCT v.id)::BIGINT AS visits,
              COUNT(DISTINCT d.id)::BIGINT AS downloads,
              COUNT(DISTINCT d.id) FILTER (WHERE dv.page_variant = 'real')::BIGINT AS real_downloads,
              COUNT(DISTINCT d.id) FILTER (WHERE dv.page_variant = 'fake')::BIGINT AS fake_downloads,
              COUNT(DISTINCT COALESCE(NULLIF(c.fingerprint, ''), dv.ip::TEXT || '|' || dv.user_agent))
                FILTER (WHERE COALESCE(NULLIF(c.fingerprint, ''), dv.ip::TEXT || '|' || dv.user_agent) <> '')::BIGINT
                AS unique_device_downloads,
              COUNT(DISTINCT dv.ip) FILTER (WHERE dv.ip IS NOT NULL)::BIGINT AS unique_ip_downloads
            FROM days
            LEFT JOIN visits v
              ON v.created_at >= (days.day::timestamp AT TIME ZONE 'Asia/Shanghai')
             AND v.created_at < ((days.day + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
            LEFT JOIN download_events d
              ON d.created_at >= (days.day::timestamp AT TIME ZONE 'Asia/Shanghai')
             AND d.created_at < ((days.day + 1)::timestamp AT TIME ZONE 'Asia/Shanghai')
            LEFT JOIN visits dv ON dv.id = d.visit_id
            LEFT JOIN visit_client_updates c ON c.visit_id = dv.id
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
            real_downloads,
            today_real_downloads,
            fake_downloads,
            today_fake_downloads,
            unique_device_downloads,
            today_unique_device_downloads,
            unique_ip_downloads,
            today_unique_ip_downloads,
            enabled_routes,
            total_routes,
            total_promos,
            enabled_promos,
            total_landing_profiles,
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
