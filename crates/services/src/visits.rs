use ab_db::DbPool;
use chrono::{DateTime, NaiveDate, Utc};
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
    pub q: Option<String>,
    pub promo: Option<String>,
    pub page_variant: Option<String>,
    pub downloaded: Option<String>,
    pub ip: Option<String>,
    pub date_from: Option<NaiveDate>,
    pub date_to: Option<NaiveDate>,
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
    pub q: String,
    pub promo: String,
    pub page_variant: String,
    pub downloaded: String,
    pub ip: String,
    pub date_from: String,
    pub date_to: String,
    pub query_string: String,
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

    pub async fn complete_probe_visit(
        &self,
        id: Uuid,
        page_variant: &str,
        cloak_reason: &str,
        promo_id: Option<Uuid>,
        promo_code: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE visits
            SET page_variant = $2,
                cloak_reason = $3,
                promo_id = $4,
                promo_code = $5
            WHERE id = $1
              AND page_variant IN ('probe', $2)
            "#,
        )
        .bind(id)
        .bind(page_variant)
        .bind(cloak_reason)
        .bind(promo_id)
        .bind(promo_code)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn belongs_to_route(&self, id: Uuid, route_id: Uuid) -> anyhow::Result<bool> {
        let belongs = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM visits WHERE id = $1 AND route_id = $2)",
        )
        .bind(id)
        .bind(route_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(belongs)
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
        let q = query.q.unwrap_or_default().trim().to_string();
        let promo = query.promo.unwrap_or_default().trim().to_uppercase();
        let page_variant = normalize_variant(query.page_variant);
        let downloaded = normalize_downloaded(query.downloaded);
        let ip = query.ip.unwrap_or_default().trim().to_string();
        let date_from = query.date_from;
        let date_to = query.date_to;
        let q_like = like_contains(&q.to_lowercase());
        let promo_filter = if promo.is_empty() {
            None
        } else {
            Some(promo.as_str())
        };
        let variant_filter = if page_variant.is_empty() {
            None
        } else {
            Some(page_variant.as_str())
        };
        let downloaded_filter = match downloaded.as_str() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        };
        let ip_like = like_contains(&ip);
        let offset = (page - 1) * page_size;

        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM visits v
            LEFT JOIN routes r ON r.id = v.route_id
            LEFT JOIN visit_client_updates c ON c.visit_id = v.id
            WHERE ($1::TEXT IS NULL OR (
                LOWER(COALESCE(NULLIF(r.name, ''), r.entry_domain, '')) LIKE $1 ESCAPE '\'
                OR LOWER(v.promo_code) LIKE $1 ESCAPE '\'
                OR LOWER(v.entry_domain) LIKE $1 ESCAPE '\'
                OR LOWER(v.exit_domain) LIKE $1 ESCAPE '\'
                OR v.ip::TEXT LIKE $1 ESCAPE '\'
                OR LOWER(COALESCE(c.fingerprint, '')) LIKE $1 ESCAPE '\'
              ))
              AND ($2::TEXT IS NULL OR v.promo_code = $2)
              AND ($3::TEXT IS NULL OR v.page_variant = $3)
              AND ($4::BOOL IS NULL OR EXISTS(SELECT 1 FROM download_events d WHERE d.visit_id = v.id) = $4)
              AND ($5::TEXT IS NULL OR v.ip::TEXT LIKE $5 ESCAPE '\')
              AND ($6::DATE IS NULL OR v.created_at >= ($6::DATE::timestamp AT TIME ZONE 'Asia/Shanghai'))
              AND ($7::DATE IS NULL OR v.created_at < (($7::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai'))
            "#,
        )
        .bind(q_like.as_deref())
        .bind(promo_filter)
        .bind(variant_filter)
        .bind(downloaded_filter)
        .bind(ip_like.as_deref())
        .bind(date_from)
        .bind(date_to)
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
              EXISTS(SELECT 1 FROM download_events d WHERE d.visit_id = v.id) AS downloaded,
              v.created_at
            FROM visits v
            LEFT JOIN routes r ON r.id = v.route_id
            LEFT JOIN visit_client_updates c ON c.visit_id = v.id
            WHERE ($1::TEXT IS NULL OR (
                LOWER(COALESCE(NULLIF(r.name, ''), r.entry_domain, '')) LIKE $1 ESCAPE '\'
                OR LOWER(v.promo_code) LIKE $1 ESCAPE '\'
                OR LOWER(v.entry_domain) LIKE $1 ESCAPE '\'
                OR LOWER(v.exit_domain) LIKE $1 ESCAPE '\'
                OR v.ip::TEXT LIKE $1 ESCAPE '\'
                OR LOWER(COALESCE(c.fingerprint, '')) LIKE $1 ESCAPE '\'
              ))
              AND ($2::TEXT IS NULL OR v.promo_code = $2)
              AND ($3::TEXT IS NULL OR v.page_variant = $3)
              AND ($4::BOOL IS NULL OR EXISTS(SELECT 1 FROM download_events d WHERE d.visit_id = v.id) = $4)
              AND ($5::TEXT IS NULL OR v.ip::TEXT LIKE $5 ESCAPE '\')
              AND ($6::DATE IS NULL OR v.created_at >= ($6::DATE::timestamp AT TIME ZONE 'Asia/Shanghai'))
              AND ($7::DATE IS NULL OR v.created_at < (($7::DATE + 1)::timestamp AT TIME ZONE 'Asia/Shanghai'))
            ORDER BY v.created_at DESC
            LIMIT $8 OFFSET $9
            "#,
        )
        .bind(q_like.as_deref())
        .bind(promo_filter)
        .bind(variant_filter)
        .bind(downloaded_filter)
        .bind(ip_like.as_deref())
        .bind(date_from)
        .bind(date_to)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let pages = ((total + page_size - 1) / page_size).max(1);
        let date_from_text = date_from.map(|date| date.to_string()).unwrap_or_default();
        let date_to_text = date_to.map(|date| date.to_string()).unwrap_or_default();
        let query_string = visit_query_string(
            page_size,
            &q,
            &promo,
            &page_variant,
            &downloaded,
            &ip,
            &date_from_text,
            &date_to_text,
        );
        Ok(VisitListResult {
            rows,
            total,
            page,
            page_size,
            pages,
            q,
            promo,
            page_variant,
            downloaded,
            ip,
            date_from: date_from_text,
            date_to: date_to_text,
            query_string,
        })
    }
}

fn normalize_variant(value: Option<String>) -> String {
    match value.unwrap_or_default().trim() {
        "real" => "real".to_string(),
        "fake" => "fake".to_string(),
        "probe" => "probe".to_string(),
        _ => String::new(),
    }
}

fn normalize_downloaded(value: Option<String>) -> String {
    match value.unwrap_or_default().trim() {
        "yes" => "yes".to_string(),
        "no" => "no".to_string(),
        _ => String::new(),
    }
}

fn like_contains(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(format!("%{}%", escape_like(value)))
}

fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn visit_query_string(
    page_size: i64,
    q: &str,
    promo: &str,
    page_variant: &str,
    downloaded: &str,
    ip: &str,
    date_from: &str,
    date_to: &str,
) -> String {
    let mut pairs = vec![format!("size={page_size}")];
    push_query_pair(&mut pairs, "q", q);
    push_query_pair(&mut pairs, "promo", promo);
    push_query_pair(&mut pairs, "page_variant", page_variant);
    push_query_pair(&mut pairs, "downloaded", downloaded);
    push_query_pair(&mut pairs, "ip", ip);
    push_query_pair(&mut pairs, "date_from", date_from);
    push_query_pair(&mut pairs, "date_to", date_to);
    pairs.join("&")
}

fn push_query_pair(pairs: &mut Vec<String>, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    pairs.push(format!("{key}={}", encode_query_value(value)));
}

fn encode_query_value(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            _ => {
                let encoded = format!("%{byte:02X}");
                encoded.chars().collect()
            }
        })
        .collect()
}
