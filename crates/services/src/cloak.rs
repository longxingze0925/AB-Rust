use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CloakRouteConfig {
    pub route_id: Uuid,
    pub route_name: String,
    pub entry_domain: String,
    pub enabled: bool,
    pub threshold: i32,
    pub token_hours: i32,
    pub decoy_title: String,
    pub decoy_apk_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveCloakInput {
    pub route_id: Uuid,
    pub enabled: bool,
    pub threshold: i32,
    pub token_hours: i32,
    pub decoy_title: String,
    pub decoy_apk_url: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct IpBlacklistRow {
    pub id: Uuid,
    pub cidr: String,
    pub note: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CloakDecision {
    pub fake: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CloakCheckInput<'a> {
    pub route_id: Uuid,
    pub ip: Option<&'a str>,
    pub user_agent: &'a str,
    pub accept_language: &'a str,
    pub sec_ch_ua: &'a str,
    pub sec_fetch_site: &'a str,
}

#[derive(Clone)]
pub struct CloakService {
    pool: DbPool,
}

impl CloakService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_route_configs(&self) -> anyhow::Result<Vec<CloakRouteConfig>> {
        let rows = sqlx::query_as::<_, CloakRouteConfig>(
            r#"
            SELECT
              r.id AS route_id,
              COALESCE(NULLIF(r.name, ''), r.entry_domain) AS route_name,
              r.entry_domain,
              COALESCE(c.enabled, FALSE) AS enabled,
              COALESCE(c.threshold, 8) AS threshold,
              COALESCE(c.token_hours, 6) AS token_hours,
              COALESCE(c.decoy_title, '下载') AS decoy_title,
              COALESCE(c.decoy_apk_url, '') AS decoy_apk_url
            FROM routes r
            LEFT JOIN route_cloak_configs c ON c.route_id = r.id
            ORDER BY r.updated_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn save_route_config(&self, input: SaveCloakInput) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO route_cloak_configs (
              route_id, enabled, threshold, token_hours, decoy_title, decoy_apk_url
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (route_id) DO UPDATE SET
              enabled = EXCLUDED.enabled,
              threshold = EXCLUDED.threshold,
              token_hours = EXCLUDED.token_hours,
              decoy_title = EXCLUDED.decoy_title,
              decoy_apk_url = EXCLUDED.decoy_apk_url
            "#,
        )
        .bind(input.route_id)
        .bind(input.enabled)
        .bind(input.threshold.max(1))
        .bind(input.token_hours.max(1))
        .bind(input.decoy_title.trim())
        .bind(input.decoy_apk_url.trim())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_blacklist(&self) -> anyhow::Result<Vec<IpBlacklistRow>> {
        let rows = sqlx::query_as::<_, IpBlacklistRow>(
            r#"
            SELECT id, cidr::TEXT AS cidr, note, created_at
            FROM ip_blacklist
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn add_blacklist(&self, cidr: &str, note: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO ip_blacklist (cidr, note)
            VALUES ($1::cidr, $2)
            ON CONFLICT (cidr) DO UPDATE SET note = EXCLUDED.note
            "#,
        )
        .bind(cidr.trim())
        .bind(note.trim())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_blacklist(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM ip_blacklist WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn decide(&self, input: CloakCheckInput<'_>) -> anyhow::Result<CloakDecision> {
        let (enabled, threshold) = sqlx::query_as::<_, (bool, i32)>(
            r#"
            SELECT COALESCE(enabled, FALSE), COALESCE(threshold, 8)
            FROM route_cloak_configs
            WHERE route_id = $1
            "#,
        )
        .bind(input.route_id)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or((false, 8));

        if !enabled {
            return Ok(CloakDecision {
                fake: false,
                reason: "分流关闭".to_string(),
            });
        }

        if let Some(ip) = input.ip.filter(|value| !value.is_empty()) {
            let blacklisted = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM ip_blacklist WHERE $1::inet <<= cidr)",
            )
            .bind(ip)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(false);
            if blacklisted {
                return Ok(CloakDecision {
                    fake: true,
                    reason: "命中 IP 黑名单".to_string(),
                });
            }
        }

        let (score, reasons) = score_request(&input);
        if score >= threshold.max(1) {
            return Ok(CloakDecision {
                fake: true,
                reason: format!("风险分 {score}/{threshold}: {}", reasons.join("，")),
            });
        }

        Ok(CloakDecision {
            fake: false,
            reason: format!("分流通过，风险分 {score}/{threshold}"),
        })
    }

    pub async fn decoy_for_route(&self, route_id: Uuid) -> anyhow::Result<(String, String)> {
        let row = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT COALESCE(decoy_title, '下载'), COALESCE(decoy_apk_url, '')
            FROM route_cloak_configs
            WHERE route_id = $1
            "#,
        )
        .bind(route_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.unwrap_or_else(|| ("下载".to_string(), String::new())))
    }
}

fn score_request(input: &CloakCheckInput<'_>) -> (i32, Vec<String>) {
    let mut score = 0;
    let mut reasons = Vec::new();
    let ua = input.user_agent.trim();
    let ua_lower = ua.to_ascii_lowercase();

    if ua.is_empty() {
        score += 6;
        reasons.push("UA 为空".to_string());
    } else if ua.len() < 20 {
        score += 4;
        reasons.push("UA 过短".to_string());
    }

    if is_bot_ua(&ua_lower) {
        score += 10;
        reasons.push("爬虫 UA".to_string());
    }
    if is_cli_ua(&ua_lower) {
        score += 10;
        reasons.push("命令行客户端".to_string());
    }
    if ua_lower.contains("headless") || ua_lower.contains("phantomjs") {
        score += 8;
        reasons.push("无头浏览器特征".to_string());
    }
    if input.accept_language.trim().is_empty() {
        score += 2;
        reasons.push("缺少 Accept-Language".to_string());
    }
    if looks_like_browser(&ua_lower) && input.sec_ch_ua.trim().is_empty() {
        score += 1;
        reasons.push("缺少 Sec-CH-UA".to_string());
    }
    if !input.sec_fetch_site.trim().is_empty()
        && !matches!(
            input.sec_fetch_site.trim(),
            "none" | "same-origin" | "same-site" | "cross-site"
        )
    {
        score += 2;
        reasons.push("Sec-Fetch-Site 异常".to_string());
    }

    if reasons.is_empty() {
        reasons.push("未命中风险规则".to_string());
    }
    (score, reasons)
}

fn is_bot_ua(user_agent: &str) -> bool {
    const HINTS: &[&str] = &[
        "bot",
        "crawler",
        "spider",
        "curl/",
        "wget/",
        "python-requests",
        "headlesschrome",
        "phantomjs",
        "facebookexternalhit",
        "bytespider",
        "gptbot",
        "claudebot",
        "chatgpt-user",
    ];
    HINTS.iter().any(|hint| user_agent.contains(hint))
}

fn is_cli_ua(user_agent: &str) -> bool {
    const HINTS: &[&str] = &[
        "curl/",
        "wget/",
        "python-requests",
        "httpclient",
        "okhttp",
        "go-http-client",
        "postmanruntime",
        "libwww-perl",
    ];
    HINTS.iter().any(|hint| user_agent.contains(hint))
}

fn looks_like_browser(user_agent: &str) -> bool {
    user_agent.contains("mozilla/")
        || user_agent.contains("chrome/")
        || user_agent.contains("safari/")
        || user_agent.contains("firefox/")
}
