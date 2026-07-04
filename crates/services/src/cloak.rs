use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};
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

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CloakRuntimeConfig {
    pub route_id: Uuid,
    pub enabled: bool,
    pub threshold: i32,
    pub token_hours: i32,
    pub decoy_title: String,
    pub decoy_image_asset_id: Option<Uuid>,
    pub decoy_apk_url: String,
    pub use_ip_blacklist: bool,
    pub use_header_rules: bool,
    pub require_sec_fetch_mode: bool,
    pub use_js_probe: bool,
    pub use_asn: bool,
    pub use_ptr: bool,
    pub block_datacenter_asn: bool,
    pub block_datacenter_ptr: bool,
    pub block_verified_bot_ptr: bool,
    pub ptr_timeout_ms: i32,
    pub ptr_cache_hours: i32,
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
pub struct CloakServerVerdict {
    pub bot: bool,
    pub reason: String,
    pub header_score: i32,
}

#[derive(Debug, Clone)]
pub struct CloakCheckInput<'a> {
    pub route_id: Uuid,
    pub ip: Option<&'a str>,
    pub user_agent: &'a str,
    pub accept_language: &'a str,
    pub sec_ch_ua: &'a str,
    pub sec_fetch_site: &'a str,
    pub sec_fetch_mode: &'a str,
    pub sec_fetch_dest: &'a str,
    pub sec_fetch_user: &'a str,
    pub upgrade_insecure_requests: &'a str,
    pub accept: &'a str,
    pub accept_encoding: &'a str,
    pub include_ptr: bool,
}

#[derive(Clone)]
pub struct CloakService {
    pool: DbPool,
    data_dir: Arc<PathBuf>,
    asn_cache: Arc<Mutex<AsnCache>>,
    runtime_cache: Arc<Mutex<HashMap<Uuid, RuntimeConfigCacheEntry>>>,
}

#[derive(Clone)]
struct RuntimeConfigCacheEntry {
    value: Option<CloakRuntimeConfig>,
    expires_at: Instant,
}

const RUNTIME_CONFIG_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const RUNTIME_CONFIG_CACHE_MAX_ITEMS: usize = 10_000;

impl CloakService {
    pub fn new(pool: DbPool, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            data_dir: Arc::new(data_dir.into()),
            asn_cache: Arc::new(Mutex::new(AsnCache::default())),
            runtime_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn clear_runtime_cache(&self) {
        self.runtime_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    pub async fn list_route_configs(&self) -> anyhow::Result<Vec<CloakRouteConfig>> {
        let rows = sqlx::query_as::<_, CloakRouteConfig>(
            r#"
            SELECT
              r.id AS route_id,
              COALESCE(NULLIF(r.name, ''), r.entry_domain) AS route_name,
              r.entry_domain,
              COALESCE(p.enabled, c.enabled, FALSE) AS enabled,
              COALESCE(p.threshold, c.threshold, 8) AS threshold,
              COALESCE(p.token_hours, c.token_hours, 6) AS token_hours,
              COALESCE(p.decoy_title, c.decoy_title, '下载') AS decoy_title,
              COALESCE(p.decoy_apk_url, c.decoy_apk_url, '') AS decoy_apk_url
            FROM routes r
            LEFT JOIN route_cloak_configs c ON c.route_id = r.id
            LEFT JOIN cloak_policies p ON p.id = c.cloak_policy_id
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
        self.clear_runtime_cache();
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
        let config = self.runtime_config(input.route_id).await?;
        let enabled = config.as_ref().map(|row| row.enabled).unwrap_or(false);
        let threshold = config.as_ref().map(|row| row.threshold).unwrap_or(8);
        let use_ip_blacklist = config
            .as_ref()
            .map(|row| row.use_ip_blacklist)
            .unwrap_or(true);

        if !enabled {
            return Ok(CloakDecision {
                fake: false,
                reason: "分流关闭".to_string(),
            });
        }

        if use_ip_blacklist {
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
        }

        let (score, reasons) = risk_score_request(&input);
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

    pub async fn classify_server(
        &self,
        input: &CloakCheckInput<'_>,
    ) -> anyhow::Result<CloakServerVerdict> {
        let config = self.runtime_config(input.route_id).await?;
        let config = config.unwrap_or_else(|| default_runtime_config(input.route_id));
        let ua = input.user_agent.trim().to_ascii_lowercase();

        if config.use_header_rules {
            if ua.is_empty() {
                return Ok(CloakServerVerdict {
                    bot: true,
                    reason: "空 User-Agent".to_string(),
                    header_score: 0,
                });
            }
            if let Some(hint) = bot_ua_hint(&ua) {
                return Ok(CloakServerVerdict {
                    bot: true,
                    reason: format!("已知爬虫/脚本 UA: {hint}"),
                    header_score: 0,
                });
            }
            if config.require_sec_fetch_mode && input.sec_fetch_mode.trim().is_empty() {
                return Ok(CloakServerVerdict {
                    bot: true,
                    reason: "缺少 sec-fetch-mode(静态抓取/旧浏览器)".to_string(),
                    header_score: 0,
                });
            }
        }

        if config.use_ip_blacklist {
            if let Some(ip) = input.ip.filter(|value| !value.is_empty()) {
                let blacklisted = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM ip_blacklist WHERE $1::inet <<= cidr)",
                )
                .bind(ip)
                .fetch_one(&self.pool)
                .await
                .unwrap_or(false);
                if blacklisted {
                    return Ok(CloakServerVerdict {
                        bot: true,
                        reason: format!("IP 黑名单: {ip}"),
                        header_score: 0,
                    });
                }
            }
        }

        if let Some(ip) = input.ip.filter(|value| !value.is_empty()) {
            if config.use_asn && config.block_datacenter_asn {
                if let Some(org) = self.lookup_asn_org(ip).await? {
                    if has_datacenter_hint(&org) {
                        return Ok(CloakServerVerdict {
                            bot: true,
                            reason: format!("机房 ASN: {org}"),
                            header_score: 0,
                        });
                    }
                }
            }

            if input.include_ptr && config.use_ptr {
                if let Some(ptr) = self.ptr_lookup(ip, &config).await? {
                    if config.block_verified_bot_ptr && ptr.is_verified_bot {
                        return Ok(CloakServerVerdict {
                            bot: true,
                            reason: format!("正规爬虫 PTR: {}", ptr.host),
                            header_score: 0,
                        });
                    }
                    if config.block_datacenter_ptr && ptr.is_datacenter {
                        return Ok(CloakServerVerdict {
                            bot: true,
                            reason: format!("机房 PTR: {}", ptr.host),
                            header_score: 0,
                        });
                    }
                }
            }
        }

        Ok(CloakServerVerdict {
            bot: false,
            reason: if config.use_js_probe {
                "需 JS 探针确认".to_string()
            } else {
                "服务端规则通过".to_string()
            },
            header_score: if config.use_header_rules {
                header_score(input)
            } else {
                0
            },
        })
    }

    pub async fn lookup_asn_org(&self, ip: &str) -> anyhow::Result<Option<String>> {
        let ip = ip.trim();
        let Ok(ip_addr) = ip.parse::<IpAddr>() else {
            return Ok(None);
        };
        if let Some(org) = lookup_ip2asn_file(&self.data_dir, &self.asn_cache, ip_addr) {
            return Ok(Some(org));
        }
        let org = sqlx::query_scalar::<_, String>(
            r#"
            SELECT isp
            FROM ip_geo_ranges
            WHERE $1::inet <<= cidr
              AND isp <> ''
            ORDER BY masklen(cidr) DESC, updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await?;
        Ok(org)
    }

    async fn ptr_lookup(
        &self,
        ip: &str,
        config: &CloakRuntimeConfig,
    ) -> anyhow::Result<Option<PtrLookupResult>> {
        let ip_addr = match ip.trim().parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return Ok(None),
        };
        if let Some(cached) = self.ptr_cache_get(ip).await? {
            return Ok(Some(cached));
        }

        let timeout_ms = u64::try_from(config.ptr_timeout_ms.clamp(100, 5_000)).unwrap_or(800);
        let host = match reverse_dns_ptr(ip_addr, timeout_ms).await {
            Ok(host) => host,
            Err(err) => {
                tracing::debug!(error = %err, ip, "ptr lookup failed");
                self.ptr_cache_put(ip, "", false, false, true, config)
                    .await?;
                return Ok(None);
            }
        };
        let is_datacenter = has_ptr_datacenter_hint(&host);
        let is_verified_bot = has_verified_bot_ptr_hint(&host)
            && verify_ptr_forward(&host, ip_addr, timeout_ms).await;
        self.ptr_cache_put(ip, &host, is_datacenter, is_verified_bot, false, config)
            .await?;
        Ok(Some(PtrLookupResult {
            host,
            is_datacenter,
            is_verified_bot,
        }))
    }

    async fn ptr_cache_get(&self, ip: &str) -> anyhow::Result<Option<PtrLookupResult>> {
        let cached = sqlx::query_as::<_, PtrLookupResult>(
            r#"
            SELECT
              host,
              is_datacenter,
              is_verified_bot
            FROM ptr_cache
            WHERE ip = $1::inet
              AND expires_at > now()
            LIMIT 1
            "#,
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await?;
        Ok(cached)
    }

    async fn ptr_cache_put(
        &self,
        ip: &str,
        host: &str,
        is_datacenter: bool,
        is_verified_bot: bool,
        failed: bool,
        config: &CloakRuntimeConfig,
    ) -> anyhow::Result<()> {
        let cache_hours = config.ptr_cache_hours.clamp(1, 24 * 30);
        sqlx::query(
            r#"
            INSERT INTO ptr_cache (
              ip, host, is_datacenter, is_verified_bot, error_count, checked_at, expires_at
            )
            VALUES ($1::inet, $2, $3, $4, CASE WHEN $5 THEN 1 ELSE 0 END, now(), now() + ($6::TEXT || ' hours')::interval)
            ON CONFLICT (ip) DO UPDATE SET
              host = EXCLUDED.host,
              is_datacenter = EXCLUDED.is_datacenter,
              is_verified_bot = EXCLUDED.is_verified_bot,
              error_count = CASE WHEN $5 THEN ptr_cache.error_count + 1 ELSE 0 END,
              checked_at = now(),
              expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(ip)
        .bind(host.trim())
        .bind(is_datacenter)
        .bind(is_verified_bot)
        .bind(failed)
        .bind(cache_hours)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn runtime_config(
        &self,
        route_id: Uuid,
    ) -> anyhow::Result<Option<CloakRuntimeConfig>> {
        if let Some(config) = self.runtime_config_cache_get(route_id) {
            return Ok(config);
        }

        let row = sqlx::query_as::<_, CloakRuntimeConfig>(
            r#"
            SELECT
              c.route_id,
              COALESCE(p.enabled, c.enabled, FALSE) AS enabled,
              COALESCE(p.threshold, c.threshold, 8) AS threshold,
              COALESCE(p.token_hours, c.token_hours, 6) AS token_hours,
              COALESCE(p.decoy_title, c.decoy_title, '下载') AS decoy_title,
              COALESCE(p.decoy_image_asset_id, c.decoy_image_asset_id) AS decoy_image_asset_id,
              COALESCE(p.decoy_apk_url, c.decoy_apk_url, '') AS decoy_apk_url,
              COALESCE(p.use_ip_blacklist, c.use_ip_blacklist, TRUE) AS use_ip_blacklist,
              COALESCE(p.use_header_rules, c.use_header_rules, TRUE) AS use_header_rules,
              COALESCE(p.require_sec_fetch_mode, c.require_sec_fetch_mode, TRUE) AS require_sec_fetch_mode,
              COALESCE(p.use_js_probe, c.use_js_probe, TRUE) AS use_js_probe,
              COALESCE(p.use_asn, c.use_asn, TRUE) AS use_asn,
              COALESCE(p.use_ptr, c.use_ptr, FALSE) AS use_ptr,
              COALESCE(p.block_datacenter_asn, c.block_datacenter_asn, TRUE) AS block_datacenter_asn,
              COALESCE(p.block_datacenter_ptr, c.block_datacenter_ptr, TRUE) AS block_datacenter_ptr,
              COALESCE(p.block_verified_bot_ptr, c.block_verified_bot_ptr, TRUE) AS block_verified_bot_ptr,
              COALESCE(p.ptr_timeout_ms, c.ptr_timeout_ms, 800) AS ptr_timeout_ms,
              COALESCE(p.ptr_cache_hours, c.ptr_cache_hours, 6) AS ptr_cache_hours
            FROM route_cloak_configs c
            LEFT JOIN cloak_policies p ON p.id = c.cloak_policy_id
            WHERE c.route_id = $1
            "#,
        )
        .bind(route_id)
        .fetch_optional(&self.pool)
        .await?;
        self.runtime_config_cache_put(route_id, row.clone());
        Ok(row)
    }

    fn runtime_config_cache_get(&self, route_id: Uuid) -> Option<Option<CloakRuntimeConfig>> {
        let now = Instant::now();
        let mut cache = self
            .runtime_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match cache.get(&route_id) {
            Some(entry) if entry.expires_at > now => Some(entry.value.clone()),
            Some(_) => {
                cache.remove(&route_id);
                None
            }
            None => None,
        }
    }

    fn runtime_config_cache_put(&self, route_id: Uuid, value: Option<CloakRuntimeConfig>) {
        let now = Instant::now();
        let mut cache = self
            .runtime_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= RUNTIME_CONFIG_CACHE_MAX_ITEMS {
            cache.clear();
        }
        cache.insert(
            route_id,
            RuntimeConfigCacheEntry {
                value,
                expires_at: now + RUNTIME_CONFIG_CACHE_TTL,
            },
        );
    }

    pub async fn decoy_for_route(
        &self,
        route_id: Uuid,
    ) -> anyhow::Result<(String, Option<Uuid>, String)> {
        let row = self.runtime_config(route_id).await?;
        Ok(row
            .map(|config| {
                (
                    config.decoy_title,
                    config.decoy_image_asset_id,
                    config.decoy_apk_url,
                )
            })
            .unwrap_or_else(|| ("下载".to_string(), None, String::new())))
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct PtrLookupResult {
    host: String,
    is_datacenter: bool,
    is_verified_bot: bool,
}

#[derive(Debug, Clone)]
struct AsnRange {
    start: u128,
    end: u128,
    org: String,
}

#[derive(Debug, Default)]
struct AsnCache {
    v4_loaded: bool,
    v6_loaded: bool,
    v4: Vec<AsnRange>,
    v6: Vec<AsnRange>,
}

fn default_runtime_config(route_id: Uuid) -> CloakRuntimeConfig {
    CloakRuntimeConfig {
        route_id,
        enabled: false,
        threshold: 8,
        token_hours: 6,
        decoy_title: "下载".to_string(),
        decoy_image_asset_id: None,
        decoy_apk_url: String::new(),
        use_ip_blacklist: true,
        use_header_rules: true,
        require_sec_fetch_mode: true,
        use_js_probe: true,
        use_asn: true,
        use_ptr: false,
        block_datacenter_asn: true,
        block_datacenter_ptr: true,
        block_verified_bot_ptr: true,
        ptr_timeout_ms: 800,
        ptr_cache_hours: 6,
    }
}

pub fn header_score(input: &CloakCheckInput<'_>) -> i32 {
    let mut score = 0;
    if input.sec_fetch_mode.trim() == "navigate" {
        score += 3;
    }
    if input.sec_fetch_dest.trim() == "document" {
        score += 2;
    }
    if !input.sec_fetch_site.trim().is_empty() {
        score += 1;
    }
    if input.sec_fetch_user.trim() == "?1" {
        score += 2;
    }
    if !input.sec_ch_ua.trim().is_empty() {
        score += 2;
    }
    if input.upgrade_insecure_requests.trim() == "1" {
        score += 2;
    }
    if !input.accept_language.trim().is_empty() {
        score += 2;
    }
    if input.accept.contains("text/html") {
        score += 2;
    }
    if input.accept_encoding.contains("gzip") {
        score += 1;
    }
    if input
        .user_agent
        .to_ascii_lowercase()
        .contains("mozilla/5.0")
    {
        score += 1;
    }
    score
}

fn risk_score_request(input: &CloakCheckInput<'_>) -> (i32, Vec<String>) {
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
    bot_ua_hint(user_agent).is_some()
}

fn bot_ua_hint(user_agent: &str) -> Option<&'static str> {
    const HINTS: &[&str] = &[
        "googlebot",
        "bingbot",
        "baiduspider",
        "yandexbot",
        "duckduckbot",
        "gptbot",
        "oai-searchbot",
        "chatgpt-user",
        "claudebot",
        "claude-web",
        "anthropic-ai",
        "ccbot",
        "perplexitybot",
        "google-extended",
        "bytespider",
        "amazonbot",
        "applebot",
        "facebookexternalhit",
        "crawler",
        "spider",
        "bot/",
        "python-requests",
        "curl/",
        "wget/",
        "scrapy",
        "go-http-client",
        "java/",
        "okhttp",
        "node-fetch",
        "axios",
        "libwww",
        "httpclient",
        "headlesschrome",
        "phantomjs",
    ];
    HINTS.iter().copied().find(|hint| user_agent.contains(hint))
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

fn has_datacenter_hint(value: &str) -> bool {
    const HINTS: &[&str] = &[
        "amazon",
        "aws",
        "google",
        "gcp",
        "microsoft",
        "azure",
        "cloudflare",
        "alibaba",
        "aliyun",
        "tencent",
        "huawei",
        "digitalocean",
        "linode",
        "ovh",
        "hetzner",
        "vultr",
        "leaseweb",
        "scaleway",
        "contabo",
        "oracle",
        "ibm cloud",
        "softlayer",
        "choopa",
        "datacamp",
        "kamatera",
        "hosting",
        "host ",
        " server",
        "colo",
        "cloud",
        "vps",
        "data center",
        "datacenter",
        "gigabit",
        "ucloud",
        "kingsoft",
        "baidu",
        "dmit",
    ];
    let value = value.to_ascii_lowercase();
    HINTS.iter().any(|hint| value.contains(hint))
}

fn has_ptr_datacenter_hint(value: &str) -> bool {
    const HINTS: &[&str] = &[
        "amazonaws.com",
        "compute.amazonaws",
        "googleusercontent.com",
        "1e100.net",
        "azure",
        "cloudapp.net",
        "aliyun",
        "alibaba",
        "myqcloud.com",
        "tencent",
        "digitalocean.com",
        "linode.com",
        "vultr.com",
        "ovh.net",
        "hetzner.de",
        "leaseweb",
        "scaleway",
        "contabo.net",
        "oraclecloud.com",
        "hosting",
        "server",
        "static",
        "colo",
        "datacenter",
        "dmit",
    ];
    let value = value.to_ascii_lowercase();
    HINTS.iter().any(|hint| value.contains(hint))
}

fn has_verified_bot_ptr_hint(value: &str) -> bool {
    const HINTS: &[&str] = &[
        "googlebot.com",
        "google.com",
        "search.msn.com",
        "crawl.baidu.com",
        "applebot.apple.com",
        "duckduckgo.com",
    ];
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    HINTS
        .iter()
        .any(|hint| value == *hint || value.ends_with(&format!(".{hint}")))
}

async fn reverse_dns_ptr(ip: IpAddr, timeout_ms: u64) -> anyhow::Result<String> {
    let query_name = ptr_query_name(ip);
    let query = build_ptr_query(&query_name)?;
    let resolvers = ptr_resolvers();
    let mut last_error = None;
    for resolver in resolvers {
        let response = timeout(
            std::time::Duration::from_millis(timeout_ms),
            send_dns_query(query.clone(), &resolver),
        )
        .await;
        match response {
            Ok(Ok(response)) => return parse_ptr_response(&response),
            Ok(Err(err)) => last_error = Some(err),
            Err(err) => last_error = Some(anyhow::Error::new(err)),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("ptr resolver unavailable")))
}

async fn send_dns_query(query: Vec<u8>, resolver: &str) -> anyhow::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let target = if resolver.contains(':') {
        resolver.to_string()
    } else {
        format!("{resolver}:53")
    };
    socket.send_to(&query, &target).await?;
    let mut buf = vec![0_u8; 512];
    let (len, _) = socket.recv_from(&mut buf).await?;
    buf.truncate(len);
    Ok(buf)
}

async fn verify_ptr_forward(host: &str, ip: IpAddr, timeout_ms: u64) -> bool {
    let host = host.trim_end_matches('.').trim();
    if host.is_empty() {
        return false;
    }
    let lookup = timeout(
        std::time::Duration::from_millis(timeout_ms),
        tokio::net::lookup_host((host, 0)),
    )
    .await;
    match lookup {
        Ok(Ok(addrs)) => addrs.map(|addr| addr.ip()).any(|addr| addr == ip),
        Ok(Err(err)) => {
            tracing::debug!(error = %err, host, "ptr forward lookup failed");
            false
        }
        Err(err) => {
            tracing::debug!(error = %err, host, "ptr forward lookup timed out");
            false
        }
    }
}

fn ptr_resolvers() -> Vec<String> {
    std::env::var("PTR_RESOLVERS")
        .unwrap_or_else(|_| "1.1.1.1,8.8.8.8".to_string())
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn lookup_ip2asn_file(
    data_dir: &std::path::Path,
    cache: &Mutex<AsnCache>,
    ip: IpAddr,
) -> Option<String> {
    let version = if ip.is_ipv4() { "v4" } else { "v6" };
    let target = ip_to_u128(ip)?;
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if ip.is_ipv4() && !cache.v4_loaded {
        cache.v4 = load_ip2asn_ranges(data_dir, version);
        cache.v4_loaded = true;
    }
    if ip.is_ipv6() && !cache.v6_loaded {
        cache.v6 = load_ip2asn_ranges(data_dir, version);
        cache.v6_loaded = true;
    }
    let ranges = if ip.is_ipv4() { &cache.v4 } else { &cache.v6 };
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
            return Some(item.org.clone());
        }
    }
    None
}

fn load_ip2asn_ranges(data_dir: &std::path::Path, version: &str) -> Vec<AsnRange> {
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
        let _country = fields.next();
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
        if !org.is_empty() && start <= end {
            ranges.push(AsnRange {
                start,
                end,
                org: org.to_string(),
            });
        }
    }
    ranges.sort_by_key(|range| range.start);
    tracing::info!(path = %file.display(), count = ranges.len(), "loaded ip2asn ranges");
    ranges
}

fn ip_to_u128(ip: IpAddr) -> Option<u128> {
    match ip {
        IpAddr::V4(ip) => Some(u32::from(ip) as u128),
        IpAddr::V6(ip) => Some(u128::from(ip)),
    }
}

fn ptr_query_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(ip) => ipv6_ptr_query_name(ip),
    }
}

fn ipv6_ptr_query_name(ip: Ipv6Addr) -> String {
    let mut nibbles = Vec::with_capacity(32);
    for byte in ip.octets().iter().rev() {
        nibbles.push(format!("{:x}", byte & 0x0f));
        nibbles.push(format!("{:x}", byte >> 4));
    }
    format!("{}.ip6.arpa", nibbles.join("."))
}

fn build_ptr_query(name: &str) -> anyhow::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&0x4242_u16.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_name(name, &mut packet)?;
    packet.extend_from_slice(&12_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> anyhow::Result<()> {
    for part in name.trim_end_matches('.').split('.') {
        if part.is_empty() || part.len() > 63 {
            anyhow::bail!("invalid dns name");
        }
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn parse_ptr_response(packet: &[u8]) -> anyhow::Result<String> {
    if packet.len() < 12 {
        anyhow::bail!("short dns response");
    }
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12;
    skip_dns_name(packet, &mut pos)?;
    if pos + 4 > packet.len() {
        anyhow::bail!("truncated dns question");
    }
    pos += 4;

    for _ in 0..answer_count {
        skip_dns_name(packet, &mut pos)?;
        if pos + 10 > packet.len() {
            anyhow::bail!("truncated dns answer");
        }
        let record_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;
        let class = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;
        pos += 4;
        let data_len = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2;
        if pos + data_len > packet.len() {
            anyhow::bail!("truncated dns record data");
        }
        if record_type == 12 && class == 1 {
            let mut name_pos = pos;
            return read_dns_name(packet, &mut name_pos);
        }
        pos += data_len;
    }
    anyhow::bail!("ptr record not found")
}

fn skip_dns_name(packet: &[u8], pos: &mut usize) -> anyhow::Result<()> {
    let _ = read_dns_name(packet, pos)?;
    Ok(())
}

fn read_dns_name(packet: &[u8], pos: &mut usize) -> anyhow::Result<String> {
    let mut labels = Vec::new();
    let mut cursor = *pos;
    let mut jumped = false;
    let mut jumps = 0;
    loop {
        if cursor >= packet.len() {
            anyhow::bail!("dns name out of bounds");
        }
        let len = packet[cursor];
        if len & 0xc0 == 0xc0 {
            if cursor + 1 >= packet.len() {
                anyhow::bail!("dns pointer out of bounds");
            }
            let offset = (((len & 0x3f) as usize) << 8) | packet[cursor + 1] as usize;
            if !jumped {
                *pos = cursor + 2;
            }
            cursor = offset;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                anyhow::bail!("too many dns name jumps");
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                *pos = cursor + 1;
            }
            break;
        }
        let start = cursor + 1;
        let end = start + len as usize;
        if end > packet.len() {
            anyhow::bail!("dns label out of bounds");
        }
        labels.push(String::from_utf8_lossy(&packet[start..end]).to_string());
        cursor = end;
        if !jumped {
            *pos = cursor;
        }
    }
    Ok(labels.join(".").trim_end_matches('.').to_string())
}
