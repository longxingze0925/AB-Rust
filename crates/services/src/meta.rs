use ab_db::DbPool;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand_core::{OsRng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ENCRYPTED_TOKEN_PREFIX: &str = "enc:v1:";
const META_TOKEN_CONTEXT: &str = "ab-meta-capi-token-v1";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetaRouteConfig {
    pub route_id: Uuid,
    pub route_name: String,
    pub entry_domain: String,
    pub enabled: bool,
    pub pixel_id: String,
    pub capi_token_set: bool,
    pub test_event_code: String,
    pub currency: String,
    pub value: rust_decimal::Decimal,
    pub page_view_enabled: bool,
    pub view_content_enabled: bool,
    pub lead_enabled: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetaEventRow {
    pub id: Uuid,
    pub route_name: String,
    pub event_name: String,
    pub event_id: String,
    pub status: String,
    pub attempts: i32,
    pub last_status: Option<i32>,
    pub last_response: String,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub archived: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetaEventStats {
    pub total_active: i64,
    pub pending: i64,
    pub processing: i64,
    pub sent: i64,
    pub failed: i64,
    pub skipped: i64,
    pub archived: i64,
    pub sent_24h: i64,
    pub failed_24h: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetaEventNameStat {
    pub event_name: String,
    pub total: i64,
    pub sent: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetaConfig {
    pub route_id: Uuid,
    pub enabled: bool,
    pub pixel_id: String,
    pub capi_token: String,
    pub test_event_code: String,
    pub currency: String,
    pub value: rust_decimal::Decimal,
    pub page_view_enabled: bool,
    pub view_content_enabled: bool,
    pub lead_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveMetaInput {
    pub route_id: Uuid,
    pub enabled: bool,
    pub pixel_id: String,
    pub capi_token: String,
    pub test_event_code: String,
    pub currency: String,
    pub value: rust_decimal::Decimal,
    pub page_view_enabled: bool,
    pub view_content_enabled: bool,
    pub lead_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetaBrowserConfig {
    pub pixel_id: String,
    pub page_view_enabled: bool,
    pub view_content_enabled: bool,
    pub lead_enabled: bool,
    pub currency: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct MetaEventInput {
    pub route_id: Uuid,
    pub event_name: String,
    pub event_id: String,
    pub event_source_url: String,
    pub user_agent: String,
    pub ip: Option<String>,
    pub fbp: String,
    pub fbc: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct MetaQueuedEvent {
    id: Uuid,
    route_id: Uuid,
    event_name: String,
    event_id: String,
    event_source_url: String,
    user_agent: String,
    ip: Option<String>,
    fbp: String,
    fbc: String,
    attempts: i32,
}

#[derive(Clone)]
pub struct MetaService {
    pool: DbPool,
    client: reqwest::Client,
    token_crypto: Option<TokenCrypto>,
}

impl MetaService {
    pub fn new(pool: DbPool, token_key: impl Into<String>) -> Self {
        let token_crypto = TokenCrypto::from_secret(&token_key.into());
        Self {
            pool,
            client: reqwest::Client::new(),
            token_crypto,
        }
    }

    pub async fn list_route_configs(&self) -> anyhow::Result<Vec<MetaRouteConfig>> {
        let rows = sqlx::query_as::<_, MetaRouteConfig>(
            r#"
            SELECT
              r.id AS route_id,
              COALESCE(NULLIF(r.name, ''), r.entry_domain) AS route_name,
              r.entry_domain,
              COALESCE(m.enabled, FALSE) AS enabled,
              COALESCE(m.pixel_id, '') AS pixel_id,
              COALESCE(NULLIF(m.capi_token, ''), '') <> '' AS capi_token_set,
              COALESCE(m.test_event_code, '') AS test_event_code,
              COALESCE(m.currency, 'USD') AS currency,
              COALESCE(m.value, 0) AS value,
              COALESCE(m.page_view_enabled, TRUE) AS page_view_enabled,
              COALESCE(m.view_content_enabled, TRUE) AS view_content_enabled,
              COALESCE(m.lead_enabled, TRUE) AS lead_enabled
            FROM routes r
            LEFT JOIN route_meta_configs m ON m.route_id = r.id
            ORDER BY r.updated_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn save_route_config(&self, input: SaveMetaInput) -> anyhow::Result<()> {
        let existing_token = sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(capi_token, '') FROM route_meta_configs WHERE route_id = $1",
        )
        .bind(input.route_id)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or_default();
        let capi_token = if input.capi_token.trim().is_empty() {
            existing_token
        } else {
            self.encrypt_token(input.capi_token.trim())?
        };

        sqlx::query(
            r#"
            INSERT INTO route_meta_configs (
              route_id, enabled, pixel_id, capi_token, test_event_code, currency, value,
              page_view_enabled, view_content_enabled, lead_enabled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (route_id) DO UPDATE SET
              enabled = EXCLUDED.enabled,
              pixel_id = EXCLUDED.pixel_id,
              capi_token = EXCLUDED.capi_token,
              test_event_code = EXCLUDED.test_event_code,
              currency = EXCLUDED.currency,
              value = EXCLUDED.value,
              page_view_enabled = EXCLUDED.page_view_enabled,
              view_content_enabled = EXCLUDED.view_content_enabled,
              lead_enabled = EXCLUDED.lead_enabled
            "#,
        )
        .bind(input.route_id)
        .bind(input.enabled)
        .bind(input.pixel_id.trim())
        .bind(capi_token)
        .bind(input.test_event_code.trim())
        .bind(input.currency.trim().to_uppercase())
        .bind(input.value)
        .bind(input.page_view_enabled)
        .bind(input.view_content_enabled)
        .bind(input.lead_enabled)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_events(&self, include_archived: bool) -> anyhow::Result<Vec<MetaEventRow>> {
        let rows = sqlx::query_as::<_, MetaEventRow>(
            r#"
            SELECT
              q.id,
              COALESCE(NULLIF(r.name, ''), r.entry_domain, '') AS route_name,
              q.event_name,
              q.event_id,
              q.status,
              q.attempts,
              q.last_status,
              q.last_response,
              q.created_at,
              q.updated_at,
              q.archived_at IS NOT NULL AS archived
            FROM meta_event_queue q
            LEFT JOIN routes r ON r.id = q.route_id
            WHERE ($1 OR q.archived_at IS NULL)
            ORDER BY q.created_at DESC
            LIMIT 80
            "#,
        )
        .bind(include_archived)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn event_stats(&self) -> anyhow::Result<MetaEventStats> {
        let stats = sqlx::query_as::<_, MetaEventStats>(
            r#"
            SELECT
              COUNT(*) FILTER (WHERE archived_at IS NULL)::BIGINT AS total_active,
              COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'pending')::BIGINT AS pending,
              COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'processing')::BIGINT AS processing,
              COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'sent')::BIGINT AS sent,
              COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'failed')::BIGINT AS failed,
              COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'skipped')::BIGINT AS skipped,
              COUNT(*) FILTER (WHERE archived_at IS NOT NULL)::BIGINT AS archived,
              COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'sent' AND updated_at >= now() - interval '24 hours')::BIGINT AS sent_24h,
              COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'failed' AND updated_at >= now() - interval '24 hours')::BIGINT AS failed_24h
            FROM meta_event_queue
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(stats)
    }

    pub async fn event_name_stats(&self) -> anyhow::Result<Vec<MetaEventNameStat>> {
        let rows = sqlx::query_as::<_, MetaEventNameStat>(
            r#"
            SELECT
              event_name,
              COUNT(*)::BIGINT AS total,
              COUNT(*) FILTER (WHERE status = 'sent')::BIGINT AS sent,
              COUNT(*) FILTER (WHERE status = 'failed')::BIGINT AS failed
            FROM meta_event_queue
            WHERE archived_at IS NULL
            GROUP BY event_name
            ORDER BY total DESC, event_name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn retry_event(&self, id: Uuid) -> anyhow::Result<()> {
        let result = sqlx::query(
            r#"
            UPDATE meta_event_queue
            SET status = 'pending',
                next_attempt_at = now(),
                archived_at = NULL,
                last_response = '',
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("Meta 事件不存在");
        }
        Ok(())
    }

    pub async fn archive_event(&self, id: Uuid) -> anyhow::Result<()> {
        let result = sqlx::query(
            r#"
            UPDATE meta_event_queue
            SET archived_at = now(),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("Meta 事件不存在");
        }
        Ok(())
    }

    pub async fn archive_finished(&self, older_than_days: i64) -> anyhow::Result<u64> {
        let older_than_days = older_than_days.clamp(1, 3650);
        let cutoff = Utc::now() - Duration::days(older_than_days);
        let result = sqlx::query(
            r#"
            UPDATE meta_event_queue
            SET archived_at = now(),
                updated_at = now()
            WHERE archived_at IS NULL
              AND status IN ('sent', 'skipped')
              AND updated_at < $1
            "#,
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn browser_config(
        &self,
        route_id: Uuid,
    ) -> anyhow::Result<Option<MetaBrowserConfig>> {
        let cfg = self.config(route_id).await?;
        Ok(cfg
            .filter(|cfg| cfg.enabled && !cfg.pixel_id.trim().is_empty())
            .map(|cfg| MetaBrowserConfig {
                pixel_id: cfg.pixel_id,
                page_view_enabled: cfg.page_view_enabled,
                view_content_enabled: cfg.view_content_enabled,
                lead_enabled: cfg.lead_enabled,
                currency: cfg.currency,
                value: cfg.value.to_string(),
            }))
    }

    pub async fn enqueue_event(&self, input: MetaEventInput) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO meta_event_queue (
              route_id, event_name, event_id, event_source_url, user_agent, ip, fbp, fbc
            )
            VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8)
            ON CONFLICT (route_id, event_name, event_id) DO UPDATE SET
              event_source_url = EXCLUDED.event_source_url,
              user_agent = EXCLUDED.user_agent,
              ip = EXCLUDED.ip,
              fbp = COALESCE(NULLIF(EXCLUDED.fbp, ''), meta_event_queue.fbp),
              fbc = COALESCE(NULLIF(EXCLUDED.fbc, ''), meta_event_queue.fbc),
              updated_at = now()
            "#,
        )
        .bind(input.route_id)
        .bind(input.event_name.trim())
        .bind(input.event_id.trim())
        .bind(input.event_source_url.trim())
        .bind(input.user_agent.trim())
        .bind(clean_ip(input.ip.as_deref()))
        .bind(input.fbp.trim())
        .bind(input.fbc.trim())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn process_pending(&self, limit: i64) -> anyhow::Result<usize> {
        let mut tx = self.pool.begin().await?;
        let events = sqlx::query_as::<_, MetaQueuedEvent>(
            r#"
            WITH locked AS (
              SELECT id
              FROM meta_event_queue
              WHERE archived_at IS NULL AND (
                (
                status IN ('pending', 'failed') AND next_attempt_at <= now()
                ) OR (
                status = 'processing' AND updated_at <= now() - interval '10 minutes'
                )
              )
              ORDER BY created_at ASC
              LIMIT $1
              FOR UPDATE SKIP LOCKED
            )
            UPDATE meta_event_queue q
            SET status = 'processing',
                updated_at = now()
            FROM locked
            WHERE q.id = locked.id
            RETURNING q.id, q.route_id, q.event_name, q.event_id, q.event_source_url, q.user_agent,
                      q.ip::TEXT AS ip, q.fbp, q.fbc, q.attempts
            "#,
        )
        .bind(limit.clamp(1, 200))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut processed = 0_usize;
        for event in events {
            self.process_event(event).await?;
            processed += 1;
        }
        Ok(processed)
    }

    async fn process_event(&self, event: MetaQueuedEvent) -> anyhow::Result<()> {
        let Some(cfg) = self.config(event.route_id).await? else {
            self.mark_skipped(event.id, "Meta 配置不存在").await?;
            return Ok(());
        };
        if !cfg.enabled || cfg.pixel_id.is_empty() || cfg.capi_token.is_empty() {
            self.mark_skipped(event.id, "Meta 未启用或缺少 Pixel/CAPI")
                .await?;
            return Ok(());
        }
        if event.event_name == "ViewContent" && !cfg.view_content_enabled {
            self.mark_skipped(event.id, "ViewContent 未启用").await?;
            return Ok(());
        }
        if event.event_name == "Lead" && !cfg.lead_enabled {
            self.mark_skipped(event.id, "Lead 未启用").await?;
            return Ok(());
        }

        let custom_data = if cfg.value.is_zero() {
            json!({})
        } else {
            json!({ "currency": cfg.currency, "value": cfg.value.to_string() })
        };

        let mut payload_event = json!({
            "event_name": event.event_name,
            "event_time": chrono::Utc::now().timestamp(),
            "event_id": event.event_id,
            "action_source": "website",
            "event_source_url": event.event_source_url,
            "user_data": {
                "client_user_agent": event.user_agent,
            },
            "custom_data": custom_data,
        });
        if let Some(ip) = event.ip.as_deref().filter(|value| !value.is_empty()) {
            payload_event["user_data"]["client_ip_address"] = json!(ip);
        }
        if !event.fbp.is_empty() {
            payload_event["user_data"]["fbp"] = json!(event.fbp);
        }
        if !event.fbc.is_empty() {
            payload_event["user_data"]["fbc"] = json!(event.fbc);
        }

        let mut body = json!({
            "data": [payload_event],
            "access_token": cfg.capi_token,
        });
        if !cfg.test_event_code.is_empty() {
            body["test_event_code"] = json!(cfg.test_event_code);
        }

        let url = format!("https://graph.facebook.com/v20.0/{}/events", cfg.pixel_id);
        match self.client.post(url).json(&body).send().await {
            Ok(response) => {
                let status = response.status();
                let status_code = i32::from(status.as_u16());
                let text = response.text().await.unwrap_or_default();
                if status.is_success() {
                    self.mark_sent(event.id, status_code, &text).await?;
                } else {
                    self.mark_failed(event.id, event.attempts, Some(status_code), &text)
                        .await?;
                    tracing::warn!(%status, response = %text, route_id = %event.route_id, "meta capi event failed");
                }
            }
            Err(err) => {
                self.mark_failed(event.id, event.attempts, None, &err.to_string())
                    .await?;
                tracing::warn!(error = %err, route_id = %event.route_id, "meta capi request failed");
            }
        }
        Ok(())
    }

    async fn mark_sent(&self, id: Uuid, status: i32, response: &str) -> anyhow::Result<()> {
        let response = sanitize_meta_response(response);
        sqlx::query(
            r#"
            UPDATE meta_event_queue
            SET status = 'sent',
                attempts = attempts + 1,
                last_status = $2,
                last_response = LEFT($3, 4000),
                sent_at = now(),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(response)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_skipped(&self, id: Uuid, reason: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE meta_event_queue
            SET status = 'skipped',
                last_response = LEFT($2, 4000),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_failed(
        &self,
        id: Uuid,
        attempts: i32,
        status: Option<i32>,
        response: &str,
    ) -> anyhow::Result<()> {
        let next_attempt = Utc::now() + retry_delay(attempts + 1);
        let response = sanitize_meta_response(response);
        sqlx::query(
            r#"
            UPDATE meta_event_queue
            SET status = 'failed',
                attempts = attempts + 1,
                next_attempt_at = $2,
                last_status = $3,
                last_response = LEFT($4, 4000),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(next_attempt)
        .bind(status)
        .bind(response)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn config(&self, route_id: Uuid) -> anyhow::Result<Option<MetaConfig>> {
        let row = sqlx::query_as::<_, MetaConfig>(
            r#"
            SELECT
              route_id, enabled, pixel_id, capi_token, test_event_code, currency, value,
              page_view_enabled, view_content_enabled, lead_enabled
            FROM route_meta_configs
            WHERE route_id = $1
            LIMIT 1
            "#,
        )
        .bind(route_id)
        .fetch_optional(&self.pool)
        .await?;
        let row = match row {
            Some(mut row) => {
                row.capi_token = self.decrypt_token(&row.capi_token)?;
                Some(row)
            }
            None => None,
        };
        Ok(row)
    }

    fn encrypt_token(&self, token: &str) -> anyhow::Result<String> {
        let Some(crypto) = &self.token_crypto else {
            return Ok(token.to_string());
        };
        crypto.encrypt(token)
    }

    fn decrypt_token(&self, token: &str) -> anyhow::Result<String> {
        let Some(crypto) = &self.token_crypto else {
            if token.starts_with(ENCRYPTED_TOKEN_PREFIX) {
                anyhow::bail!("Meta CAPI Token 已加密，但当前未配置 META_TOKEN_KEY");
            }
            return Ok(token.to_string());
        };
        crypto.decrypt(token)
    }
}

#[derive(Clone)]
struct TokenCrypto {
    key_bytes: [u8; KEY_LEN],
}

impl TokenCrypto {
    fn from_secret(secret: &str) -> Option<Self> {
        let secret = secret.trim();
        if secret.is_empty() {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(META_TOKEN_CONTEXT.as_bytes());
        hasher.update(b":");
        hasher.update(secret.as_bytes());
        let digest = hasher.finalize();
        let mut key_bytes = [0_u8; KEY_LEN];
        key_bytes.copy_from_slice(&digest[..KEY_LEN]);
        Some(Self { key_bytes })
    }

    fn encrypt(&self, token: &str) -> anyhow::Result<String> {
        if token.starts_with(ENCRYPTED_TOKEN_PREFIX) {
            return Ok(token.to_string());
        }

        let key = self.key()?;
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = token.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(META_TOKEN_CONTEXT.as_bytes()), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Meta CAPI Token 加密失败"))?;

        let mut payload = Vec::with_capacity(NONCE_LEN + in_out.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&in_out);
        Ok(format!(
            "{ENCRYPTED_TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(payload)
        ))
    }

    fn decrypt(&self, token: &str) -> anyhow::Result<String> {
        let Some(encoded) = token.strip_prefix(ENCRYPTED_TOKEN_PREFIX) else {
            return Ok(token.to_string());
        };

        let payload = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("Meta CAPI Token 密文格式无效"))?;
        if payload.len() <= NONCE_LEN {
            anyhow::bail!("Meta CAPI Token 密文长度无效");
        }

        let (nonce_bytes, ciphertext) = payload.split_at(NONCE_LEN);
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Meta CAPI Token nonce 无效"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let key = self.key()?;
        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(META_TOKEN_CONTEXT.as_bytes()), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Meta CAPI Token 解密失败"))?;
        String::from_utf8(plaintext.to_vec())
            .map_err(|_| anyhow::anyhow!("Meta CAPI Token 明文不是有效 UTF-8"))
    }

    fn key(&self) -> anyhow::Result<LessSafeKey> {
        let unbound = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| anyhow::anyhow!("Meta CAPI Token 密钥初始化失败"))?;
        Ok(LessSafeKey::new(unbound))
    }
}

fn retry_delay(attempts: i32) -> Duration {
    match attempts {
        0 | 1 => Duration::minutes(1),
        2 => Duration::minutes(5),
        3 => Duration::minutes(15),
        4 => Duration::hours(1),
        _ => Duration::hours(6),
    }
}

fn sanitize_meta_response(response: &str) -> String {
    let mut value = response.to_string();
    for key in [
        "access_token",
        "token",
        "authorization",
        "email",
        "phone",
        "client_secret",
    ] {
        value = redact_json_string_field(&value, key);
    }
    redact_long_sensitive_fragments(&value)
}

fn redact_json_string_field(input: &str, key: &str) -> String {
    let pattern = format!("\"{key}\"");
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find(&pattern) {
        output.push_str(&rest[..start + pattern.len()]);
        let after_key = &rest[start + pattern.len()..];
        let Some(colon) = after_key.find(':') else {
            output.push_str(after_key);
            return output;
        };
        output.push_str(&after_key[..=colon]);
        let after_colon = &after_key[colon + 1..];
        let trimmed_len = after_colon.len() - after_colon.trim_start().len();
        output.push_str(&after_colon[..trimmed_len]);
        let value_start = &after_colon[trimmed_len..];
        if !value_start.starts_with('"') {
            rest = value_start;
            continue;
        }
        let Some(end_quote) = find_json_string_end(&value_start[1..]) else {
            output.push_str("\"[redacted]\"");
            return output;
        };
        output.push_str("\"[redacted]\"");
        rest = &value_start[end_quote + 2..];
    }

    output.push_str(rest);
    output
}

fn find_json_string_end(value: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some(index);
        }
    }
    None
}

fn redact_long_sensitive_fragments(input: &str) -> String {
    input
        .split_whitespace()
        .map(|part| {
            if looks_sensitive_fragment(part) {
                "[redacted]"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_sensitive_fragment(value: &str) -> bool {
    let trimmed = value.trim_matches(|ch: char| {
        !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' && ch != '.' && ch != ':' && ch != '|'
    });
    if trimmed.len() < 48 {
        return false;
    }
    trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '|'))
}

fn clean_ip(ip: Option<&str>) -> Option<String> {
    let ip = ip?.trim();
    if ip.parse::<std::net::IpAddr>().is_ok() {
        Some(ip.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_meta_response;

    #[test]
    fn sanitizes_sensitive_json_string_fields() {
        let response = r#"{"error":{"message":"bad token","access_token":"abc123","email":"user@example.com","phone":"+123456789"}}"#;

        let sanitized = sanitize_meta_response(response);

        assert!(sanitized.contains(r#""access_token":"[redacted]""#));
        assert!(sanitized.contains(r#""email":"[redacted]""#));
        assert!(sanitized.contains(r#""phone":"[redacted]""#));
        assert!(!sanitized.contains("abc123"));
        assert!(!sanitized.contains("user@example.com"));
    }

    #[test]
    fn sanitizes_escaped_json_string_field_values() {
        let response = r#"{"token":"abc\"still-secret","message":"kept"}"#;

        let sanitized = sanitize_meta_response(response);

        assert_eq!(sanitized, r#"{"token":"[redacted]","message":"kept"}"#);
    }

    #[test]
    fn keeps_non_sensitive_short_text() {
        let response = r#"{"error":{"message":"Invalid pixel id","code":100}}"#;

        let sanitized = sanitize_meta_response(response);

        assert_eq!(sanitized, response);
    }

    #[test]
    fn redacts_long_token_like_fragments() {
        let response =
            "request failed Bearer EAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB retry";

        let sanitized = sanitize_meta_response(response);

        assert_eq!(sanitized, "request failed Bearer [redacted] retry");
    }
}
