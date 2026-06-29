use ab_db::DbPool;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone)]
pub struct AuthService {
    pool: DbPool,
}

impl AuthService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn ensure_admin_user(&self, username: &str, password: &str) -> anyhow::Result<()> {
        let username = username.trim();
        if username.is_empty() {
            anyhow::bail!("ADMIN_USER 不能为空");
        }

        let existing = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        match (existing, password.trim().is_empty()) {
            (None, true) => anyhow::bail!("首次初始化管理员需要设置 ADMIN_PASSWORD"),
            (Some(_), _) => Ok(()),
            (None, false) => {
                let password_hash = hash_password(password)?;
                sqlx::query(
                    r#"
                    INSERT INTO users (username, password_hash, enabled)
                    VALUES ($1, $2, TRUE)
                    "#,
                )
                .bind(username)
                .bind(password_hash)
                .execute(&self.pool)
                .await?;
                Ok(())
            }
        }
    }

    pub async fn login(
        &self,
        username: &str,
        password: &str,
        user_agent: &str,
        ip: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        let row = sqlx::query_as::<_, AuthUser>(
            r#"
            SELECT id, password_hash, enabled
            FROM users
            WHERE username = $1
            LIMIT 1
            "#,
        )
        .bind(username.trim())
        .fetch_optional(&self.pool)
        .await?;

        let Some(user) = row else {
            return Ok(None);
        };
        if !user.enabled || !verify_password(password, &user.password_hash) {
            self.audit(
                None,
                "login_failed",
                "user",
                None,
                json!({ "username": username.trim() }),
                ip,
            )
            .await?;
            return Ok(None);
        }

        let token = random_token();
        let token_hash = session_hash(&token);
        let expires_at = Utc::now() + Duration::days(7);
        sqlx::query(
            r#"
            INSERT INTO sessions (user_id, token_hash, user_agent, ip, expires_at)
            VALUES ($1, $2, $3, $4::inet, $5)
            "#,
        )
        .bind(user.id)
        .bind(token_hash)
        .bind(user_agent.trim())
        .bind(clean_ip(ip))
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        self.audit(
            Some(user.id),
            "login",
            "session",
            None,
            json!({ "username": username.trim() }),
            ip,
        )
        .await?;

        Ok(Some(token))
    }

    pub async fn current_session(&self, token: &str) -> anyhow::Result<Option<CurrentSession>> {
        if token.trim().is_empty() {
            return Ok(None);
        }
        let row = sqlx::query_as::<_, CurrentSession>(
            r#"
            SELECT s.id AS session_id, u.id AS user_id, u.username
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = $1
              AND s.expires_at > now()
              AND u.enabled = TRUE
            LIMIT 1
            "#,
        )
        .bind(session_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn session_valid(&self, token: &str) -> anyhow::Result<bool> {
        Ok(self.current_session(token).await?.is_some())
    }

    pub async fn change_password(
        &self,
        token: &str,
        old_password: &str,
        new_password: &str,
    ) -> anyhow::Result<()> {
        let current = self
            .current_session(token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("登录已失效"))?;
        if new_password.len() < 8 {
            anyhow::bail!("新密码至少 8 位");
        }

        let user = sqlx::query_as::<_, AuthUser>(
            r#"
            SELECT id, password_hash, enabled
            FROM users
            WHERE id = $1
            LIMIT 1
            "#,
        )
        .bind(current.user_id)
        .fetch_one(&self.pool)
        .await?;

        if !user.enabled || !verify_password(old_password, &user.password_hash) {
            anyhow::bail!("旧密码不正确");
        }

        let password_hash = hash_password(new_password)?;
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2")
            .bind(password_hash)
            .bind(current.user_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
            .bind(current.user_id)
            .bind(session_hash(token))
            .execute(&self.pool)
            .await?;
        self.audit(
            Some(current.user_id),
            "password_changed",
            "user",
            Some(current.user_id),
            json!({}),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn list_sessions(&self, token: &str) -> anyhow::Result<Vec<SessionRow>> {
        let current = self
            .current_session(token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("登录已失效"))?;
        let rows = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT
              s.id,
              u.username,
              s.user_agent,
              s.ip::TEXT AS ip,
              s.expires_at,
              s.created_at,
              s.id = $2 AS current
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.user_id = $1 AND s.expires_at > now()
            ORDER BY s.created_at DESC
            "#,
        )
        .bind(current.user_id)
        .bind(current.session_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn revoke_session(&self, token: &str, session_id: Uuid) -> anyhow::Result<()> {
        let current = self
            .current_session(token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("登录已失效"))?;
        if session_id == current.session_id {
            anyhow::bail!("不能在这里撤销当前会话，请使用退出登录");
        }
        sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(current.user_id)
            .execute(&self.pool)
            .await?;
        self.audit(
            Some(current.user_id),
            "session_revoked",
            "session",
            Some(session_id),
            json!({}),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn recent_audits(&self, token: &str) -> anyhow::Result<Vec<AuditRow>> {
        let current = self
            .current_session(token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("登录已失效"))?;
        let rows = sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT id, action, entity_type, entity_id, detail::TEXT AS detail, ip::TEXT AS ip, created_at
            FROM audit_logs
            WHERE actor_user_id = $1 OR actor_user_id IS NULL
            ORDER BY created_at DESC
            LIMIT 80
            "#,
        )
        .bind(current.user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn cleanup_audits(&self, token: &str, keep_days: i64) -> anyhow::Result<u64> {
        let current = self
            .current_session(token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("登录已失效"))?;
        let keep_days = keep_days.clamp(7, 3650);
        let cutoff = Utc::now() - Duration::days(keep_days);
        let result = sqlx::query("DELETE FROM audit_logs WHERE created_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        self.audit(
            Some(current.user_id),
            "audit_cleanup",
            "audit_logs",
            None,
            json!({ "keep_days": keep_days, "deleted": result.rows_affected() }),
            None,
        )
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn logout(&self, token: &str) -> anyhow::Result<()> {
        if token.trim().is_empty() {
            return Ok(());
        }
        let current = self.current_session(token).await?;
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(session_hash(token))
            .execute(&self.pool)
            .await?;
        if let Some(current) = current {
            self.audit(
                Some(current.user_id),
                "logout",
                "session",
                Some(current.session_id),
                json!({}),
                None,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn cleanup_expired(&self) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn audit(
        &self,
        actor_user_id: Option<Uuid>,
        action: &str,
        entity_type: &str,
        entity_id: Option<Uuid>,
        detail: serde_json::Value,
        ip: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (actor_user_id, action, entity_type, entity_id, detail, ip)
            VALUES ($1, $2, $3, $4, $5, $6::inet)
            "#,
        )
        .bind(actor_user_id)
        .bind(action)
        .bind(entity_type)
        .bind(entity_id)
        .bind(detail)
        .bind(clean_ip(ip))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CurrentSession {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub username: String,
    pub user_agent: String,
    pub ip: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditRow {
    pub id: Uuid,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    pub detail: String,
    pub ip: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct AuthUser {
    id: Uuid,
    password_hash: String,
    enabled: bool,
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!("密码哈希失败: {err}"))?
        .to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn session_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn clean_ip(ip: Option<&str>) -> Option<String> {
    let ip = ip?.trim();
    if ip.parse::<std::net::IpAddr>().is_ok() {
        Some(ip.to_string())
    } else {
        None
    }
}
