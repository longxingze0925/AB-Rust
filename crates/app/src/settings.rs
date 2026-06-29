use std::env;

#[derive(Debug, Clone)]
pub struct Settings {
    pub app_env: String,
    pub host: String,
    pub port: u16,
    pub base_domain: String,
    pub database_url: String,
    pub admin_user: String,
    pub admin_password: String,
    pub data_dir: String,
    pub active_proxy_file: String,
    pub release_history_file: String,
    pub meta_token_key: String,
}

impl Settings {
    pub fn from_env() -> anyhow::Result<Self> {
        let settings = Self {
            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
            host: env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("APP_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()?,
            base_domain: env::var("APP_BASE_DOMAIN").unwrap_or_default(),
            database_url: env::var("DATABASE_URL")?,
            admin_user: env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
            admin_password: env::var("ADMIN_PASSWORD").unwrap_or_default(),
            data_dir: env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string()),
            active_proxy_file: env::var("ACTIVE_PROXY_FILE")
                .unwrap_or_else(|_| "deploy/active_proxy.conf".to_string()),
            release_history_file: env::var("RELEASE_HISTORY_FILE")
                .unwrap_or_else(|_| "data/release-history.jsonl".to_string()),
            meta_token_key: env::var("META_TOKEN_KEY").unwrap_or_default(),
        };
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if !self.app_env.eq_ignore_ascii_case("production") {
            return Ok(());
        }

        if self.admin_password.trim().is_empty()
            || self.admin_password == "change_me"
            || self.admin_password.len() < 12
        {
            anyhow::bail!(
                "APP_ENV=production 时 ADMIN_PASSWORD 必须设置为至少 12 位，且不能使用默认值"
            );
        }
        if self.database_url.contains("ab_password") {
            anyhow::bail!("APP_ENV=production 时 DATABASE_URL/POSTGRES_PASSWORD 不能使用默认密码");
        }
        if self.base_domain.trim().is_empty() || self.base_domain == "admin.example.com" {
            anyhow::bail!("APP_ENV=production 时 APP_BASE_DOMAIN 必须设置为真实后台域名");
        }
        if self.meta_token_key.as_bytes().len() < 32 {
            anyhow::bail!("APP_ENV=production 时 META_TOKEN_KEY 必须设置为至少 32 字节");
        }

        Ok(())
    }
}
