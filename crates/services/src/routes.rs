use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RouteSummary {
    pub id: Uuid,
    pub name: String,
    pub entry_domain: String,
    pub target_type: String,
    pub target_label: String,
    pub landing_mode: String,
    pub enabled: bool,
    pub visits: i64,
    pub downloads: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RouteEdit {
    pub id: Uuid,
    pub name: String,
    pub entry_domain: String,
    pub target_type: String,
    pub exit_domain: Option<String>,
    pub external_url: String,
    pub landing_mode: String,
    pub template_id: Option<Uuid>,
    pub image_asset_id: Option<Uuid>,
    pub title: String,
    pub apk_url: String,
    pub auto_download: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PublicRoute {
    pub id: Uuid,
    pub match_kind: String,
    pub entry_domain: String,
    pub target_type: String,
    pub exit_domain: Option<String>,
    pub external_url: String,
    pub landing_mode: String,
    pub template_id: Option<Uuid>,
    pub template_entry_file: Option<String>,
    pub image_asset_id: Option<Uuid>,
    pub title: String,
    pub apk_url: String,
    pub auto_download: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveRouteInput {
    pub name: String,
    pub entry_domain: String,
    pub target_type: String,
    pub exit_domain: String,
    pub external_url: String,
    pub landing_mode: String,
    pub template_id: Option<Uuid>,
    pub image_asset_id: Option<Uuid>,
    pub title: String,
    pub apk_url: String,
    pub auto_download: bool,
    pub enabled: bool,
}

#[derive(Clone)]
pub struct RoutesService {
    pool: DbPool,
}

impl RoutesService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_summaries(&self) -> anyhow::Result<Vec<RouteSummary>> {
        let rows = sqlx::query_as::<_, RouteSummary>(
            r#"
            SELECT
              r.id,
              r.name,
              r.entry_domain,
              COALESCE(t.target_type, 'internal') AS target_type,
              CASE
                WHEN t.target_type = 'external' THEN COALESCE(t.external_url, '')
                ELSE COALESCE(t.exit_domain, '')
              END AS target_label,
              COALESCE(l.landing_mode, 'default') AS landing_mode,
              r.enabled,
              COUNT(DISTINCT v.id)::BIGINT AS visits,
              COUNT(DISTINCT d.id)::BIGINT AS downloads,
              r.updated_at
            FROM routes r
            LEFT JOIN route_targets t ON t.route_id = r.id
            LEFT JOIN route_landing_configs l ON l.route_id = r.id
            LEFT JOIN visits v ON v.route_id = r.id
            LEFT JOIN download_events d ON d.route_id = r.id
            GROUP BY r.id, t.target_type, t.external_url, t.exit_domain, l.landing_mode
            ORDER BY r.updated_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_edit(&self, id: Uuid) -> anyhow::Result<Option<RouteEdit>> {
        let row = sqlx::query_as::<_, RouteEdit>(
            r#"
            SELECT
              r.id,
              r.name,
              r.entry_domain,
              COALESCE(t.target_type, 'internal') AS target_type,
              t.exit_domain,
              COALESCE(t.external_url, '') AS external_url,
              COALESCE(l.landing_mode, 'default') AS landing_mode,
              l.template_id,
              l.image_asset_id,
              COALESCE(l.title, '下载') AS title,
              COALESCE(l.apk_url, '') AS apk_url,
              COALESCE(l.auto_download, TRUE) AS auto_download,
              r.enabled
            FROM routes r
            LEFT JOIN route_targets t ON t.route_id = r.id
            LEFT JOIN route_landing_configs l ON l.route_id = r.id
            WHERE r.id = $1
            LIMIT 1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn create(&self, input: SaveRouteInput) -> anyhow::Result<Uuid> {
        let row = normalize_input(input)?;
        let mut tx = self.pool.begin().await?;
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO routes (name, entry_domain, enabled)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(&row.name)
        .bind(&row.entry_domain)
        .bind(row.enabled)
        .fetch_one(&mut *tx)
        .await?;

        upsert_route_children(&mut tx, id, &row).await?;
        sync_domain_allowlist(&mut tx, &row).await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn update(&self, id: Uuid, input: SaveRouteInput) -> anyhow::Result<()> {
        let row = normalize_input(input)?;
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE routes
            SET name = $1,
                entry_domain = $2,
                enabled = $3,
                updated_at = now()
            WHERE id = $4
            "#,
        )
        .bind(&row.name)
        .bind(&row.entry_domain)
        .bind(row.enabled)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if updated.rows_affected() == 0 {
            anyhow::bail!("线路不存在");
        }

        upsert_route_children(&mut tx, id, &row).await?;
        sync_domain_allowlist(&mut tx, &row).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn toggle(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE routes SET enabled = NOT enabled, updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM routes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn find_public_by_host(&self, host: &str) -> anyhow::Result<Option<PublicRoute>> {
        let host = clean_domain(host);
        if host.is_empty() {
            return Ok(None);
        }

        let row = sqlx::query_as::<_, PublicRoute>(
            r#"
            SELECT
              r.id,
              CASE WHEN r.entry_domain = $1 THEN 'entry' ELSE 'exit' END AS match_kind,
              r.entry_domain,
              t.target_type,
              t.exit_domain,
              t.external_url,
              l.landing_mode,
              l.template_id,
              lt.entry_file AS template_entry_file,
              l.image_asset_id,
              l.title,
              l.apk_url,
              l.auto_download
            FROM routes r
            JOIN route_targets t ON t.route_id = r.id
            JOIN route_landing_configs l ON l.route_id = r.id
            LEFT JOIN landing_templates lt ON lt.id = l.template_id
            WHERE r.enabled = TRUE
              AND (r.entry_domain = $1 OR t.exit_domain = $1)
            ORDER BY CASE WHEN r.entry_domain = $1 THEN 0 ELSE 1 END
            LIMIT 1
            "#,
        )
        .bind(host)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn domain_allowed(&self, host: &str) -> anyhow::Result<bool> {
        let host = clean_domain(host);
        if host.is_empty() {
            return Ok(false);
        }
        let allowed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM domain_allowlist WHERE domain = $1 AND enabled = TRUE)",
        )
        .bind(host)
        .fetch_one(&self.pool)
        .await?;
        Ok(allowed)
    }
}

fn normalize_input(input: SaveRouteInput) -> anyhow::Result<SaveRouteInput> {
    let target_type = if input.target_type == "external" {
        "external".to_string()
    } else {
        "internal".to_string()
    };
    let entry_domain = clean_domain(&input.entry_domain);
    let exit_domain = clean_domain(&input.exit_domain);
    let external_url = input.external_url.trim().to_string();
    let landing_mode = if input.landing_mode == "template" {
        "template".to_string()
    } else {
        "default".to_string()
    };
    let title = input.title.trim();

    if entry_domain.is_empty() {
        anyhow::bail!("入口域名不能为空");
    }

    if target_type == "internal" {
        if exit_domain.is_empty() {
            anyhow::bail!("内部目标必须填写出口域名");
        }
        if landing_mode == "template" && input.template_id.is_none() {
            anyhow::bail!("模板模式必须选择模板");
        }
    } else {
        if external_url.is_empty() {
            anyhow::bail!("外部目标必须填写外部 URL");
        }
        let url = url::Url::parse(&external_url)?;
        if url.scheme() != "http" && url.scheme() != "https" {
            anyhow::bail!("外部 URL 必须以 http:// 或 https:// 开头");
        }
    }

    Ok(SaveRouteInput {
        name: input.name.trim().to_string(),
        entry_domain,
        target_type,
        exit_domain,
        external_url,
        landing_mode,
        template_id: input.template_id,
        image_asset_id: input.image_asset_id,
        title: if title.is_empty() {
            "下载".to_string()
        } else {
            title.to_string()
        },
        apk_url: input.apk_url.trim().to_string(),
        auto_download: input.auto_download,
        enabled: input.enabled,
    })
}

fn clean_domain(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

async fn upsert_route_children(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    row: &SaveRouteInput,
) -> anyhow::Result<()> {
    let exit_domain = if row.target_type == "internal" {
        Some(row.exit_domain.as_str())
    } else {
        None
    };
    let external_url = if row.target_type == "external" {
        row.external_url.as_str()
    } else {
        ""
    };

    sqlx::query(
        r#"
        INSERT INTO route_targets (route_id, target_type, exit_domain, external_url)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (route_id) DO UPDATE SET
          target_type = EXCLUDED.target_type,
          exit_domain = EXCLUDED.exit_domain,
          external_url = EXCLUDED.external_url
        "#,
    )
    .bind(id)
    .bind(&row.target_type)
    .bind(exit_domain)
    .bind(external_url)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO route_landing_configs (route_id, landing_mode, template_id, image_asset_id, title, apk_url, auto_download)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (route_id) DO UPDATE SET
          landing_mode = EXCLUDED.landing_mode,
          template_id = EXCLUDED.template_id,
          image_asset_id = EXCLUDED.image_asset_id,
          title = EXCLUDED.title,
          apk_url = EXCLUDED.apk_url,
          auto_download = EXCLUDED.auto_download
        "#,
    )
    .bind(id)
    .bind(&row.landing_mode)
    .bind(row.template_id)
    .bind(row.image_asset_id)
    .bind(&row.title)
    .bind(&row.apk_url)
    .bind(row.auto_download)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO route_cloak_configs (route_id)
        VALUES ($1)
        ON CONFLICT (route_id) DO NOTHING
        "#,
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO route_meta_configs (route_id)
        VALUES ($1)
        ON CONFLICT (route_id) DO NOTHING
        "#,
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn sync_domain_allowlist(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &SaveRouteInput,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO domain_allowlist (domain, source, enabled)
        VALUES ($1, 'route', TRUE)
        ON CONFLICT (domain) DO UPDATE SET enabled = TRUE, source = 'route'
        "#,
    )
    .bind(&row.entry_domain)
    .execute(&mut **tx)
    .await?;

    if row.target_type == "internal" {
        sqlx::query(
            r#"
            INSERT INTO domain_allowlist (domain, source, enabled)
            VALUES ($1, 'route', TRUE)
            ON CONFLICT (domain) DO UPDATE SET enabled = TRUE, source = 'route'
            "#,
        )
        .bind(&row.exit_domain)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}
