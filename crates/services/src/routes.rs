use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RouteSummary {
    pub id: Uuid,
    pub name: String,
    pub entry_domain: String,
    pub target_type: String,
    pub target_label: String,
    pub landing_profile_name: Option<String>,
    pub landing_mode: String,
    pub enabled: bool,
    pub visits: i64,
    pub real_visits: i64,
    pub fake_visits: i64,
    pub downloads: i64,
    pub real_downloads: i64,
    pub fake_downloads: i64,
    pub unique_device_downloads: i64,
    pub unique_ip_downloads: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RouteEdit {
    pub id: Uuid,
    pub name: String,
    pub entry_domain: String,
    pub target_type: String,
    pub exit_domain_id: Option<Uuid>,
    pub exit_domain: Option<String>,
    pub external_url: String,
    pub landing_profile_id: Option<Uuid>,
    pub landing_mode: String,
    pub template_id: Option<Uuid>,
    pub image_asset_id: Option<Uuid>,
    pub title: String,
    pub apk_url: String,
    pub auto_download: bool,
    pub cloak_policy_id: Option<Uuid>,
    pub meta_profile_id: Option<Uuid>,
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
    pub exit_domain_id: Option<Uuid>,
    pub exit_domain: String,
    pub external_url: String,
    pub landing_profile_id: Option<Uuid>,
    pub landing_mode: String,
    pub template_id: Option<Uuid>,
    pub image_asset_id: Option<Uuid>,
    pub title: String,
    pub apk_url: String,
    pub auto_download: bool,
    pub cloak_policy_id: Option<Uuid>,
    pub meta_profile_id: Option<Uuid>,
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
                ELSE COALESCE(t.exit_domain, td.domain, '')
              END AS target_label,
              lp.name AS landing_profile_name,
              COALESCE(lp.landing_mode, l.landing_mode, 'default') AS landing_mode,
              r.enabled,
              COALESCE(vs.visits, 0) AS visits,
              COALESCE(vs.real_visits, 0) AS real_visits,
              COALESCE(vs.fake_visits, 0) AS fake_visits,
              COALESCE(ds.downloads, 0) AS downloads,
              COALESCE(ds.real_downloads, 0) AS real_downloads,
              COALESCE(ds.fake_downloads, 0) AS fake_downloads,
              COALESCE(ds.unique_device_downloads, 0) AS unique_device_downloads,
              COALESCE(ds.unique_ip_downloads, 0) AS unique_ip_downloads,
              r.updated_at
            FROM routes r
            LEFT JOIN route_targets t ON t.route_id = r.id
            LEFT JOIN domains td ON td.id = t.exit_domain_id
            LEFT JOIN route_landing_configs l ON l.route_id = r.id
            LEFT JOIN landing_profiles lp ON lp.id = l.landing_profile_id
            LEFT JOIN (
              SELECT
                route_id,
                COUNT(*)::BIGINT AS visits,
                COUNT(*) FILTER (WHERE page_variant = 'real')::BIGINT AS real_visits,
                COUNT(*) FILTER (WHERE page_variant = 'fake')::BIGINT AS fake_visits
              FROM visits
              GROUP BY route_id
            ) vs ON vs.route_id = r.id
            LEFT JOIN (
              SELECT
                d.route_id,
                COUNT(*)::BIGINT AS downloads,
                COUNT(*) FILTER (WHERE v.page_variant = 'real')::BIGINT AS real_downloads,
                COUNT(*) FILTER (WHERE v.page_variant = 'fake')::BIGINT AS fake_downloads,
                COUNT(DISTINCT COALESCE(NULLIF(c.fingerprint, ''), v.ip::TEXT || '|' || v.user_agent))
                  FILTER (WHERE COALESCE(NULLIF(c.fingerprint, ''), v.ip::TEXT || '|' || v.user_agent) <> '')::BIGINT
                  AS unique_device_downloads,
                COUNT(DISTINCT v.ip) FILTER (WHERE v.ip IS NOT NULL)::BIGINT AS unique_ip_downloads
              FROM download_events d
              LEFT JOIN visits v ON v.id = d.visit_id
              LEFT JOIN visit_client_updates c ON c.visit_id = v.id
              GROUP BY d.route_id
            ) ds ON ds.route_id = r.id
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
              t.exit_domain_id,
              COALESCE(t.exit_domain, td.domain) AS exit_domain,
              COALESCE(t.external_url, '') AS external_url,
              l.landing_profile_id,
              COALESCE(lp.landing_mode, l.landing_mode, 'default') AS landing_mode,
              COALESCE(lp.template_id, l.template_id) AS template_id,
              COALESCE(lp.image_asset_id, l.image_asset_id) AS image_asset_id,
              COALESCE(lp.title, l.title, '下载') AS title,
              COALESCE(lp.apk_url, l.apk_url, '') AS apk_url,
              COALESCE(lp.auto_download, l.auto_download, TRUE) AS auto_download,
              c.cloak_policy_id,
              m.meta_profile_id,
              r.enabled
            FROM routes r
            LEFT JOIN route_targets t ON t.route_id = r.id
            LEFT JOIN domains td ON td.id = t.exit_domain_id
            LEFT JOIN route_landing_configs l ON l.route_id = r.id
            LEFT JOIN landing_profiles lp ON lp.id = l.landing_profile_id
            LEFT JOIN route_cloak_configs c ON c.route_id = r.id
            LEFT JOIN route_meta_configs m ON m.route_id = r.id
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
        let resolved = resolve_route_resources(&mut tx, row).await?;
        validate_route_domain_conflicts(&mut tx, None, &resolved).await?;
        validate_route_domain_catalog(&mut tx, &resolved.entry_domain, "entry", resolved.enabled)
            .await?;
        if resolved.target_type == "internal" {
            validate_route_domain_catalog(&mut tx, &resolved.exit_domain, "exit", resolved.enabled)
                .await?;
        }
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO routes (name, entry_domain, enabled)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(&resolved.name)
        .bind(&resolved.entry_domain)
        .bind(resolved.enabled)
        .fetch_one(&mut *tx)
        .await?;

        upsert_route_children(&mut tx, id, &resolved).await?;
        if resolved.enabled {
            sync_domain_allowlist(&mut tx, &resolved).await?;
        }
        tx.commit().await?;
        Ok(id)
    }

    pub async fn update(&self, id: Uuid, input: SaveRouteInput) -> anyhow::Result<()> {
        let row = normalize_input(input)?;
        let mut tx = self.pool.begin().await?;
        let previous_domains = route_domains(&mut tx, id).await?;
        let resolved = resolve_route_resources(&mut tx, row).await?;
        validate_route_domain_conflicts(&mut tx, Some(id), &resolved).await?;
        validate_route_domain_catalog(&mut tx, &resolved.entry_domain, "entry", resolved.enabled)
            .await?;
        if resolved.target_type == "internal" {
            validate_route_domain_catalog(&mut tx, &resolved.exit_domain, "exit", resolved.enabled)
                .await?;
        }
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
        .bind(&resolved.name)
        .bind(&resolved.entry_domain)
        .bind(resolved.enabled)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if updated.rows_affected() == 0 {
            anyhow::bail!("线路不存在");
        }

        upsert_route_children(&mut tx, id, &resolved).await?;
        if resolved.enabled {
            sync_domain_allowlist(&mut tx, &resolved).await?;
        }
        let mut domains_to_check = previous_domains;
        domains_to_check.extend(route_domains_from_input(&resolved));
        disable_unused_allowlist_domains(&mut tx, domains_to_check).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn toggle(&self, id: Uuid) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let domains = route_domains(&mut tx, id).await?;
        let enabled = sqlx::query_scalar::<_, bool>(
            "UPDATE routes SET enabled = NOT enabled, updated_at = now() WHERE id = $1 RETURNING enabled",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("线路不存在"))?;
        if enabled {
            validate_route_ready_for_enable(&mut tx, id).await?;
            enable_allowlist_domains(&mut tx, &domains).await?;
        } else {
            disable_unused_allowlist_domains(&mut tx, domains).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let domains = route_domains(&mut tx, id).await?;
        let deleted = sqlx::query("DELETE FROM routes WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if deleted.rows_affected() == 0 {
            anyhow::bail!("线路不存在");
        }
        disable_unused_allowlist_domains(&mut tx, domains).await?;
        tx.commit().await?;
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
              COALESCE(t.exit_domain, td.domain) AS exit_domain,
              t.external_url,
              COALESCE(lp.landing_mode, l.landing_mode, 'default') AS landing_mode,
              COALESCE(lp.template_id, l.template_id) AS template_id,
              lt.entry_file AS template_entry_file,
              COALESCE(lp.image_asset_id, l.image_asset_id) AS image_asset_id,
              COALESCE(lp.title, l.title, '下载') AS title,
              COALESCE(lp.apk_url, l.apk_url, '') AS apk_url,
              COALESCE(lp.auto_download, l.auto_download, TRUE) AS auto_download
            FROM routes r
            JOIN route_targets t ON t.route_id = r.id
            JOIN route_landing_configs l ON l.route_id = r.id
            LEFT JOIN domains td ON td.id = t.exit_domain_id
            LEFT JOIN landing_profiles lp ON lp.id = l.landing_profile_id
            LEFT JOIN landing_templates lt ON lt.id = COALESCE(lp.template_id, l.template_id)
            WHERE r.enabled = TRUE
              AND (r.entry_domain = $1 OR COALESCE(t.exit_domain, td.domain) = $1)
              AND (l.landing_profile_id IS NULL OR lp.enabled = TRUE)
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
        if exit_domain.is_empty() && input.exit_domain_id.is_none() {
            anyhow::bail!("内部目标必须填写出口域名");
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
        exit_domain_id: input.exit_domain_id,
        exit_domain,
        external_url,
        landing_profile_id: input.landing_profile_id,
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
        cloak_policy_id: input.cloak_policy_id,
        meta_profile_id: input.meta_profile_id,
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
        INSERT INTO route_targets (route_id, target_type, exit_domain, external_url, exit_domain_id)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (route_id) DO UPDATE SET
          target_type = EXCLUDED.target_type,
          exit_domain = EXCLUDED.exit_domain,
          external_url = EXCLUDED.external_url,
          exit_domain_id = EXCLUDED.exit_domain_id
        "#,
    )
    .bind(id)
    .bind(&row.target_type)
    .bind(exit_domain)
    .bind(external_url)
    .bind(if row.target_type == "internal" {
        row.exit_domain_id
    } else {
        None
    })
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO route_landing_configs (
          route_id, landing_mode, template_id, image_asset_id, title, apk_url, auto_download,
          landing_profile_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (route_id) DO UPDATE SET
          landing_mode = EXCLUDED.landing_mode,
          template_id = EXCLUDED.template_id,
          image_asset_id = EXCLUDED.image_asset_id,
          title = EXCLUDED.title,
          apk_url = EXCLUDED.apk_url,
          auto_download = EXCLUDED.auto_download,
          landing_profile_id = EXCLUDED.landing_profile_id
        "#,
    )
    .bind(id)
    .bind(&row.landing_mode)
    .bind(row.template_id)
    .bind(row.image_asset_id)
    .bind(&row.title)
    .bind(&row.apk_url)
    .bind(row.auto_download)
    .bind(row.landing_profile_id)
    .execute(&mut **tx)
    .await?;

    if let Some(policy_id) = row.cloak_policy_id {
        let result = sqlx::query(
            r#"
            INSERT INTO route_cloak_configs (
              route_id, enabled, threshold, token_hours, decoy_title, decoy_image_asset_id,
              decoy_apk_url, cloak_policy_id, use_ip_blacklist, use_header_rules,
              require_sec_fetch_mode, use_js_probe, use_asn, use_ptr, block_datacenter_asn,
              block_datacenter_ptr, block_verified_bot_ptr, ptr_timeout_ms, ptr_cache_hours
            )
            SELECT $1, enabled, threshold, token_hours, decoy_title, decoy_image_asset_id,
                   decoy_apk_url, id, use_ip_blacklist, use_header_rules,
                   require_sec_fetch_mode, use_js_probe, use_asn, use_ptr,
                   block_datacenter_asn, block_datacenter_ptr, block_verified_bot_ptr,
                   ptr_timeout_ms, ptr_cache_hours
            FROM cloak_policies
            WHERE id = $2
            ON CONFLICT (route_id) DO UPDATE SET
              enabled = EXCLUDED.enabled,
              threshold = EXCLUDED.threshold,
              token_hours = EXCLUDED.token_hours,
              decoy_title = EXCLUDED.decoy_title,
              decoy_image_asset_id = EXCLUDED.decoy_image_asset_id,
              decoy_apk_url = EXCLUDED.decoy_apk_url,
              cloak_policy_id = EXCLUDED.cloak_policy_id,
              use_ip_blacklist = EXCLUDED.use_ip_blacklist,
              use_header_rules = EXCLUDED.use_header_rules,
              require_sec_fetch_mode = EXCLUDED.require_sec_fetch_mode,
              use_js_probe = EXCLUDED.use_js_probe,
              use_asn = EXCLUDED.use_asn,
              use_ptr = EXCLUDED.use_ptr,
              block_datacenter_asn = EXCLUDED.block_datacenter_asn,
              block_datacenter_ptr = EXCLUDED.block_datacenter_ptr,
              block_verified_bot_ptr = EXCLUDED.block_verified_bot_ptr,
              ptr_timeout_ms = EXCLUDED.ptr_timeout_ms,
              ptr_cache_hours = EXCLUDED.ptr_cache_hours
            "#,
        )
        .bind(id)
        .bind(policy_id)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("请选择可用的分流策略");
        }
    } else {
        sqlx::query(
            r#"
            INSERT INTO route_cloak_configs (
              route_id, enabled, threshold, token_hours, decoy_title, decoy_image_asset_id,
              decoy_apk_url, cloak_policy_id, use_ip_blacklist, use_header_rules,
              require_sec_fetch_mode, use_js_probe, use_asn, use_ptr, block_datacenter_asn,
              block_datacenter_ptr, block_verified_bot_ptr, ptr_timeout_ms, ptr_cache_hours
            )
            VALUES ($1, FALSE, 8, 6, '下载', NULL, '', NULL, TRUE, TRUE, TRUE, TRUE, FALSE, FALSE, TRUE, TRUE, TRUE, 800, 6)
            ON CONFLICT (route_id) DO UPDATE SET
              enabled = FALSE,
              threshold = 8,
              token_hours = 6,
              decoy_title = '下载',
              decoy_image_asset_id = NULL,
              decoy_apk_url = '',
              cloak_policy_id = NULL,
              use_ip_blacklist = TRUE,
              use_header_rules = TRUE,
              require_sec_fetch_mode = TRUE,
              use_js_probe = TRUE,
              use_asn = FALSE,
              use_ptr = FALSE,
              block_datacenter_asn = TRUE,
              block_datacenter_ptr = TRUE,
              block_verified_bot_ptr = TRUE,
              ptr_timeout_ms = 800,
              ptr_cache_hours = 6
            "#,
        )
        .bind(id)
        .execute(&mut **tx)
        .await?;
    }

    if let Some(profile_id) = row.meta_profile_id {
        let result = sqlx::query(
            r#"
            INSERT INTO route_meta_configs (
              route_id, enabled, pixel_id, capi_token, test_event_code, currency, value,
              page_view_enabled, view_content_enabled, lead_enabled, meta_profile_id
            )
            SELECT $1, enabled, pixel_id, capi_token, test_event_code, currency, value,
                   page_view_enabled, view_content_enabled, lead_enabled, id
            FROM meta_profiles
            WHERE id = $2
            ON CONFLICT (route_id) DO UPDATE SET
              enabled = EXCLUDED.enabled,
              pixel_id = EXCLUDED.pixel_id,
              capi_token = EXCLUDED.capi_token,
              test_event_code = EXCLUDED.test_event_code,
              currency = EXCLUDED.currency,
              value = EXCLUDED.value,
              page_view_enabled = EXCLUDED.page_view_enabled,
              view_content_enabled = EXCLUDED.view_content_enabled,
              lead_enabled = EXCLUDED.lead_enabled,
              meta_profile_id = EXCLUDED.meta_profile_id
            "#,
        )
        .bind(id)
        .bind(profile_id)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("请选择可用的 Meta 配置");
        }
    } else {
        sqlx::query(
            r#"
            INSERT INTO route_meta_configs (
              route_id, enabled, pixel_id, capi_token, test_event_code, currency, value,
              page_view_enabled, view_content_enabled, lead_enabled, meta_profile_id
            )
            VALUES ($1, FALSE, '', '', '', 'USD', 0, TRUE, TRUE, TRUE, NULL)
            ON CONFLICT (route_id) DO UPDATE SET
              enabled = FALSE,
              pixel_id = '',
              capi_token = '',
              test_event_code = '',
              currency = 'USD',
              value = 0,
              page_view_enabled = TRUE,
              view_content_enabled = TRUE,
              lead_enabled = TRUE,
              meta_profile_id = NULL
            "#,
        )
        .bind(id)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

async fn resolve_route_resources(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mut row: SaveRouteInput,
) -> anyhow::Result<SaveRouteInput> {
    if row.target_type == "internal" {
        if let Some(id) = row.exit_domain_id {
            let domain = sqlx::query_scalar::<_, String>(
                "SELECT domain FROM domains WHERE id = $1 AND role = 'exit' AND enabled = TRUE",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| anyhow::anyhow!("请选择可用的出口域名"))?;
            row.exit_domain = clean_domain(&domain);
        }
    } else {
        row.exit_domain_id = None;
        row.exit_domain.clear();
    }

    if let Some(id) = row.landing_profile_id {
        let profile =
            sqlx::query_as::<_, (String, Option<Uuid>, Option<Uuid>, String, String, bool)>(
                r#"
            SELECT landing_mode, template_id, image_asset_id, title, apk_url, auto_download
            FROM landing_profiles
            WHERE id = $1 AND enabled = TRUE
            "#,
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| anyhow::anyhow!("请选择可用的落地页"))?;
        row.landing_mode = profile.0;
        row.template_id = profile.1;
        row.image_asset_id = profile.2;
        row.title = profile.3;
        row.apk_url = profile.4;
        row.auto_download = profile.5;
    }

    if row.landing_mode == "template" && row.template_id.is_none() {
        anyhow::bail!("模板模式必须选择模板");
    }

    Ok(row)
}

async fn validate_route_domain_conflicts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    current_route_id: Option<Uuid>,
    row: &SaveRouteInput,
) -> anyhow::Result<()> {
    if row.target_type == "internal" && row.entry_domain == row.exit_domain {
        anyhow::bail!("入口域名和出口域名不能相同");
    }

    let entry_used_by_other_route = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM routes
          WHERE entry_domain = $1
            AND ($2::UUID IS NULL OR id <> $2)
        )
        "#,
    )
    .bind(&row.entry_domain)
    .bind(current_route_id)
    .fetch_one(&mut **tx)
    .await?;
    if entry_used_by_other_route {
        anyhow::bail!("入口域名已经被其他线路使用");
    }

    let entry_used_as_exit = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM route_targets
          WHERE target_type = 'internal'
            AND (
              exit_domain = $1
              OR exit_domain_id = (SELECT id FROM domains WHERE domain = $1 LIMIT 1)
            )
            AND ($2::UUID IS NULL OR route_id <> $2)
        )
        "#,
    )
    .bind(&row.entry_domain)
    .bind(current_route_id)
    .fetch_one(&mut **tx)
    .await?;
    if entry_used_as_exit {
        anyhow::bail!("入口域名已经被其他线路作为出口域名使用");
    }

    if row.target_type != "internal" {
        return Ok(());
    }

    let exit_used_as_entry = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM routes
          WHERE entry_domain = $1
            AND ($2::UUID IS NULL OR id <> $2)
        )
        "#,
    )
    .bind(&row.exit_domain)
    .bind(current_route_id)
    .fetch_one(&mut **tx)
    .await?;
    if exit_used_as_entry {
        anyhow::bail!("出口域名已经被其他线路作为入口域名使用");
    }

    let exit_used_by_other_route = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM route_targets
          WHERE target_type = 'internal'
            AND (
              exit_domain = $1
              OR exit_domain_id = (SELECT id FROM domains WHERE domain = $1 LIMIT 1)
            )
            AND ($2::UUID IS NULL OR route_id <> $2)
        )
        "#,
    )
    .bind(&row.exit_domain)
    .bind(current_route_id)
    .fetch_one(&mut **tx)
    .await?;
    if exit_used_by_other_route {
        anyhow::bail!("出口域名已经被其他线路使用");
    }

    Ok(())
}

async fn validate_route_domain_catalog(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    domain: &str,
    expected_role: &str,
    require_enabled: bool,
) -> anyhow::Result<()> {
    let row = sqlx::query_as::<_, (String, bool)>(
        "SELECT role, enabled FROM domains WHERE domain = $1 LIMIT 1",
    )
    .bind(domain)
    .fetch_optional(&mut **tx)
    .await?;

    let Some((role, enabled)) = row else {
        if require_enabled {
            if expected_role == "entry" {
                anyhow::bail!("入口域名必须先添加到域名库并启用");
            }
            anyhow::bail!("出口域名必须先添加到域名库并启用");
        }
        return Ok(());
    };

    if role != expected_role {
        if expected_role == "entry" {
            anyhow::bail!("入口域名已在域名库标为出口域名，不能作为入口使用");
        }
        anyhow::bail!("出口域名已在域名库标为入口域名，不能作为出口使用");
    }

    if require_enabled && !enabled {
        if expected_role == "entry" {
            anyhow::bail!("入口域名在域名库中已停用，不能用于启用线路");
        }
        anyhow::bail!("出口域名在域名库中已停用，不能用于启用线路");
    }

    Ok(())
}

async fn validate_route_ready_for_enable(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> anyhow::Result<()> {
    let row = sqlx::query_as::<_, (String, String, String, Option<Uuid>)>(
        r#"
        SELECT
          r.entry_domain,
          COALESCE(t.target_type, 'internal') AS target_type,
          COALESCE(t.exit_domain, d.domain, '') AS exit_domain,
          l.landing_profile_id
        FROM routes r
        LEFT JOIN route_targets t ON t.route_id = r.id
        LEFT JOIN domains d ON d.id = t.exit_domain_id
        LEFT JOIN route_landing_configs l ON l.route_id = r.id
        WHERE r.id = $1
        LIMIT 1
        "#,
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| anyhow::anyhow!("线路不存在"))?;

    let domain_row = SaveRouteInput {
        name: String::new(),
        entry_domain: row.0.clone(),
        target_type: row.1.clone(),
        exit_domain_id: None,
        exit_domain: row.2.clone(),
        external_url: String::new(),
        landing_profile_id: row.3,
        landing_mode: "default".to_string(),
        template_id: None,
        image_asset_id: None,
        title: "下载".to_string(),
        apk_url: String::new(),
        auto_download: true,
        cloak_policy_id: None,
        meta_profile_id: None,
        enabled: true,
    };
    validate_route_domain_conflicts(tx, Some(id), &domain_row).await?;
    validate_route_domain_catalog(tx, &row.0, "entry", true).await?;
    if row.1 == "internal" {
        if row.2.trim().is_empty() {
            anyhow::bail!("内部目标必须填写出口域名");
        }
        validate_route_domain_catalog(tx, &row.2, "exit", true).await?;
    }

    if let Some(profile_id) = row.3 {
        let landing_enabled = sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM landing_profiles WHERE id = $1 LIMIT 1",
        )
        .bind(profile_id)
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or(false);
        if !landing_enabled {
            anyhow::bail!("落地页已停用，不能启用线路");
        }
    }

    Ok(())
}

async fn sync_domain_allowlist(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &SaveRouteInput,
) -> anyhow::Result<()> {
    let domains = route_domains_from_input(row);
    enable_allowlist_domains(tx, &domains).await
}

async fn enable_allowlist_domains(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    domains: &[String],
) -> anyhow::Result<()> {
    let mut checked = HashSet::new();
    for domain in domains {
        if domain.is_empty() || !checked.insert(domain.as_str()) {
            continue;
        }
        sqlx::query(
            r#"
            INSERT INTO domain_allowlist (domain, source, enabled)
            VALUES ($1, 'route', TRUE)
            ON CONFLICT (domain) DO UPDATE SET enabled = TRUE, source = 'route'
            "#,
        )
        .bind(domain)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

fn route_domains_from_input(row: &SaveRouteInput) -> Vec<String> {
    let mut domains = vec![row.entry_domain.clone()];
    if row.target_type == "internal" {
        domains.push(row.exit_domain.clone());
    }
    domains
        .into_iter()
        .map(|domain| clean_domain(&domain))
        .filter(|domain| !domain.is_empty())
        .collect()
}

async fn route_domains(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query_scalar::<_, String>(
        r#"
        SELECT domain
        FROM (
          SELECT r.entry_domain AS domain
          FROM routes r
          WHERE r.id = $1
          UNION
          SELECT COALESCE(t.exit_domain, d.domain, '') AS domain
          FROM route_targets t
          LEFT JOIN domains d ON d.id = t.exit_domain_id
          WHERE t.route_id = $1
            AND t.target_type = 'internal'
        ) domains
        WHERE domain <> ''
        "#,
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(|domain| clean_domain(&domain))
        .filter(|domain| !domain.is_empty())
        .collect())
}

async fn disable_unused_allowlist_domains(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    domains: Vec<String>,
) -> anyhow::Result<()> {
    let mut checked = HashSet::new();
    for domain in domains {
        if !checked.insert(domain.clone()) {
            continue;
        }
        sqlx::query(
            r#"
            UPDATE domain_allowlist a
            SET enabled = FALSE
            WHERE a.domain = $1
              AND NOT EXISTS (
                SELECT 1
                FROM routes r
                LEFT JOIN route_targets t ON t.route_id = r.id
                WHERE r.enabled = TRUE
                  AND (
                    r.entry_domain = a.domain
                    OR (t.target_type = 'internal' AND t.exit_domain = a.domain)
                    OR (
                      t.target_type = 'internal'
                      AND t.exit_domain_id = (
                        SELECT id FROM domains WHERE domain = a.domain LIMIT 1
                      )
                    )
                  )
              )
              AND NOT EXISTS (
                SELECT 1
                FROM domains d
                WHERE d.domain = a.domain
                  AND d.enabled = TRUE
              )
            "#,
        )
        .bind(&domain)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
