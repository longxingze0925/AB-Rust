use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PromoSummary {
    pub id: Uuid,
    pub route_id: Uuid,
    pub route_name: String,
    pub entry_domain: String,
    pub code: String,
    pub name: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PromoHit {
    pub id: Uuid,
    pub route_id: Uuid,
    pub code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SavePromoInput {
    pub route_id: Uuid,
    pub code: String,
    pub name: String,
    pub enabled: bool,
}

#[derive(Clone)]
pub struct PromosService {
    pool: DbPool,
}

impl PromosService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_summaries(&self) -> anyhow::Result<Vec<PromoSummary>> {
        let rows = sqlx::query_as::<_, PromoSummary>(
            r#"
            SELECT
              p.id,
              p.route_id,
              COALESCE(NULLIF(r.name, ''), r.entry_domain) AS route_name,
              r.entry_domain,
              p.code,
              p.name,
              p.enabled,
              p.created_at
            FROM promo_codes p
            JOIN routes r ON r.id = p.route_id
            ORDER BY p.created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn create(&self, input: SavePromoInput) -> anyhow::Result<Uuid> {
        let row = normalize_input(input)?;
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO promo_codes (route_id, code, name, enabled)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(row.route_id)
        .bind(row.code)
        .bind(row.name)
        .bind(row.enabled)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn update(&self, id: Uuid, input: SavePromoInput) -> anyhow::Result<()> {
        let row = normalize_input(input)?;
        let updated = sqlx::query(
            r#"
            UPDATE promo_codes
            SET route_id = $1,
                code = $2,
                name = $3,
                apk_url = NULL,
                enabled = $4
            WHERE id = $5
            "#,
        )
        .bind(row.route_id)
        .bind(row.code)
        .bind(row.name)
        .bind(row.enabled)
        .bind(id)
        .execute(&self.pool)
        .await?;

        if updated.rows_affected() == 0 {
            anyhow::bail!("推广码不存在");
        }
        Ok(())
    }

    pub async fn toggle(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE promo_codes SET enabled = NOT enabled WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM promo_codes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn find_enabled(
        &self,
        route_id: Uuid,
        code: &str,
    ) -> anyhow::Result<Option<PromoHit>> {
        let code = clean_code(code);
        if code.is_empty() {
            return Ok(None);
        }
        let row = sqlx::query_as::<_, PromoHit>(
            r#"
            SELECT id, route_id, code
            FROM promo_codes
            WHERE route_id = $1 AND code = $2 AND enabled = TRUE
            LIMIT 1
            "#,
        )
        .bind(route_id)
        .bind(code)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}

fn normalize_input(input: SavePromoInput) -> anyhow::Result<SavePromoInput> {
    let code = clean_code(&input.code);
    if code.is_empty() {
        anyhow::bail!("推广码不能为空");
    }
    Ok(SavePromoInput {
        route_id: input.route_id,
        code,
        name: input.name.trim().to_string(),
        enabled: input.enabled,
    })
}

fn clean_code(code: &str) -> String {
    code.trim().to_uppercase()
}
