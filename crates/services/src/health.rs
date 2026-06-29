use ab_db::DbPool;

#[derive(Clone)]
pub struct HealthService {
    pool: DbPool,
}

impl HealthService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn database_ok(&self) -> bool {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}
