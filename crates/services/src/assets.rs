use std::{fs, path::PathBuf};

use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Asset {
    pub id: Uuid,
    pub original_name: String,
    pub storage_path: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AssetsService {
    pool: DbPool,
    data_dir: PathBuf,
}

impl AssetsService {
    pub fn new(pool: DbPool, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            data_dir: data_dir.into(),
        }
    }

    pub async fn list(&self) -> anyhow::Result<Vec<Asset>> {
        let rows = sqlx::query_as::<_, Asset>(
            r#"
            SELECT id, original_name, storage_path, mime_type, size_bytes, created_at
            FROM assets
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get(&self, id: Uuid) -> anyhow::Result<Option<Asset>> {
        let row = sqlx::query_as::<_, Asset>(
            r#"
            SELECT id, original_name, storage_path, mime_type, size_bytes, created_at
            FROM assets
            WHERE id = $1
            LIMIT 1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn upload(&self, original_name: String, bytes: Vec<u8>) -> anyhow::Result<Uuid> {
        if bytes.is_empty() {
            anyhow::bail!("素材文件为空");
        }
        if bytes.len() > MAX_IMAGE_BYTES {
            anyhow::bail!("图片素材不能超过 5MB");
        }
        let image_type = detect_image_type(&bytes)
            .ok_or_else(|| anyhow::anyhow!("当前只允许上传 JPG、PNG、GIF 或 WebP 图片素材"))?;

        let id = Uuid::now_v7();
        let storage_name = format!("{id}.{}", image_type.ext);
        let upload_dir = self.data_dir.join("uploads");
        fs::create_dir_all(&upload_dir)?;
        fs::write(upload_dir.join(&storage_name), &bytes)?;

        sqlx::query(
            r#"
            INSERT INTO assets (id, original_name, storage_path, mime_type, size_bytes)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(id)
        .bind(original_name)
        .bind(storage_name)
        .bind(image_type.mime)
        .bind(i64::try_from(bytes.len()).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        let asset = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("素材不存在"))?;
        let refs = sqlx::query_as::<_, (i64, i64, i64, i64)>(
            r#"
            SELECT
              (SELECT COUNT(*)::BIGINT FROM route_landing_configs WHERE image_asset_id = $1),
              (SELECT COUNT(*)::BIGINT FROM route_cloak_configs WHERE decoy_image_asset_id = $1),
              (SELECT COUNT(*)::BIGINT FROM landing_profiles WHERE image_asset_id = $1),
              (SELECT COUNT(*)::BIGINT FROM cloak_policies WHERE decoy_image_asset_id = $1)
            "#,
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if refs.0 > 0 || refs.1 > 0 || refs.2 > 0 || refs.3 > 0 {
            anyhow::bail!("素材正在被落地页、分流策略或线路引用，先移除引用后再删除");
        }

        let path = self.file_path(&asset).ok();
        sqlx::query("DELETE FROM assets WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if let Some(path) = path {
            if let Err(err) = fs::remove_file(&path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(error = %err, path = %path.display(), "failed to remove asset file");
                }
            }
        }
        Ok(())
    }

    pub async fn cleanup_orphan_files(&self) -> anyhow::Result<usize> {
        let upload_dir = self.data_dir.join("uploads");
        fs::create_dir_all(&upload_dir)?;
        let rows = sqlx::query_scalar::<_, String>("SELECT storage_path FROM assets")
            .fetch_all(&self.pool)
            .await?;
        let known: std::collections::HashSet<String> = rows.into_iter().collect();
        let mut removed = 0_usize;

        for entry in fs::read_dir(&upload_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name == ".gitkeep" || known.contains(name) {
                continue;
            }
            fs::remove_file(&path)?;
            removed += 1;
        }

        Ok(removed)
    }

    pub fn file_path(&self, asset: &Asset) -> anyhow::Result<PathBuf> {
        let root = self.data_dir.join("uploads");
        let target = root.join(&asset.storage_path);
        let root_abs = root.canonicalize()?;
        let target_abs = target.canonicalize()?;
        if !target_abs.starts_with(&root_abs) {
            anyhow::bail!("素材文件路径越界");
        }
        Ok(target_abs)
    }
}

struct ImageType {
    mime: &'static str,
    ext: &'static str,
}

fn detect_image_type(bytes: &[u8]) -> Option<ImageType> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some(ImageType {
            mime: "image/jpeg",
            ext: "jpg",
        });
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(ImageType {
            mime: "image/png",
            ext: "png",
        });
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some(ImageType {
            mime: "image/gif",
            ext: "gif",
        });
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some(ImageType {
            mime: "image/webp",
            ext: "webp",
        });
    }
    None
}
