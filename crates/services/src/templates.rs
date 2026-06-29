use std::{
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use ab_db::DbPool;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

const MAX_ZIP_BYTES: usize = 20 * 1024 * 1024;
const MAX_TEMPLATE_FILES: i32 = 200;
const MAX_TEMPLATE_FILE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_TEMPLATE_TOTAL_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct LandingTemplate {
    pub id: Uuid,
    pub name: String,
    pub storage_key: String,
    pub entry_file: String,
    pub file_count: i32,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct TemplatesService {
    pool: DbPool,
    data_dir: PathBuf,
}

impl TemplatesService {
    pub fn new(pool: DbPool, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            data_dir: data_dir.into(),
        }
    }

    pub async fn list(&self) -> anyhow::Result<Vec<LandingTemplate>> {
        let rows = sqlx::query_as::<_, LandingTemplate>(
            r#"
            SELECT id, name, storage_key, entry_file, file_count, size_bytes, created_at
            FROM landing_templates
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get(&self, id: Uuid) -> anyhow::Result<Option<LandingTemplate>> {
        let row = sqlx::query_as::<_, LandingTemplate>(
            r#"
            SELECT id, name, storage_key, entry_file, file_count, size_bytes, created_at
            FROM landing_templates
            WHERE id = $1
            LIMIT 1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn upload_zip(
        &self,
        name: String,
        file_name: String,
        bytes: Vec<u8>,
    ) -> anyhow::Result<Uuid> {
        if bytes.len() > MAX_ZIP_BYTES {
            anyhow::bail!("模板 ZIP 不能超过 20MB");
        }
        let id = Uuid::now_v7();
        let storage_key = id.to_string();
        let template_dir = self.template_dir(&storage_key);
        fs::create_dir_all(&template_dir)?;

        let (entry_file, file_count, size_bytes) = unpack_zip(&bytes, &template_dir)?;
        let display_name = if name.trim().is_empty() {
            file_name.trim().trim_end_matches(".zip").to_string()
        } else {
            name.trim().to_string()
        };

        sqlx::query(
            r#"
            INSERT INTO landing_templates (id, name, storage_key, entry_file, file_count, size_bytes)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(id)
        .bind(display_name)
        .bind(storage_key)
        .bind(entry_file)
        .bind(file_count)
        .bind(size_bytes)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        let template = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("模板不存在"))?;
        let refs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::BIGINT FROM route_landing_configs WHERE template_id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if refs > 0 {
            anyhow::bail!("模板正在被线路引用，先在线路里切换模板后再删除");
        }

        let dir = self.template_dir(&template.storage_key);
        let dir = safe_existing_child_dir(&self.data_dir.join("templates"), &dir).ok();
        sqlx::query("DELETE FROM landing_templates WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if let Some(dir) = dir {
            if let Err(err) = fs::remove_dir_all(&dir) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(error = %err, path = %dir.display(), "failed to remove template directory");
                }
            }
        }
        Ok(())
    }

    pub async fn cleanup_orphan_dirs(&self) -> anyhow::Result<usize> {
        let root = self.data_dir.join("templates");
        fs::create_dir_all(&root)?;
        let rows = sqlx::query_scalar::<_, String>("SELECT storage_key FROM landing_templates")
            .fetch_all(&self.pool)
            .await?;
        let known: std::collections::HashSet<String> = rows.into_iter().collect();
        let mut removed = 0_usize;

        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if known.contains(name) {
                continue;
            }
            let target = safe_existing_child_dir(&root, &path)?;
            fs::remove_dir_all(target)?;
            removed += 1;
        }

        Ok(removed)
    }

    pub fn template_file_path(
        &self,
        template: &LandingTemplate,
        file: &str,
    ) -> anyhow::Result<PathBuf> {
        let relative = sanitize_zip_path(file)?;
        let root = self.template_dir(&template.storage_key);
        let target = root.join(relative);
        let root_abs = root.canonicalize()?;
        let target_abs = target.canonicalize()?;
        if !target_abs.starts_with(&root_abs) {
            anyhow::bail!("模板文件路径越界");
        }
        Ok(target_abs)
    }

    fn template_dir(&self, storage_key: &str) -> PathBuf {
        self.data_dir.join("templates").join(storage_key)
    }
}

fn unpack_zip(bytes: &[u8], dest: &Path) -> anyhow::Result<(String, i32, i64)> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut file_count = 0_i32;
    let mut size_bytes = 0_u64;
    let mut entry_file = String::new();

    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if file.is_dir() {
            continue;
        }
        if file_count >= MAX_TEMPLATE_FILES {
            anyhow::bail!("模板包文件数量不能超过 {MAX_TEMPLATE_FILES} 个");
        }
        if file.size() > MAX_TEMPLATE_FILE_BYTES {
            anyhow::bail!("模板包内单个文件不能超过 5MB");
        }
        if size_bytes.saturating_add(file.size()) > MAX_TEMPLATE_TOTAL_BYTES {
            anyhow::bail!("模板包解压后总大小不能超过 50MB");
        }

        let safe_path = sanitize_zip_path(file.name())?;
        let output = dest.join(&safe_path);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut buf = Vec::new();
        (&mut file)
            .take(MAX_TEMPLATE_FILE_BYTES + 1)
            .read_to_end(&mut buf)?;
        if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_TEMPLATE_FILE_BYTES {
            anyhow::bail!("模板包内单个文件不能超过 5MB");
        }
        size_bytes = size_bytes.saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        if size_bytes > MAX_TEMPLATE_TOTAL_BYTES {
            anyhow::bail!("模板包解压后总大小不能超过 50MB");
        }
        fs::write(&output, buf)?;
        file_count += 1;

        let normalized = safe_path.to_string_lossy().replace('\\', "/");
        if entry_file.is_empty() && normalized.ends_with("index.html") {
            entry_file = normalized;
        }
    }

    if file_count == 0 {
        anyhow::bail!("模板包里没有文件");
    }
    if entry_file.is_empty() {
        anyhow::bail!("模板包必须包含 index.html");
    }

    Ok((
        entry_file,
        file_count,
        i64::try_from(size_bytes).unwrap_or(i64::MAX),
    ))
}

fn sanitize_zip_path(path: &str) -> anyhow::Result<PathBuf> {
    let raw = Path::new(path);
    if raw.is_absolute() {
        anyhow::bail!("模板文件路径不能是绝对路径");
    }

    let mut clean = PathBuf::new();
    for component in raw.components() {
        match component {
            std::path::Component::Normal(part) => clean.push(part),
            std::path::Component::CurDir => {}
            _ => anyhow::bail!("模板文件路径不能包含上级目录"),
        }
    }

    if clean.as_os_str().is_empty() {
        anyhow::bail!("模板文件路径为空");
    }
    Ok(clean)
}

fn safe_existing_child_dir(root: &Path, target: &Path) -> anyhow::Result<PathBuf> {
    let root_abs = root.canonicalize()?;
    let target_abs = target.canonicalize()?;
    if !target_abs.starts_with(&root_abs) || target_abs == root_abs {
        anyhow::bail!("目录路径越界");
    }
    Ok(target_abs)
}
