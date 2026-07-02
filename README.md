# APK 分发后台 Rust 版

这是 `C:\Users\1\Desktop\ab` 临时系统的 Rust 重构版。当前仓库先落地长期架构骨架，后续逐步补齐线路、推广、模板、访问采集、分流和 Meta 事件能力。

## 技术栈

- Rust + axum + tokio
- PostgreSQL + SQLx migrations
- Askama 服务端模板
- HTMX 预留后台局部刷新能力
- Docker Compose + Caddy on-demand TLS
- GitHub Actions 自动构建 Docker 镜像到 GHCR

## 本地开发

1. 复制环境变量：

```powershell
Copy-Item .env.example .env
```

本地开发可以保留 `APP_ENV=development`。生产环境必须改为 `APP_ENV=production`，并设置真实的 `APP_BASE_DOMAIN`、至少 12 位的 `ADMIN_PASSWORD`、非默认的 `POSTGRES_PASSWORD`、匹配的 `DATABASE_URL`，以及至少 32 字节的 `META_TOKEN_KEY`。

2. 启动 PostgreSQL，或使用自己的数据库并修改 `.env` 的 `DATABASE_URL`。

3. 启动应用：

```powershell
cargo run -p ab-app
```

默认后台入口：

```text
http://127.0.0.1:3000/admin
```

## 部署与旧数据导入

### Linux 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/longxingze0925/AB-Rust/main/ops/install.sh)
```

安装脚本会检查 Docker/Compose、下载部署文件、生成 `.env`、拉取 `ghcr.io/longxingze0925/ab-rust:latest` 镜像、启动 PostgreSQL + Rust app + Caddy，并注册 `ab-rust` 管理命令。

安装和更新时会自动准备 `geodata/`：

| 文件 | 用途 |
| --- | --- |
| `ip2asn-v4.tsv` | IPv4 ASN / 运营商 / 机房识别 |
| `ip2asn-v6.tsv` | IPv6 ASN / 运营商 / 机房识别 |
| `dbip-city-lite-*.mmdb` | 国家、省、市识别数据 |

`ip2asn` 文件从 `iptoasn.com` 下载，城市库从 `db-ip.com` 免费库下载。服务器无外网时，可以提前把解压后的文件放到安装目录的 `geodata/`，脚本检测到文件存在会跳过下载。PTR 反查 DNS 可通过 `.env` 的 `PTR_RESOLVERS=1.1.1.1,8.8.8.8` 调整。

### 手动/Windows 部署

部署、备份、旧 Next.js SQLite 数据导入脚本放在 `ops/`：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/deploy.ps1 -Build
python ops/import_legacy_sqlite.py --sqlite C:\Users\1\Desktop\ab\data\app.db --out imports\legacy.sql
```

本机 Docker 验证需要暴露 `127.0.0.1:3001` 时，加 `-Local`：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ops/deploy.ps1 -Build -Local
```

具体步骤见 `ops/README.md`。

## 当前完成

- Cargo workspace 和四个 crate：`app`、`domain`、`db`、`services`
- 初始 PostgreSQL migration
- 后台登录、session 入库、管理员密码 Argon2 哈希初始化、总览、线路列表
- 线路新增、编辑、启停、删除
- 推广码新增、编辑、启停、删除
- `?c=` 推广码透传和专属 APK 选择
- 入口域 / 出口域 Host 查询
- 入口域访问记录基础写入，支持关联推广码
- 内部出口域默认落地页和下载事件写入，支持关联访问和推广码
- 访问记录列表、推广码筛选和分页
- `/api/collect` 客户端探针回填：屏幕、时区、网络画像、平台、语言、触控、WebDriver、指纹
- 服务端 UA/请求头解析：系统、版本、设备类型、浏览器、Cloudflare 地区和 ASN 组织
- ZIP 静态模板上传、模板列表和模板文件服务
- 线路支持默认下载页 / 自定义模板两种落地页模式
- 基础分流策略：线路开关、假页标题/APK、风险评分、爬虫/命令行 UA 判定、IP/CIDR 黑名单
- 后台总览真实统计：访问、下载、线路、推广码、模板、独立设备、7 日趋势和最近访问
- 图片素材上传、素材文件服务、默认落地页展示图配置
- 素材/模板删除引用保护、磁盘文件清理、孤儿资源清理入口
- 危险删除/清理操作统一确认弹窗、审计日志按保留天数批量清理
- Meta Pixel / CAPI 按线路配置、浏览器事件、fbp/fbc、服务端事件队列、失败重试、回执查看、手动重发、批量归档和统计
- 后台用户改密、登录审计、退出审计和在线 session 管理
- 自建 IP 地区库：CIDR 规则维护、访问记录地区/运营商兜底补全、通用 CSV 导入、MaxMind CSV 转换、ASN/City 区间匹配和自动更新脚本
- Caddy TLS ask 接口读取后台线路域名 allowlist
- `/health` 健康检查接口，仅公开简单 `ok` 状态
- Dockerfile、docker-compose、Caddyfile
- Docker Compose 蓝绿部署脚本、Linux 一键安装菜单、Caddy 动态切流、健康巡检、失败回滚、发布历史记录、后台蓝绿状态页、PostgreSQL 备份脚本、旧 SQLite 数据导入 SQL 生成脚本
- GitHub Actions 自动构建并推送 Docker 镜像到 GHCR
- 后台 CSRF、Cookie 加固、上传大小/类型限制、生产环境变量校验
- 公开采集/下载接口签名 token、防重复下载事件、下载事件数据库级唯一约束
- Meta CAPI Token 应用层加密、Meta 回执脱敏、Meta 脱敏单元测试

## 下一阶段

优先落地：

- 历史明文 Meta CAPI Token 仍兼容读取；配置 `META_TOKEN_KEY` 后，在后台重新保存一次 Meta 配置即可写回密文。数据库备份仍需按敏感数据处理。
- 蓝绿发布脚本已做配置校验、健康检查和回滚。包含新 migration 的版本上线前，建议先在 staging 数据库或目标颜色容器上完成一次迁移/启动演练。
- 访问、下载和客户端指纹表后续需要按运营周期补数据保留/清理策略。
