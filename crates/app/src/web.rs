use ab_services::{
    Asset, AuditRow, CloakCheckInput, CloakRouteConfig, DashboardStats, GeoIpRange, IpBlacklistRow,
    LandingTemplate, MetaEventInput, MetaEventNameStat, MetaEventRow, MetaEventStats,
    MetaRouteConfig, PromoEdit, RecordDownloadInput, RecordVisitInput, RouteEdit, RouteSummary,
    SaveCloakInput, SaveGeoIpRangeInput, SaveMetaInput, SavePromoInput, SaveRouteInput, SessionRow,
    UpdateVisitClientInput, VisitListResult,
};
use askama::Template;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use ring::hmac;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_cookies::{
    cookie::{time::Duration as CookieDuration, SameSite},
    Cookie, CookieManagerLayer, Cookies,
};
use uuid::Uuid;

use crate::state::AppState;

const SESSION_COOKIE: &str = "ab_admin_session";
const CSRF_FIELD: &str = "csrf_token";
const SESSION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const CSRF_SALT: &str = "ab-admin-csrf-v1";
const MAX_UPLOAD_BODY_BYTES: usize = 25 * 1024 * 1024;
const PUBLIC_EVENT_SALT: &str = "ab-public-event-v1";
const PUBLIC_EVENT_TOKEN_TTL_SECONDS: i64 = 6 * 60 * 60;
const PUBLIC_EVENT_DEDUP_TTL_SECONDS: u64 = 6 * 60 * 60;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(public_entry))
        .route("/health", get(health))
        .route("/api/tls-check", get(tls_check))
        .route("/api/collect", post(collect))
        .route("/api/downloaded", post(downloaded))
        .route("/admin", get(admin_index))
        .route("/admin/login", get(login_page).post(login_submit))
        .route("/admin/routes", get(admin_routes))
        .route("/admin/routes/new", get(admin_route_new))
        .route("/admin/routes/create", post(admin_route_create))
        .route("/admin/routes/:id/edit", get(admin_route_edit))
        .route("/admin/routes/:id/update", post(admin_route_update))
        .route("/admin/routes/:id/toggle", post(admin_route_toggle))
        .route("/admin/routes/:id/delete", post(admin_route_delete))
        .route("/admin/promos", get(admin_promos))
        .route("/admin/promos/new", get(admin_promo_new))
        .route("/admin/promos/create", post(admin_promo_create))
        .route("/admin/promos/:id/edit", get(admin_promo_edit))
        .route("/admin/promos/:id/update", post(admin_promo_update))
        .route("/admin/promos/:id/toggle", post(admin_promo_toggle))
        .route("/admin/promos/:id/delete", post(admin_promo_delete))
        .route("/admin/visits", get(admin_visits))
        .route("/admin/templates", get(admin_templates))
        .route(
            "/admin/templates/upload",
            post(admin_template_upload).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
        .route("/admin/templates/:id/delete", post(admin_template_delete))
        .route("/admin/assets", get(admin_assets))
        .route(
            "/admin/assets/upload",
            post(admin_asset_upload).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
        .route("/admin/assets/:id/delete", post(admin_asset_delete))
        .route("/admin/cloak", get(admin_cloak))
        .route("/admin/cloak/save", post(admin_cloak_save))
        .route("/admin/cloak/blacklist/add", post(admin_blacklist_add))
        .route(
            "/admin/cloak/blacklist/:id/delete",
            post(admin_blacklist_delete),
        )
        .route("/admin/meta", get(admin_meta))
        .route("/admin/meta/save", post(admin_meta_save))
        .route("/admin/meta/events/:id/retry", post(admin_meta_event_retry))
        .route(
            "/admin/meta/events/:id/archive",
            post(admin_meta_event_archive),
        )
        .route(
            "/admin/meta/events/archive-finished",
            post(admin_meta_archive_finished),
        )
        .route("/admin/settings", get(admin_settings))
        .route(
            "/admin/settings/change-password",
            post(admin_change_password),
        )
        .route(
            "/admin/settings/sessions/:id/revoke",
            post(admin_revoke_session),
        )
        .route("/admin/settings/ip-geo/add", post(admin_geo_ip_add))
        .route(
            "/admin/settings/ip-geo/:id/delete",
            post(admin_geo_ip_delete),
        )
        .route(
            "/admin/settings/cleanup-resources",
            post(admin_cleanup_resources),
        )
        .route("/admin/settings/cleanup-audits", post(admin_cleanup_audits))
        .route("/admin/logout", post(logout))
        .route("/landing-templates/:id/*file", get(template_file))
        .route("/uploads/:id", get(asset_file))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}

#[derive(Template)]
#[template(path = "admin/login.html")]
struct LoginTemplate<'a> {
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
struct DashboardTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    stats: DashboardStats,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/routes.html")]
struct RoutesTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    routes: Vec<ab_services::RouteSummary>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/promos.html")]
struct PromosTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    promos: Vec<ab_services::PromoSummary>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/promo_form.html")]
struct PromoFormTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    mode: &'a str,
    action: String,
    promo: PromoFormView,
    routes: Vec<RouteSummary>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/visits.html")]
struct VisitsTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    result: Option<VisitListResult>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/route_form.html")]
struct RouteFormTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    mode: &'a str,
    action: String,
    route: RouteFormView,
    templates: Vec<LandingTemplate>,
    assets: Vec<Asset>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/assets.html")]
struct AssetsTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    assets: Vec<Asset>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/templates.html")]
struct TemplatesTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    templates: Vec<LandingTemplate>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/cloak.html")]
struct CloakTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    routes: Vec<CloakRouteConfig>,
    blacklist: Vec<IpBlacklistRow>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/meta.html")]
struct MetaTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    routes: Vec<MetaRouteConfig>,
    events: Vec<MetaEventRow>,
    stats: Option<MetaEventStats>,
    event_stats: Vec<MetaEventNameStat>,
    include_archived: bool,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/settings.html")]
struct SettingsTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    message: Option<String>,
    error: Option<String>,
    release: ReleaseStatusView,
    release_history: Vec<ReleaseHistoryRow>,
    sessions: Vec<SessionRow>,
    audits: Vec<AuditRow>,
    geo_ranges: Vec<GeoIpRange>,
}

#[derive(Debug, Clone, Default)]
struct ReleaseStatusView {
    active_color: String,
    active_service: String,
    active_proxy: String,
}

#[derive(Debug, Clone, Default)]
struct ReleaseHistoryRow {
    timestamp: String,
    status: String,
    from_color: String,
    to_color: String,
    image: String,
    message: String,
}

#[derive(Template)]
#[template(path = "landing/not_configured.html")]
struct NotConfiguredTemplate<'a> {
    host: &'a str,
}

#[derive(Template)]
#[template(path = "landing/default.html")]
struct DefaultLandingTemplate<'a> {
    route_id: Uuid,
    promo_id: Option<Uuid>,
    visit_id: Option<Uuid>,
    event_token_json: String,
    title: &'a str,
    image_url: String,
    apk_url_json: String,
    meta_json: String,
    auto_download: bool,
}

#[derive(Template)]
#[template(path = "landing/template_frame.html")]
struct TemplateFrameTemplate {
    route_id: Uuid,
    promo_id: Option<Uuid>,
    visit_id: Option<Uuid>,
    event_token_json: String,
    template_url: String,
    apk_url_json: String,
    meta_json: String,
    auto_download: bool,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordForm {
    csrf_token: String,
    old_password: String,
    new_password: String,
    confirm_password: String,
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf_token: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GeoIpRangeForm {
    csrf_token: String,
    cidr: String,
    country: String,
    province: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    source: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditCleanupForm {
    csrf_token: String,
    keep_days: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct PublicQuery {
    c: Option<String>,
    v: Option<Uuid>,
    fbclid: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TlsCheckQuery {
    domain: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DownloadedPayload {
    route_id: Option<Uuid>,
    visit_id: Option<Uuid>,
    promo_id: Option<Uuid>,
    token: Option<String>,
    event_id: Option<String>,
    apk_url: Option<String>,
    url: Option<String>,
    fbp: Option<String>,
    fbc: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CollectPayload {
    route_id: Option<Uuid>,
    visit_id: Option<Uuid>,
    token: Option<String>,
    screen: Option<String>,
    timezone: Option<String>,
    network: Option<String>,
    fingerprint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminVisitQuery {
    page: Option<i64>,
    size: Option<i64>,
    promo: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CloakForm {
    csrf_token: String,
    route_id: Uuid,
    enabled: Option<String>,
    threshold: i32,
    token_hours: i32,
    decoy_title: String,
    decoy_apk_url: Option<String>,
}

impl From<CloakForm> for SaveCloakInput {
    fn from(form: CloakForm) -> Self {
        let _ = form.csrf_token;
        Self {
            route_id: form.route_id,
            enabled: form.enabled.is_some(),
            threshold: form.threshold,
            token_hours: form.token_hours,
            decoy_title: form.decoy_title,
            decoy_apk_url: form.decoy_apk_url.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct BlacklistForm {
    csrf_token: String,
    cidr: String,
    note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct MetaForm {
    csrf_token: String,
    route_id: Uuid,
    enabled: Option<String>,
    pixel_id: String,
    capi_token: Option<String>,
    test_event_code: Option<String>,
    currency: Option<String>,
    value: Option<String>,
    page_view_enabled: Option<String>,
    view_content_enabled: Option<String>,
    lead_enabled: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct MetaQuery {
    archived: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct MetaArchiveForm {
    csrf_token: String,
    older_than_days: Option<i64>,
}

impl TryFrom<MetaForm> for SaveMetaInput {
    type Error = anyhow::Error;

    fn try_from(form: MetaForm) -> Result<Self, Self::Error> {
        let value_text = form.value.as_deref().unwrap_or("0").trim().to_string();
        let value = if value_text.is_empty() {
            Decimal::ZERO
        } else {
            value_text
                .parse::<Decimal>()
                .map_err(|_| anyhow::anyhow!("事件价值必须是数字"))?
        };
        let currency = form
            .currency
            .as_deref()
            .unwrap_or("USD")
            .trim()
            .to_uppercase();
        let currency = if currency.is_empty() {
            "USD".to_string()
        } else {
            currency
        };

        Ok(Self {
            route_id: form.route_id,
            enabled: form.enabled.is_some(),
            pixel_id: form.pixel_id.trim().to_string(),
            capi_token: form.capi_token.unwrap_or_default(),
            test_event_code: form.test_event_code.unwrap_or_default(),
            currency,
            value,
            page_view_enabled: form.page_view_enabled.is_some(),
            view_content_enabled: form.view_content_enabled.is_some(),
            lead_enabled: form.lead_enabled.is_some(),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RouteForm {
    csrf_token: String,
    name: String,
    entry_domain: String,
    target_type: String,
    exit_domain: Option<String>,
    external_url: Option<String>,
    landing_mode: Option<String>,
    template_id: Option<String>,
    image_asset_id: Option<String>,
    title: String,
    apk_url: Option<String>,
    auto_download: Option<String>,
    enabled: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PromoForm {
    csrf_token: String,
    route_id: Uuid,
    code: String,
    name: String,
    apk_url: Option<String>,
    enabled: Option<String>,
}

#[derive(Debug, Clone)]
struct PromoFormView {
    route_id: Uuid,
    code: String,
    name: String,
    apk_url: String,
    enabled: bool,
}

impl PromoFormView {
    fn blank(routes: &[RouteSummary]) -> Self {
        Self {
            route_id: routes
                .first()
                .map(|route| route.id)
                .unwrap_or_else(Uuid::nil),
            code: String::new(),
            name: String::new(),
            apk_url: String::new(),
            enabled: true,
        }
    }
}

impl From<PromoEdit> for PromoFormView {
    fn from(promo: PromoEdit) -> Self {
        Self {
            route_id: promo.route_id,
            code: promo.code,
            name: promo.name,
            apk_url: promo.apk_url.unwrap_or_default(),
            enabled: promo.enabled,
        }
    }
}

impl From<PromoForm> for PromoFormView {
    fn from(form: PromoForm) -> Self {
        let _ = form.csrf_token;
        Self {
            route_id: form.route_id,
            code: form.code,
            name: form.name,
            apk_url: form.apk_url.unwrap_or_default(),
            enabled: form.enabled.is_some(),
        }
    }
}

impl From<PromoForm> for SavePromoInput {
    fn from(form: PromoForm) -> Self {
        let _ = form.csrf_token;
        Self {
            route_id: form.route_id,
            code: form.code,
            name: form.name,
            apk_url: form.apk_url.unwrap_or_default(),
            enabled: form.enabled.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
struct RouteFormView {
    name: String,
    entry_domain: String,
    target_type: String,
    exit_domain: String,
    external_url: String,
    landing_mode: String,
    template_id_value: String,
    image_asset_id_value: String,
    title: String,
    apk_url: String,
    auto_download: bool,
    enabled: bool,
}

impl Default for RouteFormView {
    fn default() -> Self {
        Self {
            name: String::new(),
            entry_domain: String::new(),
            target_type: "internal".to_string(),
            exit_domain: String::new(),
            external_url: String::new(),
            landing_mode: "default".to_string(),
            template_id_value: String::new(),
            image_asset_id_value: String::new(),
            title: "下载".to_string(),
            apk_url: String::new(),
            auto_download: true,
            enabled: true,
        }
    }
}

impl From<RouteEdit> for RouteFormView {
    fn from(route: RouteEdit) -> Self {
        Self {
            name: route.name,
            entry_domain: route.entry_domain,
            target_type: route.target_type,
            exit_domain: route.exit_domain.unwrap_or_default(),
            external_url: route.external_url,
            landing_mode: route.landing_mode,
            template_id_value: route
                .template_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            image_asset_id_value: route
                .image_asset_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            title: route.title,
            apk_url: route.apk_url,
            auto_download: route.auto_download,
            enabled: route.enabled,
        }
    }
}

impl From<RouteForm> for RouteFormView {
    fn from(form: RouteForm) -> Self {
        let _ = form.csrf_token;
        Self {
            name: form.name,
            entry_domain: form.entry_domain,
            target_type: form.target_type,
            exit_domain: form.exit_domain.unwrap_or_default(),
            external_url: form.external_url.unwrap_or_default(),
            landing_mode: form.landing_mode.unwrap_or_else(|| "default".to_string()),
            template_id_value: form.template_id.unwrap_or_default(),
            image_asset_id_value: form.image_asset_id.unwrap_or_default(),
            title: form.title,
            apk_url: form.apk_url.unwrap_or_default(),
            auto_download: form.auto_download.is_some(),
            enabled: form.enabled.is_some(),
        }
    }
}

impl From<RouteForm> for SaveRouteInput {
    fn from(form: RouteForm) -> Self {
        let _ = form.csrf_token;
        Self {
            name: form.name,
            entry_domain: form.entry_domain,
            target_type: form.target_type,
            exit_domain: form.exit_domain.unwrap_or_default(),
            external_url: form.external_url.unwrap_or_default(),
            landing_mode: form.landing_mode.unwrap_or_else(|| "default".to_string()),
            template_id: parse_optional_uuid(form.template_id.as_deref()),
            image_asset_id: parse_optional_uuid(form.image_asset_id.as_deref()),
            title: form.title,
            apk_url: form.apk_url.unwrap_or_default(),
            auto_download: form.auto_download.is_some(),
            enabled: form.enabled.is_some(),
        }
    }
}

fn parse_optional_uuid(value: Option<&str>) -> Option<Uuid> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| Uuid::parse_str(value).ok())
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let database = state.health.database_ok().await;
    Json(HealthResponse { ok: database })
}

async fn login_page() -> impl IntoResponse {
    render(LoginTemplate { error: None })
}

async fn login_submit(
    State(state): State<AppState>,
    cookies: Cookies,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let (ip, _) = client_ip(&headers);
    let login_key = login_failure_key(ip.as_deref(), &form.username);
    if state.security.login_blocked(&login_key) {
        return render(LoginTemplate {
            error: Some("登录失败次数过多，请稍后再试"),
        });
    }
    match state
        .auth
        .login(
            &form.username,
            &form.password,
            &header_value(&headers, "user-agent"),
            ip.as_deref(),
        )
        .await
    {
        Ok(Some(token)) => {
            state.security.clear_login_failure(&login_key);
            cookies.add(session_cookie(token, request_is_https(&headers)));
            Redirect::to("/admin").into_response()
        }
        Ok(None) => {
            state.security.record_login_failure(&login_key);
            render(LoginTemplate {
                error: Some("账号或密码不正确"),
            })
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to login admin");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        if form.csrf_token == csrf_token_for_session(cookie.value()) {
            if let Err(err) = state.auth.logout(cookie.value()).await {
                tracing::warn!(error = %err, "failed to delete admin session");
            }
        } else {
            tracing::warn!("ignored logout with invalid csrf token");
            return Redirect::to("/admin").into_response();
        }
    }
    cookies.remove(expired_session_cookie());
    Redirect::to("/admin/login").into_response()
}

async fn admin_index(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let (stats, error) = match state.stats.dashboard().await {
        Ok(stats) => (stats, None),
        Err(err) => (empty_dashboard_stats(), Some(err.to_string())),
    };
    render(DashboardTemplate {
        active: "dashboard",
        csrf_token: csrf_token(&cookies),
        stats,
        error,
    })
}

fn empty_dashboard_stats() -> DashboardStats {
    DashboardStats {
        total_visits: 0,
        today_visits: 0,
        total_downloads: 0,
        today_downloads: 0,
        enabled_routes: 0,
        total_routes: 0,
        total_promos: 0,
        enabled_promos: 0,
        total_templates: 0,
        unique_devices: 0,
        fake_visits: 0,
        real_visits: 0,
        daily: Vec::new(),
        variants: Vec::new(),
        recent: Vec::new(),
    }
}

async fn admin_routes(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }

    match state.routes.list_summaries().await {
        Ok(routes) => render(RoutesTemplate {
            active: "routes",
            csrf_token: csrf_token(&cookies),
            routes,
            error: None,
        }),
        Err(err) => render(RoutesTemplate {
            active: "routes",
            csrf_token: csrf_token(&cookies),
            routes: Vec::new(),
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_route_new(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let templates = state.templates.list().await.unwrap_or_default();
    let assets = state.assets.list().await.unwrap_or_default();
    render(RouteFormTemplate {
        active: "routes",
        csrf_token: csrf_token(&cookies),
        mode: "新增线路",
        action: "/admin/routes/create".to_string(),
        route: RouteFormView::default(),
        templates,
        assets,
        error: None,
    })
}

async fn admin_route_create(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<RouteForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }

    let view = RouteFormView::from(form.clone());
    let templates = state.templates.list().await.unwrap_or_default();
    let assets = state.assets.list().await.unwrap_or_default();
    match state.routes.create(form.into()).await {
        Ok(_) => Redirect::to("/admin/routes").into_response(),
        Err(err) => render(RouteFormTemplate {
            active: "routes",
            csrf_token: csrf_token(&cookies),
            mode: "新增线路",
            action: "/admin/routes/create".to_string(),
            route: view,
            templates,
            assets,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_route_edit(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let templates = state.templates.list().await.unwrap_or_default();
    let assets = state.assets.list().await.unwrap_or_default();

    match state.routes.get_edit(id).await {
        Ok(Some(route)) => render(RouteFormTemplate {
            active: "routes",
            csrf_token: csrf_token(&cookies),
            mode: "编辑线路",
            action: format!("/admin/routes/{id}/update"),
            route: route.into(),
            templates,
            assets,
            error: None,
        }),
        Ok(None) => Redirect::to("/admin/routes").into_response(),
        Err(err) => render(RouteFormTemplate {
            active: "routes",
            csrf_token: csrf_token(&cookies),
            mode: "编辑线路",
            action: format!("/admin/routes/{id}/update"),
            route: RouteFormView::default(),
            templates,
            assets,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_route_update(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<RouteForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }

    let view = RouteFormView::from(form.clone());
    let templates = state.templates.list().await.unwrap_or_default();
    let assets = state.assets.list().await.unwrap_or_default();
    match state.routes.update(id, form.into()).await {
        Ok(_) => Redirect::to("/admin/routes").into_response(),
        Err(err) => render(RouteFormTemplate {
            active: "routes",
            csrf_token: csrf_token(&cookies),
            mode: "编辑线路",
            action: format!("/admin/routes/{id}/update"),
            route: view,
            templates,
            assets,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_route_toggle(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = state.routes.toggle(id).await {
        tracing::error!(error = %err, route_id = %id, "failed to toggle route");
    }
    Redirect::to("/admin/routes").into_response()
}

async fn admin_route_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = state.routes.delete(id).await {
        tracing::error!(error = %err, route_id = %id, "failed to delete route");
    }
    Redirect::to("/admin/routes").into_response()
}

async fn admin_promos(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }

    match state.promos.list_summaries().await {
        Ok(promos) => render(PromosTemplate {
            active: "promos",
            csrf_token: csrf_token(&cookies),
            promos,
            error: None,
        }),
        Err(err) => render(PromosTemplate {
            active: "promos",
            csrf_token: csrf_token(&cookies),
            promos: Vec::new(),
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_promo_new(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let routes = state.routes.list_summaries().await.unwrap_or_default();
    render(PromoFormTemplate {
        active: "promos",
        csrf_token: csrf_token(&cookies),
        mode: "新增推广码",
        action: "/admin/promos/create".to_string(),
        promo: PromoFormView::blank(&routes),
        routes,
        error: None,
    })
}

async fn admin_promo_create(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<PromoForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    let routes = state.routes.list_summaries().await.unwrap_or_default();
    let view = PromoFormView::from(form.clone());
    match state.promos.create(form.into()).await {
        Ok(_) => Redirect::to("/admin/promos").into_response(),
        Err(err) => render(PromoFormTemplate {
            active: "promos",
            csrf_token: csrf_token(&cookies),
            mode: "新增推广码",
            action: "/admin/promos/create".to_string(),
            promo: view,
            routes,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_promo_edit(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let routes = state.routes.list_summaries().await.unwrap_or_default();
    match state.promos.get_edit(id).await {
        Ok(Some(promo)) => render(PromoFormTemplate {
            active: "promos",
            csrf_token: csrf_token(&cookies),
            mode: "编辑推广码",
            action: format!("/admin/promos/{id}/update"),
            promo: promo.into(),
            routes,
            error: None,
        }),
        Ok(None) => Redirect::to("/admin/promos").into_response(),
        Err(err) => render(PromoFormTemplate {
            active: "promos",
            csrf_token: csrf_token(&cookies),
            mode: "编辑推广码",
            action: format!("/admin/promos/{id}/update"),
            promo: PromoFormView::blank(&routes),
            routes,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_promo_update(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<PromoForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    let routes = state.routes.list_summaries().await.unwrap_or_default();
    let view = PromoFormView::from(form.clone());
    match state.promos.update(id, form.into()).await {
        Ok(_) => Redirect::to("/admin/promos").into_response(),
        Err(err) => render(PromoFormTemplate {
            active: "promos",
            csrf_token: csrf_token(&cookies),
            mode: "编辑推广码",
            action: format!("/admin/promos/{id}/update"),
            promo: view,
            routes,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_promo_toggle(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = state.promos.toggle(id).await {
        tracing::error!(error = %err, promo_id = %id, "failed to toggle promo");
    }
    Redirect::to("/admin/promos").into_response()
}

async fn admin_promo_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = state.promos.delete(id).await {
        tracing::error!(error = %err, promo_id = %id, "failed to delete promo");
    }
    Redirect::to("/admin/promos").into_response()
}

async fn admin_visits(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(query): Query<AdminVisitQuery>,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }

    match state
        .visits
        .list(ab_services::VisitListQuery {
            page: query.page.unwrap_or(1),
            page_size: query.size.unwrap_or(50),
            promo: query.promo,
        })
        .await
    {
        Ok(result) => render(VisitsTemplate {
            active: "visits",
            csrf_token: csrf_token(&cookies),
            result: Some(result),
            error: None,
        }),
        Err(err) => render(VisitsTemplate {
            active: "visits",
            csrf_token: csrf_token(&cookies),
            result: None,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_templates(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }

    match state.templates.list().await {
        Ok(templates) => render(TemplatesTemplate {
            active: "templates",
            csrf_token: csrf_token(&cookies),
            templates,
            error: None,
        }),
        Err(err) => render(TemplatesTemplate {
            active: "templates",
            csrf_token: csrf_token(&cookies),
            templates: Vec::new(),
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_template_upload(
    State(state): State<AppState>,
    cookies: Cookies,
    mut multipart: Multipart,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }

    let mut name = String::new();
    let mut file_name = String::new();
    let mut file_bytes = Vec::new();
    let mut csrf = String::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == CSRF_FIELD {
            csrf = field.text().await.unwrap_or_default();
        } else if !require_admin_form(&state, &cookies, &csrf).await {
            return Redirect::to("/admin/login").into_response();
        } else if field_name == "name" {
            name = field.text().await.unwrap_or_default();
        } else if field_name == "file" {
            file_name = field.file_name().unwrap_or("template.zip").to_string();
            file_bytes = field
                .bytes()
                .await
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default();
        }
    }

    if !require_admin_form(&state, &cookies, &csrf).await {
        return Redirect::to("/admin/login").into_response();
    }

    if file_bytes.is_empty() {
        return render(TemplatesTemplate {
            active: "templates",
            csrf_token: csrf_token(&cookies),
            templates: state.templates.list().await.unwrap_or_default(),
            error: Some("请选择 ZIP 模板包".to_string()),
        });
    }

    match state
        .templates
        .upload_zip(name, file_name, file_bytes)
        .await
    {
        Ok(_) => Redirect::to("/admin/templates").into_response(),
        Err(err) => render(TemplatesTemplate {
            active: "templates",
            csrf_token: csrf_token(&cookies),
            templates: state.templates.list().await.unwrap_or_default(),
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_template_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }

    match state.templates.delete(id).await {
        Ok(_) => Redirect::to("/admin/templates").into_response(),
        Err(err) => render(TemplatesTemplate {
            active: "templates",
            csrf_token: csrf_token(&cookies),
            templates: state.templates.list().await.unwrap_or_default(),
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_assets(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    render_assets(&state, &cookies, None).await
}

async fn admin_asset_upload(
    State(state): State<AppState>,
    cookies: Cookies,
    mut multipart: Multipart,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }

    let mut file_name = String::new();
    let mut file_bytes = Vec::new();
    let mut csrf = String::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == CSRF_FIELD {
            csrf = field.text().await.unwrap_or_default();
        } else if !require_admin_form(&state, &cookies, &csrf).await {
            return Redirect::to("/admin/login").into_response();
        } else if field_name == "file" {
            file_name = field.file_name().unwrap_or("image").to_string();
            file_bytes = field
                .bytes()
                .await
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default();
        }
    }

    if !require_admin_form(&state, &cookies, &csrf).await {
        return Redirect::to("/admin/login").into_response();
    }

    match state.assets.upload(file_name, file_bytes).await {
        Ok(_) => Redirect::to("/admin/assets").into_response(),
        Err(err) => render_assets(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_asset_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }

    match state.assets.delete(id).await {
        Ok(_) => Redirect::to("/admin/assets").into_response(),
        Err(err) => render_assets(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn render_assets(state: &AppState, cookies: &Cookies, error: Option<String>) -> Response {
    render(AssetsTemplate {
        active: "assets",
        csrf_token: csrf_token(cookies),
        assets: state.assets.list().await.unwrap_or_default(),
        error,
    })
}

async fn admin_cloak(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    render_cloak(&state, &cookies, None).await
}

async fn admin_cloak_save(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CloakForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.cloak.save_route_config(form.into()).await {
        Ok(_) => Redirect::to("/admin/cloak").into_response(),
        Err(err) => render_cloak(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_blacklist_add(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<BlacklistForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state
        .cloak
        .add_blacklist(&form.cidr, &form.note.unwrap_or_default())
        .await
    {
        Ok(_) => Redirect::to("/admin/cloak").into_response(),
        Err(err) => render_cloak(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_blacklist_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = state.cloak.delete_blacklist(id).await {
        tracing::warn!(error = %err, blacklist_id = %id, "failed to delete blacklist");
    }
    Redirect::to("/admin/cloak").into_response()
}

async fn render_cloak(state: &AppState, cookies: &Cookies, error: Option<String>) -> Response {
    let routes = state.cloak.list_route_configs().await.unwrap_or_default();
    let blacklist = state.cloak.list_blacklist().await.unwrap_or_default();
    render(CloakTemplate {
        active: "cloak",
        csrf_token: csrf_token(cookies),
        routes,
        blacklist,
        error,
    })
}

async fn admin_meta(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(query): Query<MetaQuery>,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    render_meta(&state, &cookies, query.archived.is_some(), None, None).await
}

async fn admin_meta_save(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<MetaForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }

    let input = match SaveMetaInput::try_from(form) {
        Ok(input) => input,
        Err(err) => {
            return render_meta(&state, &cookies, false, None, Some(err.to_string())).await;
        }
    };
    match state.meta.save_route_config(input).await {
        Ok(_) => Redirect::to("/admin/meta").into_response(),
        Err(err) => render_meta(&state, &cookies, false, None, Some(err.to_string())).await,
    }
}

async fn admin_meta_event_retry(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.meta.retry_event(id).await {
        Ok(_) => Redirect::to("/admin/meta").into_response(),
        Err(err) => render_meta(&state, &cookies, false, None, Some(err.to_string())).await,
    }
}

async fn admin_meta_event_archive(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.meta.archive_event(id).await {
        Ok(_) => Redirect::to("/admin/meta").into_response(),
        Err(err) => render_meta(&state, &cookies, false, None, Some(err.to_string())).await,
    }
}

async fn admin_meta_archive_finished(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<MetaArchiveForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    let older_than_days = form.older_than_days.unwrap_or(30);
    match state.meta.archive_finished(older_than_days).await {
        Ok(count) => {
            render_meta(
                &state,
                &cookies,
                false,
                Some(format!("Meta 事件归档完成：归档 {count} 条已完成事件。")),
                None,
            )
            .await
        }
        Err(err) => render_meta(&state, &cookies, false, None, Some(err.to_string())).await,
    }
}

async fn render_meta(
    state: &AppState,
    cookies: &Cookies,
    include_archived: bool,
    message: Option<String>,
    error: Option<String>,
) -> Response {
    let routes = state.meta.list_route_configs().await.unwrap_or_default();
    let events = state
        .meta
        .recent_events(include_archived)
        .await
        .unwrap_or_default();
    let stats = state.meta.event_stats().await.ok();
    let event_stats = state.meta.event_name_stats().await.unwrap_or_default();
    render(MetaTemplate {
        active: "meta",
        csrf_token: csrf_token(cookies),
        routes,
        events,
        stats,
        event_stats,
        include_archived,
        message,
        error,
    })
}

async fn admin_settings(State(state): State<AppState>, cookies: Cookies) -> Response {
    let Some(token) = session_token(&cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if !state.auth.session_valid(&token).await.unwrap_or(false) {
        return Redirect::to("/admin/login").into_response();
    }
    render_settings(&state, &token, None, None).await
}

async fn admin_change_password(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let Some(token) = session_token(&cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if form.csrf_token != csrf_token_for_session(&token)
        || !state.auth.session_valid(&token).await.unwrap_or(false)
    {
        return Redirect::to("/admin/login").into_response();
    }

    if form.new_password != form.confirm_password {
        return render_settings(
            &state,
            &token,
            None,
            Some("两次输入的新密码不一致".to_string()),
        )
        .await;
    }

    match state
        .auth
        .change_password(&token, &form.old_password, &form.new_password)
        .await
    {
        Ok(_) => {
            render_settings(
                &state,
                &token,
                Some("密码已更新，其他会话已下线。".to_string()),
                None,
            )
            .await
        }
        Err(err) => render_settings(&state, &token, None, Some(err.to_string())).await,
    }
}

async fn admin_revoke_session(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(token) = session_token(&cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if form.csrf_token != csrf_token_for_session(&token)
        || !state.auth.session_valid(&token).await.unwrap_or(false)
    {
        return Redirect::to("/admin/login").into_response();
    }

    match state.auth.revoke_session(&token, id).await {
        Ok(_) => render_settings(&state, &token, Some("会话已撤销。".to_string()), None).await,
        Err(err) => render_settings(&state, &token, None, Some(err.to_string())).await,
    }
}

async fn admin_geo_ip_add(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<GeoIpRangeForm>,
) -> Response {
    let Some(token) = session_token(&cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if form.csrf_token != csrf_token_for_session(&token)
        || !state.auth.session_valid(&token).await.unwrap_or(false)
    {
        return Redirect::to("/admin/login").into_response();
    }

    let input = SaveGeoIpRangeInput {
        cidr: form.cidr,
        country: form.country,
        province: form.province.unwrap_or_default(),
        city: form.city.unwrap_or_default(),
        isp: form.isp.unwrap_or_default(),
        source: form.source.unwrap_or_else(|| "manual".to_string()),
    };

    match state.geo.save(input).await {
        Ok(_) => {
            render_settings(
                &state,
                &token,
                Some("IP 地区规则已保存。".to_string()),
                None,
            )
            .await
        }
        Err(err) => render_settings(&state, &token, None, Some(err.to_string())).await,
    }
}

async fn admin_geo_ip_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(token) = session_token(&cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if form.csrf_token != csrf_token_for_session(&token)
        || !state.auth.session_valid(&token).await.unwrap_or(false)
    {
        return Redirect::to("/admin/login").into_response();
    }

    match state.geo.delete(id).await {
        Ok(_) => {
            render_settings(
                &state,
                &token,
                Some("IP 地区规则已删除。".to_string()),
                None,
            )
            .await
        }
        Err(err) => render_settings(&state, &token, None, Some(err.to_string())).await,
    }
}

async fn admin_cleanup_resources(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(token) = session_token(&cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if form.csrf_token != csrf_token_for_session(&token)
        || !state.auth.session_valid(&token).await.unwrap_or(false)
    {
        return Redirect::to("/admin/login").into_response();
    }

    let asset_removed = state.assets.cleanup_orphan_files().await;
    let template_removed = state.templates.cleanup_orphan_dirs().await;
    match (asset_removed, template_removed) {
        (Ok(files), Ok(dirs)) => {
            let message =
                format!("资源清理完成：删除孤儿素材文件 {files} 个，模板目录 {dirs} 个。");
            render_settings(&state, &token, Some(message), None).await
        }
        (Err(err), _) | (_, Err(err)) => {
            render_settings(&state, &token, None, Some(format!("资源清理失败：{err}"))).await
        }
    }
}

async fn admin_cleanup_audits(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<AuditCleanupForm>,
) -> Response {
    let Some(token) = session_token(&cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if form.csrf_token != csrf_token_for_session(&token)
        || !state.auth.session_valid(&token).await.unwrap_or(false)
    {
        return Redirect::to("/admin/login").into_response();
    }

    let keep_days = form.keep_days.unwrap_or(90);
    match state.auth.cleanup_audits(&token, keep_days).await {
        Ok(deleted) => {
            let keep_days = keep_days.clamp(7, 3650);
            render_settings(
                &state,
                &token,
                Some(format!(
                    "审计日志清理完成：保留最近 {keep_days} 天，删除 {deleted} 条。"
                )),
                None,
            )
            .await
        }
        Err(err) => render_settings(&state, &token, None, Some(err.to_string())).await,
    }
}

async fn render_settings(
    state: &AppState,
    token: &str,
    message: Option<String>,
    error: Option<String>,
) -> Response {
    let (sessions, session_error) = match state.auth.list_sessions(token).await {
        Ok(sessions) => (sessions, None),
        Err(err) => (Vec::new(), Some(format!("会话列表加载失败：{err}"))),
    };
    let (audits, audit_error) = match state.auth.recent_audits(token).await {
        Ok(audits) => (audits, None),
        Err(err) => (Vec::new(), Some(format!("审计日志加载失败：{err}"))),
    };
    let (geo_ranges, geo_error) = match state.geo.list().await {
        Ok(ranges) => (ranges, None),
        Err(err) => (Vec::new(), Some(format!("IP 地区库加载失败：{err}"))),
    };
    let release = read_release_status(&state.settings.active_proxy_file);
    let release_history = read_release_history(&state.settings.release_history_file, 20);
    let error = error.or(session_error).or(audit_error).or(geo_error);
    render(SettingsTemplate {
        active: "settings",
        csrf_token: csrf_token_for_session(token),
        message,
        error,
        release,
        release_history,
        sessions,
        audits,
        geo_ranges,
    })
}

fn read_release_status(path: &str) -> ReleaseStatusView {
    let active_proxy = std::fs::read_to_string(path).unwrap_or_default();
    let active_color = if active_proxy.contains("app_green:3000") {
        "green".to_string()
    } else {
        "blue".to_string()
    };
    let active_service = format!("app_{active_color}");
    ReleaseStatusView {
        active_color,
        active_service,
        active_proxy: active_proxy.trim().to_string(),
    }
}

fn read_release_history(path: &str, limit: usize) -> Vec<ReleaseHistoryRow> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut rows = content
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .map(|value| ReleaseHistoryRow {
            timestamp: json_field(&value, "timestamp"),
            status: json_field(&value, "status"),
            from_color: json_field(&value, "from_color"),
            to_color: json_field(&value, "to_color"),
            image: json_field(&value, "image"),
            message: json_field(&value, "message"),
        })
        .take(limit)
        .collect::<Vec<_>>();
    rows.shrink_to_fit();
    rows
}

fn json_field(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

async fn public_entry(
    State(state): State<AppState>,
    Query(query): Query<PublicQuery>,
    headers: HeaderMap,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    match state.routes.find_public_by_host(host).await {
        Ok(Some(route)) if route.match_kind == "entry" => {
            let promo = query.c.clone().unwrap_or_default();
            let promo_hit = state
                .promos
                .find_enabled(route.id, &promo)
                .await
                .ok()
                .flatten();
            let exit_label = if route.target_type == "external" {
                route.external_url.clone()
            } else {
                route.exit_domain.clone().unwrap_or_default()
            };
            let (ip, _) = client_ip(&headers);
            let decision = state
                .cloak
                .decide(CloakCheckInput {
                    route_id: route.id,
                    ip: ip.as_deref(),
                    user_agent: &header_value(&headers, "user-agent"),
                    accept_language: &header_value(&headers, "accept-language"),
                    sec_ch_ua: &header_value(&headers, "sec-ch-ua"),
                    sec_fetch_site: &header_value(&headers, "sec-fetch-site"),
                })
                .await
                .unwrap_or(ab_services::CloakDecision {
                    fake: false,
                    reason: "分流判断失败，默认放行".to_string(),
                });
            if decision.fake {
                if let Err(err) = state
                    .visits
                    .record(
                        build_visit_input(
                            &state,
                            &headers,
                            route.id,
                            promo_hit.as_ref().map(|hit| hit.id),
                            promo,
                            "fake",
                            &decision.reason,
                            route.entry_domain.clone(),
                            exit_label,
                        )
                        .await,
                    )
                    .await
                {
                    tracing::warn!(error = %err, route_id = %route.id, "failed to record fake visit");
                }

                let (decoy_title, decoy_apk_url) = state
                    .cloak
                    .decoy_for_route(route.id)
                    .await
                    .unwrap_or_else(|_| ("下载".to_string(), String::new()));
                return render(DefaultLandingTemplate {
                    route_id: route.id,
                    promo_id: promo_hit.map(|hit| hit.id),
                    visit_id: None,
                    event_token_json: "null".to_string(),
                    title: &decoy_title,
                    image_url: String::new(),
                    apk_url_json: serde_json::to_string(&decoy_apk_url)
                        .unwrap_or_else(|_| "\"\"".to_string()),
                    meta_json: "null".to_string(),
                    auto_download: false,
                });
            }

            let visit_id = match state
                .visits
                .record(
                    build_visit_input(
                        &state,
                        &headers,
                        route.id,
                        promo_hit.as_ref().map(|hit| hit.id),
                        promo,
                        "real",
                        &decision.reason,
                        route.entry_domain.clone(),
                        exit_label,
                    )
                    .await,
                )
                .await
            {
                Ok(id) => Some(id),
                Err(err) => {
                    tracing::warn!(error = %err, route_id = %route.id, "failed to record entry visit");
                    None
                }
            };
            if let Some(id) = visit_id {
                send_meta_event(
                    &state,
                    MetaEventInput {
                        route_id: route.id,
                        event_name: "ViewContent".to_string(),
                        event_id: format!("vc_{id}"),
                        event_source_url: request_url(host, &query),
                        user_agent: header_value(&headers, "user-agent"),
                        ip,
                        fbp: String::new(),
                        fbc: fbc_from_query(&query),
                    },
                );
            }
            if route.target_type == "external" {
                match append_public_query(&route.external_url, &query, visit_id) {
                    Ok(url) => Redirect::to(&url).into_response(),
                    Err(err) => {
                        tracing::error!(error = %err, route_id = %route.id, "failed to build external redirect");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            } else if let Some(exit_domain) = route.exit_domain {
                let mut url = format!("https://{exit_domain}/");
                append_query_pairs(&mut url, &query, visit_id);
                Redirect::to(&url).into_response()
            } else {
                render_with_status(StatusCode::NOT_FOUND, NotConfiguredTemplate { host })
            }
        }
        Ok(Some(route)) => {
            let promo = query.c.clone().unwrap_or_default();
            let promo_hit = state
                .promos
                .find_enabled(route.id, &promo)
                .await
                .ok()
                .flatten();
            let promo_id = promo_hit.as_ref().map(|hit| hit.id);
            let apk_url = promo_hit
                .as_ref()
                .and_then(|hit| hit.apk_url.as_ref())
                .filter(|url| !url.is_empty())
                .unwrap_or(&route.apk_url);
            let meta_json = browser_meta_json(&state, route.id).await;
            if route.landing_mode == "template" {
                if let (Some(template_id), Some(entry_file)) =
                    (route.template_id, route.template_entry_file.as_deref())
                {
                    let template_url = append_template_query(
                        &format!("/landing-templates/{template_id}/{entry_file}"),
                        &query,
                    );
                    return render(TemplateFrameTemplate {
                        route_id: route.id,
                        promo_id,
                        visit_id: query.v,
                        event_token_json: public_event_token_json(&state, route.id, query.v),
                        template_url,
                        apk_url_json: serde_json::to_string(apk_url)
                            .unwrap_or_else(|_| "\"\"".to_string()),
                        meta_json: meta_json.clone(),
                        auto_download: route.auto_download,
                    });
                }
            }
            render(DefaultLandingTemplate {
                route_id: route.id,
                promo_id,
                visit_id: query.v,
                event_token_json: public_event_token_json(&state, route.id, query.v),
                title: &route.title,
                image_url: route
                    .image_asset_id
                    .map(|id| format!("/uploads/{id}"))
                    .unwrap_or_default(),
                apk_url_json: serde_json::to_string(apk_url).unwrap_or_else(|_| "\"\"".to_string()),
                meta_json,
                auto_download: route.auto_download,
            })
        }
        Ok(None) => render_with_status(StatusCode::NOT_FOUND, NotConfiguredTemplate { host }),
        Err(err) => {
            tracing::error!(error = %err, host, "failed to resolve public route");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn template_file(
    State(state): State<AppState>,
    Path((id, file)): Path<(Uuid, String)>,
) -> Response {
    let template = match state.templates.get(id).await {
        Ok(Some(template)) => template,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::warn!(error = %err, template_id = %id, "failed to load template record");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let path = match state.templates.template_file_path(&template, &file) {
        Ok(path) => path,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            ([(axum::http::header::CONTENT_TYPE, mime.as_ref())], bytes).into_response()
        }
        Err(err) => {
            tracing::warn!(error = %err, template_id = %id, "failed to serve template file");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

async fn asset_file(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let asset = match state.assets.get(id).await {
        Ok(Some(asset)) => asset,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::warn!(error = %err, asset_id = %id, "failed to load asset record");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let path = match state.assets.file_path(&asset) {
        Ok(path) => path,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match tokio::fs::read(path).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, asset.mime_type.as_str())],
            bytes,
        )
            .into_response(),
        Err(err) => {
            tracing::warn!(error = %err, asset_id = %id, "failed to serve asset");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

async fn build_visit_input(
    state: &AppState,
    headers: &HeaderMap,
    route_id: Uuid,
    promo_id: Option<Uuid>,
    promo_code: String,
    page_variant: &str,
    cloak_reason: &str,
    entry_domain: String,
    exit_domain: String,
) -> RecordVisitInput {
    let (ip, ip_source) = client_ip(headers);
    let user_agent = header_value(headers, "user-agent");
    let parsed = parse_user_agent(&user_agent);
    let mut country = header_value(headers, "cf-ipcountry");
    let mut province = first_non_empty(&[
        header_value(headers, "cf-region"),
        header_value(headers, "x-vercel-ip-country-region"),
    ]);
    let mut city = first_non_empty(&[
        header_value(headers, "cf-ipcity"),
        header_value(headers, "x-vercel-ip-city"),
    ]);
    let mut isp = first_non_empty(&[
        header_value(headers, "cf-as-organization"),
        header_value(headers, "x-isp"),
        header_value(headers, "x-as-organization"),
    ]);

    if country.is_empty() || province.is_empty() || city.is_empty() || isp.is_empty() {
        if let Some(ip_text) = ip
            .as_deref()
            .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
        {
            match state.geo.lookup(ip_text).await {
                Ok(Some(hit)) => {
                    if country.is_empty() {
                        country = hit.country;
                    }
                    if province.is_empty() {
                        province = hit.province;
                    }
                    if city.is_empty() {
                        city = hit.city;
                    }
                    if isp.is_empty() {
                        isp = hit.isp;
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(error = %err, ip = ip_text, "failed to lookup geo ip");
                }
            }
        }
    }

    RecordVisitInput {
        route_id,
        promo_id,
        promo_code,
        page_variant: page_variant.to_string(),
        cloak_reason: cloak_reason.to_string(),
        entry_domain,
        exit_domain,
        ip,
        ip_source,
        cf_ray: header_value(headers, "cf-ray"),
        country,
        province,
        city,
        isp,
        os: parsed.os,
        os_version: parsed.os_version,
        device: parsed.device,
        browser: parsed.browser,
        language: header_value(headers, "accept-language")
            .split(',')
            .next()
            .unwrap_or("")
            .to_string(),
        referer: header_value(headers, "referer"),
        user_agent,
    }
}

fn client_ip(headers: &HeaderMap) -> (Option<String>, String) {
    for key in [
        "cf-connecting-ip",
        "true-client-ip",
        "x-forwarded-for",
        "x-real-ip",
    ] {
        let value = header_value(headers, key);
        if value.is_empty() {
            continue;
        }
        let ip = value.split(',').next().unwrap_or("").trim().to_string();
        if !ip.is_empty() {
            return (Some(ip), key.to_string());
        }
    }
    (None, String::new())
}

fn header_value(headers: &HeaderMap, key: &str) -> String {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string()
}

#[derive(Debug, Default)]
struct ParsedUserAgent {
    os: String,
    os_version: String,
    device: String,
    browser: String,
}

fn parse_user_agent(user_agent: &str) -> ParsedUserAgent {
    let ua = user_agent.to_ascii_lowercase();
    ParsedUserAgent {
        os: parse_os(user_agent, &ua),
        os_version: parse_os_version(user_agent, &ua),
        device: parse_device(&ua),
        browser: parse_browser(user_agent, &ua),
    }
}

fn parse_os(original: &str, lower: &str) -> String {
    if lower.contains("android") {
        "Android".to_string()
    } else if lower.contains("iphone") || lower.contains("ipad") || lower.contains("ios") {
        "iOS".to_string()
    } else if lower.contains("windows nt") {
        "Windows".to_string()
    } else if lower.contains("mac os x") {
        "macOS".to_string()
    } else if lower.contains("linux") {
        "Linux".to_string()
    } else if original.trim().is_empty() {
        String::new()
    } else {
        "Unknown".to_string()
    }
}

fn parse_os_version(original: &str, lower: &str) -> String {
    if let Some(value) = after_token(lower, "android ") {
        return take_version(value);
    }
    if lower.contains("iphone") || lower.contains("ipad") {
        if let Some(value) = after_token(original, "OS ") {
            return take_version(value).replace('_', ".");
        }
    }
    if let Some(value) = after_token(lower, "windows nt ") {
        return take_version(value);
    }
    if let Some(value) = after_token(original, "Mac OS X ") {
        return take_version(value).replace('_', ".");
    }
    String::new()
}

fn parse_device(lower: &str) -> String {
    if lower.contains("ipad") || lower.contains("tablet") {
        "Tablet".to_string()
    } else if lower.contains("iphone") || lower.contains("android") || lower.contains("mobile") {
        "Mobile".to_string()
    } else if lower.contains("windows") || lower.contains("macintosh") || lower.contains("linux") {
        "Desktop".to_string()
    } else {
        String::new()
    }
}

fn parse_browser(original: &str, lower: &str) -> String {
    if lower.contains("micromessenger/") {
        format_browser("WeChat", original, "MicroMessenger/")
    } else if lower.contains("fban/") || lower.contains("fbav/") {
        format_browser("Facebook", original, "FBAV/")
    } else if lower.contains("edg/") {
        format_browser("Edge", original, "Edg/")
    } else if lower.contains("firefox/") {
        format_browser("Firefox", original, "Firefox/")
    } else if lower.contains("chrome/") || lower.contains("crios/") {
        format_browser(
            "Chrome",
            original,
            if lower.contains("crios/") {
                "CriOS/"
            } else {
                "Chrome/"
            },
        )
    } else if lower.contains("safari/") && lower.contains("version/") {
        format_browser("Safari", original, "Version/")
    } else {
        String::new()
    }
}

fn format_browser(name: &str, original: &str, token: &str) -> String {
    let version = after_token(original, token)
        .map(take_version)
        .unwrap_or_default();
    if version.is_empty() {
        name.to_string()
    } else {
        format!("{name} {version}")
    }
}

fn after_token<'a>(value: &'a str, token: &str) -> Option<&'a str> {
    let index = value.find(token)?;
    Some(&value[index + token.len()..])
}

fn take_version(value: &str) -> String {
    value
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '.' || *ch == '_')
        .collect()
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or("")
        .to_string()
}

fn limit_text(value: String, max: usize) -> String {
    value.chars().take(max).collect()
}

async fn browser_meta_json(state: &AppState, route_id: Uuid) -> String {
    match state.meta.browser_config(route_id).await {
        Ok(Some(config)) => serde_json::to_string(&config).unwrap_or_else(|_| "null".to_string()),
        Ok(None) => "null".to_string(),
        Err(err) => {
            tracing::warn!(error = %err, route_id = %route_id, "failed to load meta browser config");
            "null".to_string()
        }
    }
}

fn send_meta_event(state: &AppState, input: MetaEventInput) {
    let meta = state.meta.clone();
    tokio::spawn(async move {
        if let Err(err) = meta.enqueue_event(input).await {
            tracing::warn!(error = %err, "failed to enqueue meta capi event");
        }
    });
}

fn request_url(host: &str, query: &PublicQuery) -> String {
    let mut url = format!("https://{host}/");
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    let mut has_pair = false;
    if let Some(value) = query.c.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("c", value);
        has_pair = true;
    }
    if let Some(value) = query.v {
        serializer.append_pair("v", &value.to_string());
        has_pair = true;
    }
    if let Some(value) = query.fbclid.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("fbclid", value);
        has_pair = true;
    }
    if has_pair {
        url.push('?');
        url.push_str(&serializer.finish());
    }
    url
}

fn fbc_from_query(query: &PublicQuery) -> String {
    let Some(fbclid) = query.fbclid.as_deref().filter(|value| !value.is_empty()) else {
        return String::new();
    };
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default();
    format!("fb.1.{millis}.{fbclid}")
}

async fn tls_check(
    State(state): State<AppState>,
    Query(query): Query<TlsCheckQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let host_header = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let host = query.domain.as_deref().unwrap_or(host_header);

    let allowed = !host.is_empty()
        && (host == state.settings.base_domain
            || state.routes.domain_allowed(host).await.unwrap_or(false));
    if allowed {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    }
}

async fn collect(State(state): State<AppState>, Json(payload): Json<CollectPayload>) -> StatusCode {
    let (Some(route_id), Some(visit_id)) = (payload.route_id, payload.visit_id) else {
        return StatusCode::ACCEPTED;
    };
    if !valid_public_event_token(
        &state,
        route_id,
        visit_id,
        payload.token.as_deref().unwrap_or(""),
    ) {
        return StatusCode::ACCEPTED;
    }

    if let Err(err) = state
        .visits
        .update_client(UpdateVisitClientInput {
            visit_id,
            screen: payload.screen.unwrap_or_default(),
            timezone: payload.timezone.unwrap_or_default(),
            network: limit_text(payload.network.unwrap_or_default(), 2000),
            fingerprint: limit_text(payload.fingerprint.unwrap_or_default(), 128),
        })
        .await
    {
        tracing::warn!(error = %err, visit_id = %visit_id, "failed to update visit client fields");
    }
    StatusCode::ACCEPTED
}

async fn downloaded(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DownloadedPayload>,
) -> StatusCode {
    let (Some(route_id), Some(visit_id)) = (payload.route_id, payload.visit_id) else {
        return StatusCode::ACCEPTED;
    };
    if !valid_public_event_token(
        &state,
        route_id,
        visit_id,
        payload.token.as_deref().unwrap_or(""),
    ) {
        return StatusCode::ACCEPTED;
    }
    let event_id = payload
        .event_id
        .filter(|value| !value.trim().is_empty())
        .or_else(|| payload.visit_id.map(|id| format!("lead_{id}")))
        .unwrap_or_else(|| format!("lead_{}", Uuid::now_v7()));
    let promo_id = payload.promo_id;
    let apk_url = payload.apk_url.unwrap_or_default();
    let event_source_url = payload.url.unwrap_or_default();
    let dedup_key = format!("download:{route_id}:{visit_id}:{event_id}");
    if !state.security.mark_public_event_once(
        &dedup_key,
        Duration::from_secs(PUBLIC_EVENT_DEDUP_TTL_SECONDS),
    ) {
        return StatusCode::ACCEPTED;
    }

    if let Err(err) = state
        .visits
        .record_download(RecordDownloadInput {
            route_id: Some(route_id),
            visit_id: Some(visit_id),
            promo_id,
            event_id: event_id.clone(),
            apk_url,
        })
        .await
    {
        tracing::warn!(error = %err, "failed to record download event");
        state.security.clear_public_event_hit(&dedup_key);
        return StatusCode::ACCEPTED;
    }

    let (ip, _) = client_ip(&headers);
    send_meta_event(
        &state,
        MetaEventInput {
            route_id,
            event_name: "Lead".to_string(),
            event_id,
            event_source_url,
            user_agent: header_value(&headers, "user-agent"),
            ip,
            fbp: payload.fbp.unwrap_or_default(),
            fbc: payload.fbc.unwrap_or_default(),
        },
    );
    StatusCode::ACCEPTED
}

async fn is_admin(state: &AppState, cookies: &Cookies) -> bool {
    let Some(token) = session_token(cookies) else {
        return false;
    };
    state.auth.session_valid(&token).await.unwrap_or(false)
}

async fn require_admin_form(state: &AppState, cookies: &Cookies, csrf_token: &str) -> bool {
    let Some(token) = session_token(cookies) else {
        return false;
    };
    if csrf_token != csrf_token_for_session(&token) {
        return false;
    }
    state.auth.session_valid(&token).await.unwrap_or(false)
}

fn session_token(cookies: &Cookies) -> Option<String> {
    cookies
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_string())
        .filter(|token| !token.trim().is_empty())
}

fn csrf_token(cookies: &Cookies) -> String {
    session_token(cookies)
        .map(|token| csrf_token_for_session(&token))
        .unwrap_or_default()
}

fn csrf_token_for_session(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CSRF_SALT.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

fn login_failure_key(ip: Option<&str>, username: &str) -> String {
    let username = username.trim().to_ascii_lowercase();
    let ip = ip.unwrap_or("unknown").trim();
    format!("{ip}:{username}")
}

fn public_event_token_json(state: &AppState, route_id: Uuid, visit_id: Option<Uuid>) -> String {
    visit_id
        .map(|id| public_event_token(state, route_id, id))
        .and_then(|token| serde_json::to_string(&token).ok())
        .unwrap_or_else(|| "null".to_string())
}

fn public_event_token(state: &AppState, route_id: Uuid, visit_id: Uuid) -> String {
    let expires_at = unix_timestamp() + PUBLIC_EVENT_TOKEN_TTL_SECONDS;
    let payload = format!("{route_id}.{visit_id}.{expires_at}");
    let signature = public_event_signature(state, &payload);
    format!("{payload}.{signature}")
}

fn valid_public_event_token(state: &AppState, route_id: Uuid, visit_id: Uuid, token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(route), Some(visit), Some(expires), Some(signature), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    if route != route_id.to_string() || visit != visit_id.to_string() {
        return false;
    }
    let Ok(expires_at) = expires.parse::<i64>() else {
        return false;
    };
    if expires_at < unix_timestamp() {
        return false;
    }

    let payload = format!("{route}.{visit}.{expires}");
    let expected = public_event_signature(state, &payload);
    constant_time_eq(signature.as_bytes(), expected.as_bytes())
}

fn public_event_signature(state: &AppState, payload: &str) -> String {
    let secret = if state.settings.meta_token_key.is_empty() {
        state.settings.admin_password.as_bytes()
    } else {
        state.settings.meta_token_key.as_bytes()
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let signature = hmac::sign(&key, format!("{PUBLIC_EVENT_SALT}:{payload}").as_bytes());
    hex_encode(signature.as_ref())
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn session_cookie(token: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, token);
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(CookieDuration::seconds(SESSION_TTL_SECONDS));
    cookie.set_secure(secure);
    cookie
}

fn expired_session_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::from(SESSION_COOKIE);
    cookie.set_path("/");
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(CookieDuration::seconds(0));
    cookie
}

fn request_is_https(headers: &HeaderMap) -> bool {
    header_value(headers, "x-forwarded-proto")
        .split(',')
        .next()
        .map(|value| value.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
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

fn append_public_query(
    base: &str,
    query: &PublicQuery,
    visit_id: Option<Uuid>,
) -> anyhow::Result<String> {
    let mut url = url::Url::parse(base)?;
    if let Some(value) = query.c.as_deref().filter(|value| !value.is_empty()) {
        url.query_pairs_mut().append_pair("c", value);
    }
    if let Some(value) = visit_id {
        url.query_pairs_mut().append_pair("v", &value.to_string());
    }
    if let Some(value) = query.fbclid.as_deref().filter(|value| !value.is_empty()) {
        url.query_pairs_mut().append_pair("fbclid", value);
    }
    Ok(url.to_string())
}

fn append_query_pairs(url: &mut String, query: &PublicQuery, visit_id: Option<Uuid>) {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    let mut has_pair = false;
    if let Some(value) = query.c.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("c", value);
        has_pair = true;
    }
    if let Some(value) = visit_id {
        serializer.append_pair("v", &value.to_string());
        has_pair = true;
    }
    if let Some(value) = query.fbclid.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("fbclid", value);
        has_pair = true;
    }
    if !has_pair {
        return;
    }

    let query_string = serializer.finish();
    url.push('?');
    url.push_str(&query_string);
}

fn append_template_query(base: &str, query: &PublicQuery) -> String {
    let mut url = base.to_string();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    let mut has_pair = false;
    if let Some(value) = query.c.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("c", value);
        has_pair = true;
    }
    if let Some(value) = query.v {
        serializer.append_pair("v", &value.to_string());
        has_pair = true;
    }
    if let Some(value) = query.fbclid.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("fbclid", value);
        has_pair = true;
    }
    if has_pair {
        url.push('?');
        url.push_str(&serializer.finish());
    }
    url
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("template render error: {err}"),
        )
            .into_response(),
    }
}

fn render_with_status<T: Template>(status: StatusCode, template: T) -> Response {
    match template.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("template render error: {err}"),
        )
            .into_response(),
    }
}
