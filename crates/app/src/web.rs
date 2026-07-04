use ab_services::{
    Asset, AuditRow, CloakCheckInput, DashboardStats, GeoIpRange, IpBlacklistRow, LandingProfile,
    LandingTemplate, MetaEventFilter, MetaEventInput, MetaProfile, MetaProfileEvents,
    RecordDownloadInput, RecordVisitInput, RouteEdit, RouteSummary, SaveCloakInput,
    SaveCloakPolicyInput, SaveDomainInput, SaveGeoIpRangeInput, SaveLandingProfileInput,
    SaveMetaInput, SaveMetaProfileInput, SavePromoInput, SaveRouteInput, SessionRow,
    UpdateVisitClientInput, VisitListResult,
};
use askama::Template;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use chrono::NaiveDate;
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
const HUMAN_COOKIE: &str = "ab_human";
const PROBED_COOKIE: &str = "ab_probed";
const HUMAN_TOKEN_SALT: &str = "ab-human-token-v1";
const EXIT_TOKEN_SALT: &str = "ab-exit-token-v1";
const EXIT_TRANSFER_TOKEN_TTL_SECONDS: i64 = 120;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(public_entry))
        .route("/health", get(health))
        .route("/api/tls-check", get(tls_check))
        .route("/api/cloak/verify", post(cloak_verify))
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
        .route("/admin/domains", get(admin_domains))
        .route("/admin/landing", get(admin_landing))
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
        .route("/admin/resources", get(admin_resources))
        .route("/admin/domains/save", post(admin_resource_domain_save))
        .route(
            "/admin/domains/:id/update",
            post(admin_resource_domain_update),
        )
        .route(
            "/admin/domains/:id/toggle",
            post(admin_resource_domain_toggle),
        )
        .route(
            "/admin/domains/:id/delete",
            post(admin_resource_domain_delete),
        )
        .route(
            "/admin/landing/profiles/save",
            post(admin_landing_profile_save).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
        .route(
            "/admin/landing/profiles/:id/update",
            post(admin_landing_profile_update).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
        .route(
            "/admin/landing/profiles/:id/toggle",
            post(admin_resource_landing_toggle),
        )
        .route(
            "/admin/landing/profiles/:id/delete",
            post(admin_resource_landing_delete),
        )
        .route(
            "/admin/cloak/policies/save",
            post(admin_cloak_policy_save).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
        .route(
            "/admin/cloak/policies/:id/update",
            post(admin_cloak_policy_update).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
        .route(
            "/admin/cloak/policies/:id/toggle",
            post(admin_resource_cloak_policy_toggle),
        )
        .route(
            "/admin/cloak/policies/:id/delete",
            post(admin_resource_cloak_policy_delete),
        )
        .route(
            "/admin/meta/profiles/save",
            post(admin_resource_meta_profile_save),
        )
        .route(
            "/admin/meta/profiles/:id/update",
            post(admin_resource_meta_profile_update),
        )
        .route(
            "/admin/meta/profiles/:id/toggle",
            post(admin_resource_meta_profile_toggle),
        )
        .route(
            "/admin/meta/profiles/:id/delete",
            post(admin_resource_meta_profile_delete),
        )
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
    entry_domains: Vec<ab_services::DomainResource>,
    exit_domains: Vec<ab_services::DomainResource>,
    landing_profiles: Vec<LandingProfile>,
    cloak_policies: Vec<ab_services::CloakPolicy>,
    meta_profiles: Vec<MetaProfile>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/domains.html")]
struct DomainsTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    domains: Vec<ab_services::DomainResource>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/landing.html")]
struct LandingTemplatePage<'a> {
    active: &'a str,
    csrf_token: String,
    landing_profiles: Vec<LandingProfileView>,
    templates: Vec<LandingTemplate>,
    assets: Vec<Asset>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/cloak.html")]
struct CloakTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    policies: Vec<CloakPolicyView>,
    blacklist: Vec<IpBlacklistRow>,
    assets: Vec<Asset>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/meta.html")]
struct MetaTemplate<'a> {
    active: &'a str,
    csrf_token: String,
    profiles: Vec<MetaProfile>,
    active_profile_id: String,
    profile_events: Option<MetaProfileEvents>,
    include_archived: bool,
    status_filter: String,
    event_filter: String,
    route_filter: String,
    event_query_base: String,
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
    return_to: Option<String>,
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

#[derive(Debug, Clone, Default, Deserialize)]
struct PublicQuery {
    c: Option<String>,
    v: Option<Uuid>,
    ht: Option<String>,
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
struct CloakVerifyQuery {
    route: Option<Uuid>,
    c: Option<String>,
    fbclid: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ProbePayload {
    js: Option<bool>,
    webdriver: Option<bool>,
    automation: Option<bool>,
    has_chrome: Option<bool>,
    #[serde(alias = "hasChrome")]
    has_chrome_alias: Option<bool>,
    #[serde(default, alias = "webglVendor")]
    webgl_vendor: String,
    #[serde(default, alias = "webglRenderer")]
    webgl_renderer: String,
    plugins: Option<i32>,
    hc: Option<i32>,
    sw: Option<i32>,
    sh: Option<i32>,
    dpr: Option<Decimal>,
    #[serde(default)]
    tz: String,
    #[serde(default)]
    platform: String,
    #[serde(default, alias = "uaPlatform")]
    ua_platform: String,
    #[serde(default)]
    langs: String,
    #[serde(default)]
    notif: String,
    #[serde(default, alias = "notifQ")]
    notif_q: String,
    touch: Option<i32>,
}

#[derive(Debug, Serialize)]
struct CloakVerifyResponse {
    human: bool,
    next: String,
    reason: String,
    score: i32,
    header_score: i32,
    probe_score: i32,
    server_reason: String,
    target: String,
    threshold: i32,
}

#[derive(Debug, Default, Deserialize)]
struct AdminVisitQuery {
    page: Option<i64>,
    size: Option<i64>,
    q: Option<String>,
    promo: Option<String>,
    page_variant: Option<String>,
    downloaded: Option<String>,
    ip: Option<String>,
    date_from: Option<String>,
    date_to: Option<String>,
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
    profile: Option<String>,
    archived: Option<String>,
    status: Option<String>,
    event: Option<String>,
    route: Option<String>,
    page: Option<i64>,
    size: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct MetaArchiveForm {
    csrf_token: String,
    older_than_days: Option<i64>,
    return_to: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DomainResourceForm {
    csrf_token: String,
    domain: String,
    role: String,
    note: Option<String>,
    enabled: Option<String>,
}

impl From<DomainResourceForm> for SaveDomainInput {
    fn from(form: DomainResourceForm) -> Self {
        let _ = form.csrf_token;
        Self {
            domain: form.domain,
            role: form.role,
            note: form.note.unwrap_or_default(),
            enabled: form.enabled.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
struct LandingProfileMultipart {
    csrf_token: String,
    name: String,
    landing_mode: String,
    template_id: Option<String>,
    image_asset_id: Option<String>,
    title: String,
    apk_url: String,
    auto_download: bool,
    enabled: bool,
    template_name: String,
    template_file_name: String,
    template_file_bytes: Vec<u8>,
    asset_file_name: String,
    asset_file_bytes: Vec<u8>,
}

impl LandingProfileMultipart {
    fn into_input(self) -> SaveLandingProfileInput {
        SaveLandingProfileInput {
            name: self.name,
            landing_mode: self.landing_mode,
            template_id: parse_optional_uuid(self.template_id.as_deref()),
            image_asset_id: parse_optional_uuid(self.image_asset_id.as_deref()),
            title: self.title,
            apk_url: self.apk_url,
            auto_download: self.auto_download,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone)]
struct CloakPolicyMultipart {
    csrf_token: String,
    name: String,
    enabled: bool,
    threshold: i32,
    token_hours: i32,
    decoy_title: String,
    decoy_image_asset_id: Option<String>,
    decoy_apk_url: String,
    use_ip_blacklist: bool,
    use_header_rules: bool,
    require_sec_fetch_mode: bool,
    use_js_probe: bool,
    use_asn: bool,
    use_ptr: bool,
    block_datacenter_asn: bool,
    block_datacenter_ptr: bool,
    block_verified_bot_ptr: bool,
    ptr_timeout_ms: i32,
    ptr_cache_hours: i32,
    asset_file_name: String,
    asset_file_bytes: Vec<u8>,
}

impl CloakPolicyMultipart {
    fn into_input(self) -> SaveCloakPolicyInput {
        SaveCloakPolicyInput {
            name: self.name,
            enabled: self.enabled,
            threshold: self.threshold,
            token_hours: self.token_hours,
            decoy_title: self.decoy_title,
            decoy_image_asset_id: parse_optional_uuid(self.decoy_image_asset_id.as_deref()),
            decoy_apk_url: self.decoy_apk_url,
            use_ip_blacklist: self.use_ip_blacklist,
            use_header_rules: self.use_header_rules,
            require_sec_fetch_mode: self.require_sec_fetch_mode,
            use_js_probe: self.use_js_probe,
            use_asn: self.use_asn,
            use_ptr: self.use_ptr,
            block_datacenter_asn: self.block_datacenter_asn,
            block_datacenter_ptr: self.block_datacenter_ptr,
            block_verified_bot_ptr: self.block_verified_bot_ptr,
            ptr_timeout_ms: self.ptr_timeout_ms,
            ptr_cache_hours: self.ptr_cache_hours,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct MetaProfileForm {
    csrf_token: String,
    name: String,
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

impl TryFrom<MetaProfileForm> for SaveMetaProfileInput {
    type Error = anyhow::Error;

    fn try_from(form: MetaProfileForm) -> Result<Self, Self::Error> {
        let value_text = form.value.as_deref().unwrap_or("0").trim();
        let value = if value_text.is_empty() {
            Decimal::ZERO
        } else {
            value_text
                .parse::<Decimal>()
                .map_err(|_| anyhow::anyhow!("事件价值必须是数字"))?
        };
        Ok(Self {
            name: form.name,
            enabled: form.enabled.is_some(),
            pixel_id: form.pixel_id,
            capi_token: form.capi_token.unwrap_or_default(),
            test_event_code: form.test_event_code.unwrap_or_default(),
            currency: form.currency.unwrap_or_else(|| "USD".to_string()),
            value,
            page_view_enabled: form.page_view_enabled.is_some(),
            view_content_enabled: form.view_content_enabled.is_some(),
            lead_enabled: form.lead_enabled.is_some(),
        })
    }
}

#[derive(Debug, Clone)]
struct LandingProfileView {
    id: Uuid,
    name: String,
    landing_mode: String,
    template_id_value: String,
    template_name: Option<String>,
    image_asset_id_value: String,
    image_name: Option<String>,
    title: String,
    apk_url: String,
    auto_download: bool,
    enabled: bool,
}

impl From<LandingProfile> for LandingProfileView {
    fn from(profile: LandingProfile) -> Self {
        Self {
            id: profile.id,
            name: profile.name,
            landing_mode: profile.landing_mode,
            template_id_value: profile
                .template_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            template_name: profile.template_name,
            image_asset_id_value: profile
                .image_asset_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            image_name: profile.image_name,
            title: profile.title,
            apk_url: profile.apk_url,
            auto_download: profile.auto_download,
            enabled: profile.enabled,
        }
    }
}

#[derive(Debug, Clone)]
struct CloakPolicyView {
    id: Uuid,
    name: String,
    enabled: bool,
    threshold: i32,
    token_hours: i32,
    decoy_title: String,
    decoy_image_asset_id_value: String,
    decoy_image_name: Option<String>,
    decoy_apk_url: String,
    use_ip_blacklist: bool,
    use_header_rules: bool,
    require_sec_fetch_mode: bool,
    use_js_probe: bool,
    use_asn: bool,
    use_ptr: bool,
    block_datacenter_asn: bool,
    block_datacenter_ptr: bool,
    block_verified_bot_ptr: bool,
    ptr_timeout_ms: i32,
    ptr_cache_hours: i32,
    rule_summary: String,
    bound_route_count: i64,
    bound_route_names: String,
    updated_at: String,
}

impl From<ab_services::CloakPolicy> for CloakPolicyView {
    fn from(policy: ab_services::CloakPolicy) -> Self {
        let rule_summary = cloak_rule_summary(&policy);
        Self {
            id: policy.id,
            name: policy.name,
            enabled: policy.enabled,
            threshold: policy.threshold,
            token_hours: policy.token_hours,
            decoy_title: policy.decoy_title,
            decoy_image_asset_id_value: policy
                .decoy_image_asset_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            decoy_image_name: policy.decoy_image_name,
            decoy_apk_url: policy.decoy_apk_url,
            use_ip_blacklist: policy.use_ip_blacklist,
            use_header_rules: policy.use_header_rules,
            require_sec_fetch_mode: policy.require_sec_fetch_mode,
            use_js_probe: policy.use_js_probe,
            use_asn: policy.use_asn,
            use_ptr: policy.use_ptr,
            block_datacenter_asn: policy.block_datacenter_asn,
            block_datacenter_ptr: policy.block_datacenter_ptr,
            block_verified_bot_ptr: policy.block_verified_bot_ptr,
            ptr_timeout_ms: policy.ptr_timeout_ms,
            ptr_cache_hours: policy.ptr_cache_hours,
            rule_summary,
            bound_route_count: policy.bound_route_count,
            bound_route_names: policy.bound_route_names,
            updated_at: policy.updated_at.to_string(),
        }
    }
}

fn cloak_rule_summary(policy: &ab_services::CloakPolicy) -> String {
    let mut rules = Vec::new();
    if policy.use_ip_blacklist {
        rules.push("IP");
    }
    if policy.use_header_rules {
        rules.push("Header");
    }
    if policy.use_js_probe {
        rules.push("JS");
    }
    if policy.use_asn {
        rules.push("ASN");
    }
    if policy.use_ptr {
        rules.push("PTR");
    }
    if rules.is_empty() {
        "仅手动放行".to_string()
    } else {
        rules.join(" / ")
    }
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
    exit_domain_id: Option<String>,
    exit_domain: Option<String>,
    external_url: Option<String>,
    landing_profile_id: Option<String>,
    landing_mode: Option<String>,
    template_id: Option<String>,
    image_asset_id: Option<String>,
    title: String,
    apk_url: Option<String>,
    cloak_policy_id: Option<String>,
    meta_profile_id: Option<String>,
    auto_download: Option<String>,
    enabled: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PromoForm {
    csrf_token: String,
    route_id: Uuid,
    code: String,
    name: String,
    enabled: Option<String>,
}

impl From<PromoForm> for SavePromoInput {
    fn from(form: PromoForm) -> Self {
        let _ = form.csrf_token;
        Self {
            route_id: form.route_id,
            code: form.code,
            name: form.name,
            enabled: form.enabled.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
struct RouteFormView {
    name: String,
    entry_domain: String,
    target_type: String,
    exit_domain_id_value: String,
    exit_domain: String,
    external_url: String,
    landing_profile_id_value: String,
    landing_mode: String,
    template_id_value: String,
    image_asset_id_value: String,
    title: String,
    apk_url: String,
    cloak_policy_id_value: String,
    meta_profile_id_value: String,
    auto_download: bool,
    enabled: bool,
}

struct RouteFormOptions {
    entry_domains: Vec<ab_services::DomainResource>,
    exit_domains: Vec<ab_services::DomainResource>,
    landing_profiles: Vec<LandingProfile>,
    cloak_policies: Vec<ab_services::CloakPolicy>,
    meta_profiles: Vec<MetaProfile>,
}

impl Default for RouteFormView {
    fn default() -> Self {
        Self {
            name: String::new(),
            entry_domain: String::new(),
            target_type: "internal".to_string(),
            exit_domain_id_value: String::new(),
            exit_domain: String::new(),
            external_url: String::new(),
            landing_profile_id_value: String::new(),
            landing_mode: "default".to_string(),
            template_id_value: String::new(),
            image_asset_id_value: String::new(),
            title: "下载".to_string(),
            apk_url: String::new(),
            cloak_policy_id_value: String::new(),
            meta_profile_id_value: String::new(),
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
            exit_domain_id_value: route
                .exit_domain_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            exit_domain: route.exit_domain.unwrap_or_default(),
            external_url: route.external_url,
            landing_profile_id_value: route
                .landing_profile_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
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
            cloak_policy_id_value: route
                .cloak_policy_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            meta_profile_id_value: route
                .meta_profile_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
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
            exit_domain_id_value: form.exit_domain_id.unwrap_or_default(),
            exit_domain: form.exit_domain.unwrap_or_default(),
            external_url: form.external_url.unwrap_or_default(),
            landing_profile_id_value: form.landing_profile_id.unwrap_or_default(),
            landing_mode: form.landing_mode.unwrap_or_else(|| "default".to_string()),
            template_id_value: form.template_id.unwrap_or_default(),
            image_asset_id_value: form.image_asset_id.unwrap_or_default(),
            title: form.title,
            apk_url: form.apk_url.unwrap_or_default(),
            cloak_policy_id_value: form.cloak_policy_id.unwrap_or_default(),
            meta_profile_id_value: form.meta_profile_id.unwrap_or_default(),
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
            exit_domain_id: parse_optional_uuid(form.exit_domain_id.as_deref()),
            exit_domain: form.exit_domain.unwrap_or_default(),
            external_url: form.external_url.unwrap_or_default(),
            landing_profile_id: parse_optional_uuid(form.landing_profile_id.as_deref()),
            landing_mode: form.landing_mode.unwrap_or_else(|| "default".to_string()),
            template_id: parse_optional_uuid(form.template_id.as_deref()),
            image_asset_id: parse_optional_uuid(form.image_asset_id.as_deref()),
            title: form.title,
            apk_url: form.apk_url.unwrap_or_default(),
            cloak_policy_id: parse_optional_uuid(form.cloak_policy_id.as_deref()),
            meta_profile_id: parse_optional_uuid(form.meta_profile_id.as_deref()),
            auto_download: form.auto_download.is_some(),
            enabled: form.enabled.is_some(),
        }
    }
}

async fn route_form_options(state: &AppState, view: &RouteFormView) -> RouteFormOptions {
    RouteFormOptions {
        entry_domains: state
            .resources
            .list_selectable_entry_domains(Some(&view.entry_domain))
            .await
            .unwrap_or_default(),
        exit_domains: state
            .resources
            .list_selectable_exit_domains(parse_optional_uuid(Some(&view.exit_domain_id_value)))
            .await
            .unwrap_or_default(),
        landing_profiles: state
            .resources
            .list_selectable_landing_profiles(parse_optional_uuid(Some(
                &view.landing_profile_id_value,
            )))
            .await
            .unwrap_or_default(),
        cloak_policies: state
            .resources
            .list_selectable_cloak_policies(parse_optional_uuid(Some(&view.cloak_policy_id_value)))
            .await
            .unwrap_or_default(),
        meta_profiles: state
            .resources
            .list_selectable_meta_profiles(parse_optional_uuid(Some(&view.meta_profile_id_value)))
            .await
            .unwrap_or_default(),
    }
}

fn render_route_form(
    cookies: &Cookies,
    mode: &'static str,
    action: String,
    route: RouteFormView,
    options: RouteFormOptions,
    error: Option<String>,
) -> Response {
    render(RouteFormTemplate {
        active: "routes",
        csrf_token: csrf_token(cookies),
        mode,
        action,
        route,
        entry_domains: options.entry_domains,
        exit_domains: options.exit_domains,
        landing_profiles: options.landing_profiles,
        cloak_policies: options.cloak_policies,
        meta_profiles: options.meta_profiles,
        error,
    })
}

fn parse_optional_uuid(value: Option<&str>) -> Option<Uuid> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn meta_return_url(return_to: Option<&str>) -> &str {
    match return_to.map(str::trim) {
        Some(path) if path == "/admin/meta" || path.starts_with("/admin/meta?") => path,
        _ => "/admin/meta",
    }
}

fn meta_event_query_base(
    profile_id: Uuid,
    page_size: i64,
    status: &str,
    event_name: &str,
    route: &str,
    include_archived: bool,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("profile", &profile_id.to_string());
    serializer.append_pair("size", &page_size.clamp(20, 200).to_string());
    if !status.trim().is_empty() {
        serializer.append_pair("status", status.trim());
    }
    if !event_name.trim().is_empty() {
        serializer.append_pair("event", event_name.trim());
    }
    if !route.trim().is_empty() {
        serializer.append_pair("route", route.trim());
    }
    if include_archived {
        serializer.append_pair("archived", "1");
    }
    serializer.finish()
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
        real_downloads: 0,
        today_real_downloads: 0,
        fake_downloads: 0,
        today_fake_downloads: 0,
        unique_device_downloads: 0,
        today_unique_device_downloads: 0,
        unique_ip_downloads: 0,
        today_unique_ip_downloads: 0,
        enabled_routes: 0,
        total_routes: 0,
        total_promos: 0,
        enabled_promos: 0,
        total_landing_profiles: 0,
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
    let route = RouteFormView::default();
    let options = route_form_options(&state, &route).await;
    render_route_form(
        &cookies,
        "新增线路",
        "/admin/routes/create".to_string(),
        route,
        options,
        None,
    )
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
    match state.routes.create(form.into()).await {
        Ok(_) => admin_config_redirect(&state, "/admin/routes"),
        Err(err) => {
            let options = route_form_options(&state, &view).await;
            render_route_form(
                &cookies,
                "新增线路",
                "/admin/routes/create".to_string(),
                view,
                options,
                Some(err.to_string()),
            )
        }
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
    match state.routes.get_edit(id).await {
        Ok(Some(route)) => {
            let view = RouteFormView::from(route);
            let options = route_form_options(&state, &view).await;
            render_route_form(
                &cookies,
                "编辑线路",
                format!("/admin/routes/{id}/update"),
                view,
                options,
                None,
            )
        }
        Ok(None) => Redirect::to("/admin/routes").into_response(),
        Err(err) => {
            let route = RouteFormView::default();
            let options = route_form_options(&state, &route).await;
            render_route_form(
                &cookies,
                "编辑线路",
                format!("/admin/routes/{id}/update"),
                route,
                options,
                Some(err.to_string()),
            )
        }
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
    match state.routes.update(id, form.into()).await {
        Ok(_) => admin_config_redirect(&state, "/admin/routes"),
        Err(err) => {
            let options = route_form_options(&state, &view).await;
            render_route_form(
                &cookies,
                "编辑线路",
                format!("/admin/routes/{id}/update"),
                view,
                options,
                Some(err.to_string()),
            )
        }
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
    match state.routes.toggle(id).await {
        Ok(_) => state.clear_public_config_cache(),
        Err(err) => tracing::error!(error = %err, route_id = %id, "failed to toggle route"),
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
    match state.routes.delete(id).await {
        Ok(_) => state.clear_public_config_cache(),
        Err(err) => tracing::error!(error = %err, route_id = %id, "failed to delete route"),
    }
    Redirect::to("/admin/routes").into_response()
}

async fn admin_promos(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    render_promos(&state, &cookies, None).await
}

async fn render_promos(state: &AppState, cookies: &Cookies, error: Option<String>) -> Response {
    let routes = state.routes.list_summaries().await.unwrap_or_default();
    match state.promos.list_summaries().await {
        Ok(promos) => render(PromosTemplate {
            active: "promos",
            csrf_token: csrf_token(cookies),
            promos,
            routes,
            error,
        }),
        Err(err) => render(PromosTemplate {
            active: "promos",
            csrf_token: csrf_token(cookies),
            promos: Vec::new(),
            routes,
            error: Some(err.to_string()),
        }),
    }
}

async fn admin_promo_new(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    Redirect::to("/admin/promos").into_response()
}

async fn admin_promo_create(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<PromoForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.promos.create(form.into()).await {
        Ok(_) => admin_config_redirect(&state, "/admin/promos"),
        Err(err) => render_promos(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_promo_edit(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(_id): Path<Uuid>,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    Redirect::to("/admin/promos").into_response()
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
    match state.promos.update(id, form.into()).await {
        Ok(_) => admin_config_redirect(&state, "/admin/promos"),
        Err(err) => render_promos(&state, &cookies, Some(err.to_string())).await,
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
    match state.promos.toggle(id).await {
        Ok(_) => state.clear_public_config_cache(),
        Err(err) => tracing::error!(error = %err, promo_id = %id, "failed to toggle promo"),
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
    match state.promos.delete(id).await {
        Ok(_) => state.clear_public_config_cache(),
        Err(err) => tracing::error!(error = %err, promo_id = %id, "failed to delete promo"),
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
            q: query.q,
            promo: query.promo,
            page_variant: query.page_variant,
            downloaded: query.downloaded,
            ip: query.ip,
            date_from: parse_visit_date(query.date_from.as_deref()),
            date_to: parse_visit_date(query.date_to.as_deref()),
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

fn parse_visit_date(value: Option<&str>) -> Option<NaiveDate> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

async fn admin_templates(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    Redirect::to("/admin/landing").into_response()
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
        return render_landing(&state, &cookies, Some("请选择 ZIP 模板包".to_string())).await;
    }

    match state
        .templates
        .upload_zip(name, file_name, file_bytes)
        .await
    {
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
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
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_assets(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    Redirect::to("/admin/landing").into_response()
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
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
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
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resources() -> Response {
    Redirect::to("/admin/domains").into_response()
}

async fn admin_domains(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    render_domains(&state, &cookies, None).await
}

async fn admin_landing(State(state): State<AppState>, cookies: Cookies) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    render_landing(&state, &cookies, None).await
}

async fn admin_resource_domain_save(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<DomainResourceForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.upsert_domain(form.into()).await {
        Ok(_) => admin_config_redirect(&state, "/admin/domains"),
        Err(err) => render_domains(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_domain_update(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<DomainResourceForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.update_domain(id, form.into()).await {
        Ok(_) => admin_config_redirect(&state, "/admin/domains"),
        Err(err) => render_domains(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_domain_toggle(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.toggle_domain(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/domains"),
        Err(err) => render_domains(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_domain_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.delete_domain(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/domains"),
        Err(err) => render_domains(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_landing_profile_save(
    State(state): State<AppState>,
    cookies: Cookies,
    multipart: Multipart,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let mut form = match parse_landing_profile_multipart(multipart).await {
        Ok(form) => form,
        Err(err) => return render_landing(&state, &cookies, Some(err.to_string())).await,
    };
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = apply_landing_uploads(&state, &mut form).await {
        return render_landing(&state, &cookies, Some(err.to_string())).await;
    }
    match state
        .resources
        .save_landing_profile(None, form.into_input())
        .await
    {
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_landing_profile_update(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    multipart: Multipart,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let mut form = match parse_landing_profile_multipart(multipart).await {
        Ok(form) => form,
        Err(err) => return render_landing(&state, &cookies, Some(err.to_string())).await,
    };
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = apply_landing_uploads(&state, &mut form).await {
        return render_landing(&state, &cookies, Some(err.to_string())).await;
    }
    match state
        .resources
        .save_landing_profile(Some(id), form.into_input())
        .await
    {
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_landing_toggle(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.toggle_landing_profile(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_landing_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.delete_landing_profile(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/landing"),
        Err(err) => render_landing(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_cloak_policy_save(
    State(state): State<AppState>,
    cookies: Cookies,
    multipart: Multipart,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let mut form = match parse_cloak_policy_multipart(multipart).await {
        Ok(form) => form,
        Err(err) => return render_cloak(&state, &cookies, Some(err.to_string())).await,
    };
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = apply_cloak_uploads(&state, &mut form).await {
        return render_cloak(&state, &cookies, Some(err.to_string())).await;
    }
    match state
        .resources
        .save_cloak_policy(None, form.into_input())
        .await
    {
        Ok(_) => admin_config_redirect(&state, "/admin/cloak"),
        Err(err) => render_cloak(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_cloak_policy_update(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    multipart: Multipart,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let mut form = match parse_cloak_policy_multipart(multipart).await {
        Ok(form) => form,
        Err(err) => return render_cloak(&state, &cookies, Some(err.to_string())).await,
    };
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(err) = apply_cloak_uploads(&state, &mut form).await {
        return render_cloak(&state, &cookies, Some(err.to_string())).await;
    }
    match state
        .resources
        .save_cloak_policy(Some(id), form.into_input())
        .await
    {
        Ok(_) => admin_config_redirect(&state, "/admin/cloak"),
        Err(err) => render_cloak(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_cloak_policy_toggle(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.toggle_cloak_policy(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/cloak"),
        Err(err) => render_cloak(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_cloak_policy_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.delete_cloak_policy(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/cloak"),
        Err(err) => render_cloak(&state, &cookies, Some(err.to_string())).await,
    }
}

async fn admin_resource_meta_profile_save(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<MetaProfileForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    let input = match SaveMetaProfileInput::try_from(form) {
        Ok(input) => input,
        Err(err) => {
            return render_meta_default(&state, &cookies, None, Some(err.to_string())).await;
        }
    };
    match state.resources.save_meta_profile(None, input).await {
        Ok(_) => admin_config_redirect(&state, "/admin/meta"),
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
    }
}

async fn admin_resource_meta_profile_update(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<MetaProfileForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    let input = match SaveMetaProfileInput::try_from(form) {
        Ok(input) => input,
        Err(err) => {
            return render_meta_default(&state, &cookies, None, Some(err.to_string())).await;
        }
    };
    match state.resources.save_meta_profile(Some(id), input).await {
        Ok(_) => admin_config_redirect(&state, "/admin/meta"),
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
    }
}

async fn admin_resource_meta_profile_toggle(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.toggle_meta_profile(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/meta"),
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
    }
}

async fn admin_resource_meta_profile_delete(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !require_admin_form(&state, &cookies, &form.csrf_token).await {
        return Redirect::to("/admin/login").into_response();
    }
    match state.resources.delete_meta_profile(id).await {
        Ok(_) => admin_config_redirect(&state, "/admin/meta"),
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
    }
}

async fn render_domains(state: &AppState, cookies: &Cookies, error: Option<String>) -> Response {
    render(DomainsTemplate {
        active: "domains",
        csrf_token: csrf_token(cookies),
        domains: state.resources.list_domains(None).await.unwrap_or_default(),
        error,
    })
}

async fn render_landing(state: &AppState, cookies: &Cookies, error: Option<String>) -> Response {
    let landing_profiles = state
        .resources
        .list_landing_profiles()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(LandingProfileView::from)
        .collect();
    render(LandingTemplatePage {
        active: "landing",
        csrf_token: csrf_token(cookies),
        landing_profiles,
        templates: state.templates.list().await.unwrap_or_default(),
        assets: state.assets.list().await.unwrap_or_default(),
        error,
    })
}

async fn parse_landing_profile_multipart(
    mut multipart: Multipart,
) -> anyhow::Result<LandingProfileMultipart> {
    let mut form = LandingProfileMultipart {
        csrf_token: String::new(),
        name: String::new(),
        landing_mode: "default".to_string(),
        template_id: None,
        image_asset_id: None,
        title: "下载".to_string(),
        apk_url: String::new(),
        auto_download: false,
        enabled: false,
        template_name: String::new(),
        template_file_name: String::new(),
        template_file_bytes: Vec::new(),
        asset_file_name: String::new(),
        asset_file_bytes: Vec::new(),
    };
    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            CSRF_FIELD => form.csrf_token = field.text().await.unwrap_or_default(),
            "name" => form.name = field.text().await.unwrap_or_default(),
            "landing_mode" => form.landing_mode = field.text().await.unwrap_or_default(),
            "template_id" => form.template_id = Some(field.text().await.unwrap_or_default()),
            "image_asset_id" => form.image_asset_id = Some(field.text().await.unwrap_or_default()),
            "title" => form.title = field.text().await.unwrap_or_default(),
            "apk_url" => form.apk_url = field.text().await.unwrap_or_default(),
            "auto_download" => form.auto_download = true,
            "enabled" => form.enabled = true,
            "template_name" => form.template_name = field.text().await.unwrap_or_default(),
            "template_file" => {
                form.template_file_name = field.file_name().unwrap_or("template.zip").to_string();
                form.template_file_bytes = field
                    .bytes()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .unwrap_or_default();
            }
            "asset_file" => {
                form.asset_file_name = field.file_name().unwrap_or("image").to_string();
                form.asset_file_bytes = field
                    .bytes()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
    Ok(form)
}

async fn apply_landing_uploads(
    state: &AppState,
    form: &mut LandingProfileMultipart,
) -> anyhow::Result<()> {
    if form.landing_mode == "template" && !form.template_file_bytes.is_empty() {
        let id = state
            .templates
            .upload_zip(
                form.template_name.clone(),
                form.template_file_name.clone(),
                std::mem::take(&mut form.template_file_bytes),
            )
            .await?;
        form.template_id = Some(id.to_string());
    }
    if form.landing_mode != "template" && !form.asset_file_bytes.is_empty() {
        let id = state
            .assets
            .upload(
                form.asset_file_name.clone(),
                std::mem::take(&mut form.asset_file_bytes),
            )
            .await?;
        form.image_asset_id = Some(id.to_string());
    }
    Ok(())
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
        Ok(_) => admin_config_redirect(&state, "/admin/cloak"),
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
    let policies = state
        .resources
        .list_cloak_policies()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(CloakPolicyView::from)
        .collect();
    let blacklist = state.cloak.list_blacklist().await.unwrap_or_default();
    render(CloakTemplate {
        active: "cloak",
        csrf_token: csrf_token(cookies),
        policies,
        blacklist,
        assets: state.assets.list().await.unwrap_or_default(),
        error,
    })
}

async fn parse_cloak_policy_multipart(
    mut multipart: Multipart,
) -> anyhow::Result<CloakPolicyMultipart> {
    let mut form = CloakPolicyMultipart {
        csrf_token: String::new(),
        name: String::new(),
        enabled: false,
        threshold: 8,
        token_hours: 6,
        decoy_title: "下载".to_string(),
        decoy_image_asset_id: None,
        decoy_apk_url: String::new(),
        use_ip_blacklist: false,
        use_header_rules: false,
        require_sec_fetch_mode: false,
        use_js_probe: false,
        use_asn: false,
        use_ptr: false,
        block_datacenter_asn: false,
        block_datacenter_ptr: false,
        block_verified_bot_ptr: false,
        ptr_timeout_ms: 800,
        ptr_cache_hours: 6,
        asset_file_name: String::new(),
        asset_file_bytes: Vec::new(),
    };
    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            CSRF_FIELD => form.csrf_token = field.text().await.unwrap_or_default(),
            "name" => form.name = field.text().await.unwrap_or_default(),
            "enabled" => form.enabled = true,
            "threshold" => {
                form.threshold = field.text().await.unwrap_or_default().parse().unwrap_or(8);
            }
            "token_hours" => {
                form.token_hours = field.text().await.unwrap_or_default().parse().unwrap_or(6);
            }
            "decoy_title" => form.decoy_title = field.text().await.unwrap_or_default(),
            "decoy_image_asset_id" => {
                form.decoy_image_asset_id = Some(field.text().await.unwrap_or_default());
            }
            "decoy_apk_url" => form.decoy_apk_url = field.text().await.unwrap_or_default(),
            "use_ip_blacklist" => form.use_ip_blacklist = true,
            "use_header_rules" => form.use_header_rules = true,
            "require_sec_fetch_mode" => form.require_sec_fetch_mode = true,
            "use_js_probe" => form.use_js_probe = true,
            "use_asn" => form.use_asn = true,
            "use_ptr" => form.use_ptr = true,
            "block_datacenter_asn" => form.block_datacenter_asn = true,
            "block_datacenter_ptr" => form.block_datacenter_ptr = true,
            "block_verified_bot_ptr" => form.block_verified_bot_ptr = true,
            "ptr_timeout_ms" => {
                form.ptr_timeout_ms = field
                    .text()
                    .await
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or(800);
            }
            "ptr_cache_hours" => {
                form.ptr_cache_hours = field.text().await.unwrap_or_default().parse().unwrap_or(6);
            }
            "asset_file" => {
                form.asset_file_name = field.file_name().unwrap_or("image").to_string();
                form.asset_file_bytes = field
                    .bytes()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
    Ok(form)
}

async fn apply_cloak_uploads(
    state: &AppState,
    form: &mut CloakPolicyMultipart,
) -> anyhow::Result<()> {
    if !form.asset_file_bytes.is_empty() {
        let id = state
            .assets
            .upload(
                form.asset_file_name.clone(),
                std::mem::take(&mut form.asset_file_bytes),
            )
            .await?;
        form.decoy_image_asset_id = Some(id.to_string());
    }
    Ok(())
}

async fn admin_meta(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(query): Query<MetaQuery>,
) -> Response {
    if !is_admin(&state, &cookies).await {
        return Redirect::to("/admin/login").into_response();
    }
    let active_profile_id = query.active_profile_id();
    render_meta(
        &state,
        &cookies,
        active_profile_id,
        query.into_filter(),
        None,
        None,
    )
    .await
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
            return render_meta_default(&state, &cookies, None, Some(err.to_string())).await;
        }
    };
    match state.meta.save_route_config(input).await {
        Ok(_) => admin_config_redirect(&state, "/admin/meta"),
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
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
        Ok(_) => Redirect::to(meta_return_url(form.return_to.as_deref())).into_response(),
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
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
        Ok(_) => Redirect::to(meta_return_url(form.return_to.as_deref())).into_response(),
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
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
    let return_to = form.return_to.clone();
    let active_profile_id = parse_optional_uuid(
        return_to
            .as_deref()
            .and_then(|url| url.split_once("profile="))
            .map(|(_, rest)| rest.split('&').next().unwrap_or(rest)),
    );
    match state
        .meta
        .archive_finished(older_than_days, active_profile_id)
        .await
    {
        Ok(count) => {
            render_meta(
                &state,
                &cookies,
                active_profile_id,
                MetaEventFilter::default(),
                Some(format!("Meta 事件归档完成：归档 {count} 条已完成事件。")),
                None,
            )
            .await
        }
        Err(err) => render_meta_default(&state, &cookies, None, Some(err.to_string())).await,
    }
}

async fn render_meta(
    state: &AppState,
    cookies: &Cookies,
    active_profile_id: Option<Uuid>,
    filter: MetaEventFilter,
    message: Option<String>,
    error: Option<String>,
) -> Response {
    let event_query_base = active_profile_id
        .map(|profile_id| {
            meta_event_query_base(
                profile_id,
                filter.page_size,
                &filter.status,
                &filter.event_name,
                &filter.route,
                filter.include_archived,
            )
        })
        .unwrap_or_default();
    let profile_events = match active_profile_id {
        Some(profile_id) => state
            .meta
            .profile_events(profile_id, filter.clone())
            .await
            .ok(),
        None => None,
    };
    render(MetaTemplate {
        active: "meta",
        csrf_token: csrf_token(cookies),
        profiles: state
            .resources
            .list_meta_profiles()
            .await
            .unwrap_or_default(),
        active_profile_id: active_profile_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        profile_events,
        include_archived: filter.include_archived,
        status_filter: filter.status,
        event_filter: filter.event_name,
        route_filter: filter.route,
        event_query_base,
        message,
        error,
    })
}

async fn render_meta_default(
    state: &AppState,
    cookies: &Cookies,
    message: Option<String>,
    error: Option<String>,
) -> Response {
    render_meta(
        state,
        cookies,
        None,
        MetaEventFilter::default(),
        message,
        error,
    )
    .await
}

impl MetaQuery {
    fn active_profile_id(&self) -> Option<Uuid> {
        parse_optional_uuid(self.profile.as_deref())
    }

    fn into_filter(self) -> MetaEventFilter {
        MetaEventFilter {
            include_archived: self.archived.is_some(),
            status: self.status.unwrap_or_default(),
            event_name: self.event.unwrap_or_default(),
            route: self.route.unwrap_or_default(),
            page: self.page.unwrap_or(1),
            page_size: self.size.unwrap_or(50),
        }
    }
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

fn found_redirect(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

fn admin_config_redirect(state: &AppState, location: &str) -> Response {
    state.clear_public_config_cache();
    Redirect::to(location).into_response()
}

fn is_base_domain(host: &str, base_domain: &str) -> bool {
    let host = normalize_host(host);
    let base_domain = normalize_host(base_domain);
    !host.is_empty() && host == base_domain
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

async fn public_entry(
    State(state): State<AppState>,
    Query(query): Query<PublicQuery>,
    cookies: Cookies,
    headers: HeaderMap,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if is_base_domain(host, &state.settings.base_domain) {
        return found_redirect("/admin");
    }

    match state.find_public_route_cached(host).await {
        Ok(Some(route)) if route.match_kind == "entry" => {
            let promo = query.c.clone().unwrap_or_default();
            let promo_hit = state
                .find_enabled_promo_cached(route.id, &promo)
                .await
                .ok()
                .flatten();
            let promo_code = promo_hit
                .as_ref()
                .map(|hit| hit.code.clone())
                .unwrap_or_default();
            let exit_label = if route.target_type == "external" {
                route.external_url.clone()
            } else {
                route.exit_domain.clone().unwrap_or_default()
            };
            let (ip, _) = client_ip(&headers);
            let cloak_config = state.cloak.runtime_config(route.id).await.ok().flatten();
            let cloak_enabled = cloak_config
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            let client_key = client_token_key(&headers, ip.as_deref());
            let visit_key = visit_cache_key(route.id, &client_key);
            let human_scope = human_scope(route.id);
            let human = cookies
                .get(HUMAN_COOKIE)
                .map(|cookie| {
                    verify_scoped_token(
                        &state,
                        HUMAN_TOKEN_SALT,
                        cookie.value(),
                        &client_key,
                        &human_scope,
                    )
                })
                .unwrap_or(false);
            let probed_failed = cookies
                .get(PROBED_COOKIE)
                .map(|cookie| cookie.value() == "0")
                .unwrap_or(false);

            if cloak_enabled && !human {
                let mut input = cloak_check_input(&headers, route.id, ip.as_deref());
                input.include_ptr = !cloak_config
                    .as_ref()
                    .map(|cfg| cfg.use_js_probe)
                    .unwrap_or(true);
                let verdict = state.cloak.classify_server(&input).await.unwrap_or_else(|err| {
                    tracing::warn!(error = %err, route_id = %route.id, "failed to classify cloak server request");
                    ab_services::CloakServerVerdict {
                        bot: true,
                        reason: "分流判断失败".to_string(),
                        header_score: 0,
                    }
                });
                if probed_failed || verdict.bot {
                    let reason = if probed_failed {
                        "JS 探针未通过".to_string()
                    } else {
                        verdict.reason
                    };
                    let mut visit_id = None;
                    if probed_failed {
                        if let Some(id) = state.security.public_visit(&visit_key) {
                            match state
                                .visits
                                .complete_probe_visit(
                                    id,
                                    "fake",
                                    &reason,
                                    promo_hit.as_ref().map(|hit| hit.id),
                                    &promo_code,
                                )
                                .await
                            {
                                Ok(true) => visit_id = Some(id),
                                Ok(false) => {}
                                Err(err) => {
                                    tracing::warn!(error = %err, visit_id = %id, "failed to complete failed probe visit");
                                }
                            }
                        }
                    }
                    if visit_id.is_none() {
                        match state
                            .visits
                            .record(
                                build_visit_input(
                                    &state,
                                    &headers,
                                    route.id,
                                    promo_hit.as_ref().map(|hit| hit.id),
                                    promo_code.clone(),
                                    "fake",
                                    &reason,
                                    route.entry_domain.clone(),
                                    exit_label.clone(),
                                )
                                .await,
                            )
                            .await
                        {
                            Ok(id) => visit_id = Some(id),
                            Err(err) => {
                                tracing::warn!(error = %err, route_id = %route.id, "failed to record fake visit");
                            }
                        }
                    }
                    if let Some(id) = visit_id {
                        state.security.remember_public_visit(
                            &visit_key,
                            id,
                            Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
                        );
                    }
                    return render_decoy_landing(
                        &state,
                        &headers,
                        &route,
                        promo_hit.map(|hit| hit.id),
                    )
                    .await;
                }

                if !cloak_config
                    .as_ref()
                    .map(|cfg| cfg.use_js_probe)
                    .unwrap_or(true)
                {
                    let visit_id = match state
                        .visits
                        .record(
                            build_visit_input(
                                &state,
                                &headers,
                                route.id,
                                promo_hit.as_ref().map(|hit| hit.id),
                                promo_code.clone(),
                                "real",
                                "服务端规则通过",
                                route.entry_domain.clone(),
                                exit_label.clone(),
                            )
                            .await,
                        )
                        .await
                    {
                        Ok(id) => Some(id),
                        Err(err) => {
                            tracing::warn!(error = %err, route_id = %route.id, "failed to record server-only real visit");
                            None
                        }
                    };
                    if let Some(id) = visit_id {
                        state.security.remember_public_visit(
                            &visit_key,
                            id,
                            Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
                        );
                        let meta_query = PublicQuery {
                            c: query.c.clone(),
                            v: Some(id),
                            ht: None,
                            fbclid: query.fbclid.clone(),
                        };
                        send_meta_page_events(
                            &state,
                            route.id,
                            id,
                            host,
                            &meta_query,
                            &headers,
                            ip,
                        );
                    }
                    if route.target_type == "external" {
                        match append_public_query(&route.external_url, &query, visit_id) {
                            Ok(url) => return found_redirect(&url),
                            Err(err) => {
                                tracing::error!(error = %err, route_id = %route.id, "failed to build external redirect");
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            }
                        }
                    }
                    if let Some(exit_domain) = route.exit_domain.clone() {
                        let mut url = format!("https://{exit_domain}/");
                        append_query_pairs(&mut url, &query, visit_id);
                        append_ht_pair(&mut url, &state, route.id, &exit_domain, &client_key);
                        return found_redirect(&url);
                    }
                    return render_with_status(
                        StatusCode::NOT_FOUND,
                        NotConfiguredTemplate { host },
                    );
                }

                match state.security.public_visit(&visit_key) {
                    Some(_) => {}
                    None => match state
                        .visits
                        .record(
                            build_visit_input(
                                &state,
                                &headers,
                                route.id,
                                promo_hit.as_ref().map(|hit| hit.id),
                                promo_code.clone(),
                                "probe",
                                "需 JS 探针确认",
                                route.entry_domain.clone(),
                                exit_label.clone(),
                            )
                            .await,
                        )
                        .await
                    {
                        Ok(id) => state.security.remember_public_visit(
                            &visit_key,
                            id,
                            Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
                        ),
                        Err(err) => {
                            tracing::warn!(error = %err, route_id = %route.id, "failed to record probe visit");
                        }
                    },
                }

                return render_probe_page(route.id, &promo, query.fbclid.as_deref().unwrap_or(""));
            }

            let visit_id = match state
                .visits
                .record(
                    build_visit_input(
                        &state,
                        &headers,
                        route.id,
                        promo_hit.as_ref().map(|hit| hit.id),
                        promo_code.clone(),
                        "real",
                        if cloak_enabled {
                            "真人令牌通过"
                        } else {
                            "分流关闭"
                        },
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
                state.security.remember_public_visit(
                    &visit_key,
                    id,
                    Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
                );
            }
            if let Some(id) = visit_id {
                let meta_query = PublicQuery {
                    c: query.c.clone(),
                    v: Some(id),
                    ht: None,
                    fbclid: query.fbclid.clone(),
                };
                send_meta_page_events(&state, route.id, id, host, &meta_query, &headers, ip);
            }
            if route.target_type == "external" {
                match append_public_query(&route.external_url, &query, visit_id) {
                    Ok(url) => found_redirect(&url),
                    Err(err) => {
                        tracing::error!(error = %err, route_id = %route.id, "failed to build external redirect");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            } else if let Some(exit_domain) = route.exit_domain {
                let mut url = format!("https://{exit_domain}/");
                append_query_pairs(&mut url, &query, visit_id);
                if cloak_enabled {
                    append_ht_pair(&mut url, &state, route.id, &exit_domain, &client_key);
                }
                found_redirect(&url)
            } else {
                render_with_status(StatusCode::NOT_FOUND, NotConfiguredTemplate { host })
            }
        }
        Ok(Some(route)) => {
            let (ip, _) = client_ip(&headers);
            let cloak_config = state.cloak.runtime_config(route.id).await.ok().flatten();
            let cloak_enabled = cloak_config
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            if cloak_enabled {
                let client_key = client_token_key(&headers, ip.as_deref());
                let exit_domain = route.exit_domain.as_deref().unwrap_or("");
                let token = query.ht.as_deref().unwrap_or("");
                if !verify_scoped_token(
                    &state,
                    EXIT_TOKEN_SALT,
                    token,
                    &client_key,
                    &exit_scope(route.id, exit_domain),
                ) {
                    let promo = query.c.clone().unwrap_or_default();
                    let promo_hit = state
                        .find_enabled_promo_cached(route.id, &promo)
                        .await
                        .ok()
                        .flatten();
                    let promo_code = promo_hit
                        .as_ref()
                        .map(|hit| hit.code.clone())
                        .unwrap_or_default();
                    let client_key = client_token_key(&headers, ip.as_deref());
                    match state
                        .visits
                        .record(
                            build_visit_input(
                                &state,
                                &headers,
                                route.id,
                                promo_hit.as_ref().map(|hit| hit.id),
                                promo_code,
                                "fake",
                                "出口缺少真实访问令牌",
                                route.entry_domain.clone(),
                                exit_domain.to_string(),
                            )
                            .await,
                        )
                        .await
                    {
                        Ok(id) => state.security.remember_public_visit(
                            &visit_cache_key(route.id, &client_key),
                            id,
                            Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
                        ),
                        Err(err) => {
                            tracing::warn!(error = %err, route_id = %route.id, "failed to record exit fake visit");
                        }
                    }
                    return render_decoy_landing(
                        &state,
                        &headers,
                        &route,
                        promo_hit.map(|hit| hit.id),
                    )
                    .await;
                }
            }
            let promo = query.c.clone().unwrap_or_default();
            let promo_hit = state
                .find_enabled_promo_cached(route.id, &promo)
                .await
                .ok()
                .flatten();
            let promo_code = promo_hit
                .as_ref()
                .map(|hit| hit.code.clone())
                .unwrap_or_default();
            let promo_id = promo_hit.as_ref().map(|hit| hit.id);
            let visit_id = resolve_exit_visit(
                &state,
                &headers,
                &route,
                &query,
                promo_id,
                promo_code,
                cloak_enabled,
            )
            .await;
            let effective_query = PublicQuery {
                c: query.c.clone(),
                v: visit_id,
                ht: None,
                fbclid: query.fbclid.clone(),
            };
            let meta_json = browser_meta_json(&state, route.id).await;
            if route.landing_mode == "template" {
                if let (Some(template_id), Some(entry_file)) =
                    (route.template_id, route.template_entry_file.as_deref())
                {
                    let template_url = append_template_query(
                        &format!("/landing-templates/{template_id}/{entry_file}"),
                        &effective_query,
                    );
                    return render(TemplateFrameTemplate {
                        route_id: route.id,
                        promo_id,
                        visit_id,
                        event_token_json: public_event_token_json(&state, route.id, visit_id),
                        template_url,
                        apk_url_json: serde_json::to_string(&route.apk_url)
                            .unwrap_or_else(|_| "\"\"".to_string()),
                        meta_json: meta_json.clone(),
                        auto_download: route.auto_download,
                    });
                }
            }
            render(DefaultLandingTemplate {
                route_id: route.id,
                promo_id,
                visit_id,
                event_token_json: public_event_token_json(&state, route.id, visit_id),
                title: &route.title,
                image_url: route
                    .image_asset_id
                    .map(|id| format!("/uploads/{id}"))
                    .unwrap_or_default(),
                apk_url_json: serde_json::to_string(&route.apk_url)
                    .unwrap_or_else(|_| "\"\"".to_string()),
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

async fn cloak_verify(
    State(state): State<AppState>,
    Query(query): Query<CloakVerifyQuery>,
    cookies: Cookies,
    headers: HeaderMap,
    Json(payload): Json<ProbePayload>,
) -> Json<CloakVerifyResponse> {
    let Some(route_id) = query.route else {
        return Json(CloakVerifyResponse {
            human: false,
            next: "fake".to_string(),
            reason: "线路不存在".to_string(),
            score: 0,
            header_score: 0,
            probe_score: 0,
            server_reason: "线路不存在".to_string(),
            target: String::new(),
            threshold: 8,
        });
    };

    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let route = match state.find_public_route_cached(host).await {
        Ok(Some(route)) if route.id == route_id && route.match_kind == "entry" => route,
        _ => {
            return Json(CloakVerifyResponse {
                human: false,
                next: "fake".to_string(),
                reason: "线路不存在".to_string(),
                score: 0,
                header_score: 0,
                probe_score: 0,
                server_reason: "线路不存在".to_string(),
                target: String::new(),
                threshold: 8,
            })
        }
    };

    let config = match state.cloak.runtime_config(route.id).await {
        Ok(Some(config)) => config,
        _ => {
            return Json(CloakVerifyResponse {
                human: true,
                next: "real".to_string(),
                reason: "分流关闭".to_string(),
                score: 0,
                header_score: 0,
                probe_score: 0,
                server_reason: "分流关闭".to_string(),
                target: String::new(),
                threshold: 8,
            })
        }
    };
    if !config.enabled {
        return Json(CloakVerifyResponse {
            human: true,
            next: "real".to_string(),
            reason: "分流关闭".to_string(),
            score: 0,
            header_score: 0,
            probe_score: 0,
            server_reason: "分流关闭".to_string(),
            target: String::new(),
            threshold: config.threshold,
        });
    }

    let (ip, _) = client_ip(&headers);
    let mut input = cloak_check_input(&headers, route.id, ip.as_deref());
    input.include_ptr = true;
    let server = state.cloak.classify_server(&input).await.unwrap_or_else(|err| {
        tracing::warn!(error = %err, route_id = %route.id, "failed to classify cloak verify request");
        ab_services::CloakServerVerdict {
            bot: true,
            reason: "分流判断失败".to_string(),
            header_score: 0,
        }
    });
    let probe = score_probe(
        &payload,
        &header_value(&headers, "accept-language"),
        &header_value(&headers, "user-agent"),
    );
    let total_score = server.header_score + probe.score;
    let human = !server.bot && !probe.hard_bot && total_score >= config.threshold.max(1);
    let reason = if server.bot {
        server.reason.clone()
    } else if probe.hard_bot {
        probe.reason.clone()
    } else if human {
        "探针通过".to_string()
    } else if probe.reason.is_empty() {
        format!("探针分不足: {total_score}/{}", config.threshold.max(1))
    } else {
        format!(
            "探针分不足: {total_score}/{}; {}",
            config.threshold.max(1),
            probe.reason
        )
    };

    let client_key = client_token_key(&headers, ip.as_deref());
    let visit_key = visit_cache_key(route.id, &client_key);
    let mut target = String::new();
    if human {
        let promo = query.c.clone().unwrap_or_default();
        let promo_hit = state
            .find_enabled_promo_cached(route.id, &promo)
            .await
            .ok()
            .flatten();
        let effective_promo = promo_hit
            .as_ref()
            .map(|hit| hit.code.clone())
            .unwrap_or_default();
        let exit_label = if route.target_type == "external" {
            route.external_url.clone()
        } else {
            route.exit_domain.clone().unwrap_or_default()
        };
        let cached_visit_id = state.security.public_visit(&visit_key);
        let mut visit_id = None;
        if let Some(id) = cached_visit_id {
            match state
                .visits
                .complete_probe_visit(
                    id,
                    "real",
                    "探针通过",
                    promo_hit.as_ref().map(|hit| hit.id),
                    &effective_promo,
                )
                .await
            {
                Ok(true) => visit_id = Some(id),
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!(error = %err, visit_id = %id, "failed to complete real probe visit");
                }
            }
        }
        if visit_id.is_none() {
            visit_id = state
                .visits
                .record(
                    build_visit_input(
                        &state,
                        &headers,
                        route.id,
                        promo_hit.as_ref().map(|hit| hit.id),
                        effective_promo,
                        "real",
                        "探针通过",
                        route.entry_domain.clone(),
                        exit_label,
                    )
                    .await,
                )
                .await
                .ok();
        }
        if let Some(id) = visit_id {
            state.security.remember_public_visit(
                &visit_key,
                id,
                Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
            );
            let meta_query = PublicQuery {
                c: query.c.clone(),
                v: Some(id),
                ht: None,
                fbclid: query.fbclid.clone(),
            };
            send_meta_page_events(&state, route.id, id, host, &meta_query, &headers, ip);
        }
        target = real_target_url(
            &state,
            &route,
            &PublicQuery {
                c: query.c.clone(),
                v: visit_id,
                ht: None,
                fbclid: query.fbclid.clone(),
            },
            &client_key,
        )
        .unwrap_or_default();
        cookies.add(scoped_token_cookie(
            HUMAN_COOKIE,
            scoped_token(
                &state,
                HUMAN_TOKEN_SALT,
                &client_key,
                &human_scope(route.id),
                i64::from(config.token_hours.max(1)) * 3600,
            ),
            i64::from(config.token_hours.max(1)) * 3600,
            request_is_https(&headers),
        ));
    } else {
        let promo = query.c.clone().unwrap_or_default();
        let promo_hit = state
            .find_enabled_promo_cached(route.id, &promo)
            .await
            .ok()
            .flatten();
        let effective_promo = promo_hit
            .as_ref()
            .map(|hit| hit.code.clone())
            .unwrap_or_default();
        if let Some(id) = state.security.public_visit(&visit_key) {
            if let Err(err) = state
                .visits
                .complete_probe_visit(
                    id,
                    "fake",
                    &reason,
                    promo_hit.as_ref().map(|hit| hit.id),
                    &effective_promo,
                )
                .await
            {
                tracing::warn!(error = %err, visit_id = %id, "failed to complete fake probe visit");
            }
            state.security.remember_public_visit(
                &visit_key,
                id,
                Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
            );
        }
        cookies.add(scoped_token_cookie(
            PROBED_COOKIE,
            "0".to_string(),
            600,
            request_is_https(&headers),
        ));
    }

    Json(CloakVerifyResponse {
        human,
        next: if human { "real" } else { "fake" }.to_string(),
        reason,
        score: total_score,
        header_score: server.header_score,
        probe_score: probe.score,
        server_reason: server.reason,
        target,
        threshold: config.threshold.max(1),
    })
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

fn cloak_check_input<'a>(
    headers: &'a HeaderMap,
    route_id: Uuid,
    ip: Option<&'a str>,
) -> CloakCheckInput<'a> {
    CloakCheckInput {
        route_id,
        ip,
        user_agent: header_str(headers, "user-agent"),
        accept_language: header_str(headers, "accept-language"),
        sec_ch_ua: header_str(headers, "sec-ch-ua"),
        sec_fetch_site: header_str(headers, "sec-fetch-site"),
        sec_fetch_mode: header_str(headers, "sec-fetch-mode"),
        sec_fetch_dest: header_str(headers, "sec-fetch-dest"),
        sec_fetch_user: header_str(headers, "sec-fetch-user"),
        upgrade_insecure_requests: header_str(headers, "upgrade-insecure-requests"),
        accept: header_str(headers, "accept"),
        accept_encoding: header_str(headers, "accept-encoding"),
        include_ptr: false,
    }
}

fn header_str<'a>(headers: &'a HeaderMap, key: &str) -> &'a str {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
}

async fn render_decoy_landing(
    state: &AppState,
    headers: &HeaderMap,
    route: &ab_services::PublicRoute,
    promo_id: Option<Uuid>,
) -> Response {
    let (title, image_asset_id, apk_url) = state
        .cloak
        .decoy_for_route(route.id)
        .await
        .unwrap_or_else(|_| ("下载".to_string(), None, String::new()));
    let visit_id = {
        let (ip, _) = client_ip(headers);
        let client_key = client_token_key(headers, ip.as_deref());
        state
            .security
            .public_visit(&visit_cache_key(route.id, &client_key))
    };
    render(DefaultLandingTemplate {
        route_id: route.id,
        promo_id,
        visit_id,
        event_token_json: public_event_token_json(state, route.id, visit_id),
        title: &title,
        image_url: image_asset_id
            .map(|id| format!("/uploads/{id}"))
            .unwrap_or_default(),
        apk_url_json: serde_json::to_string(&apk_url).unwrap_or_else(|_| "\"\"".to_string()),
        meta_json: "null".to_string(),
        auto_download: false,
    })
}

async fn resolve_exit_visit(
    state: &AppState,
    headers: &HeaderMap,
    route: &ab_services::PublicRoute,
    query: &PublicQuery,
    promo_id: Option<Uuid>,
    promo_code: String,
    cloak_enabled: bool,
) -> Option<Uuid> {
    if let Some(id) = query.v {
        match state.visits.belongs_to_route(id, route.id).await {
            Ok(true) => return Some(id),
            Ok(false) => {
                tracing::warn!(visit_id = %id, route_id = %route.id, "ignored visit id from another route");
            }
            Err(err) => {
                tracing::warn!(error = %err, visit_id = %id, route_id = %route.id, "failed to verify visit id route");
            }
        }
    }

    let (ip, _) = client_ip(headers);
    let client_key = client_token_key(headers, ip.as_deref());
    if let Some(id) = state
        .security
        .public_visit(&visit_cache_key(route.id, &client_key))
    {
        match state.visits.belongs_to_route(id, route.id).await {
            Ok(true) => return Some(id),
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(error = %err, visit_id = %id, route_id = %route.id, "failed to verify cached visit id route");
            }
        }
    }

    let exit_label = if route.target_type == "external" {
        route.external_url.clone()
    } else {
        route.exit_domain.clone().unwrap_or_default()
    };
    let reason = if cloak_enabled {
        "出口令牌通过"
    } else {
        "出口直接访问"
    };
    let visit_id = match state
        .visits
        .record(
            build_visit_input(
                state,
                headers,
                route.id,
                promo_id,
                promo_code,
                "real",
                reason,
                route.entry_domain.clone(),
                exit_label,
            )
            .await,
        )
        .await
    {
        Ok(id) => id,
        Err(err) => {
            tracing::warn!(error = %err, route_id = %route.id, "failed to record exit visit");
            return None;
        }
    };

    state.security.remember_public_visit(
        &visit_cache_key(route.id, &client_key),
        visit_id,
        Duration::from_secs(PUBLIC_EVENT_TOKEN_TTL_SECONDS as u64),
    );

    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let meta_query = PublicQuery {
        c: query.c.clone(),
        v: Some(visit_id),
        ht: None,
        fbclid: query.fbclid.clone(),
    };
    send_meta_page_events(state, route.id, visit_id, host, &meta_query, headers, ip);
    Some(visit_id)
}

fn render_probe_page(route_id: Uuid, promo: &str, fbclid: &str) -> Response {
    let verify_url = format!(
        "/api/cloak/verify?route={route_id}{}{}",
        query_pair("c", promo),
        query_pair("fbclid", fbclid)
    );
    let script = format!(
        r#"
(async function(){{
  function webglValue(kind){{
    try{{
      var c=document.createElement('canvas');
      var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
      if(!gl)return'';
      var e=gl.getExtension('WEBGL_debug_renderer_info');
      if(!e)return'';
      return String(gl.getParameter(kind==='vendor'?e.UNMASKED_VENDOR_WEBGL:e.UNMASKED_RENDERER_WEBGL));
    }}catch(_){{return'';}}
  }}
  var notifQ='';
  try{{if(navigator.permissions&&navigator.permissions.query){{var st=await navigator.permissions.query({{name:'notifications'}});notifQ=st.state;}}}}catch(_){{}}
  var nav=navigator;
  var uaPlatform='';
  try{{uaPlatform=(nav.userAgentData&&nav.userAgentData.platform)||'';}}catch(_){{}}
  var p={{
    js:true,
    webdriver:nav.webdriver===true,
    automation:!!(window._phantom||window.__nightmare||window.callPhantom||
      Object.keys(window.document||{{}}).some(function(k){{return k.indexOf('cdc_')===0;}})||
      Object.keys(window).some(function(k){{return k.indexOf('cdc_')===0;}})),
    hasChrome:!!window.chrome,
    webglVendor:webglValue('vendor'),
    webglRenderer:webglValue('renderer'),
    plugins:(nav.plugins&&nav.plugins.length)||0,
    hc:nav.hardwareConcurrency||0,
    dm:nav.deviceMemory||0,
    sw:screen.width||0,
    sh:screen.height||0,
    dpr:window.devicePixelRatio||1,
    tz:(Intl&&Intl.DateTimeFormat)?Intl.DateTimeFormat().resolvedOptions().timeZone:'',
    platform:nav.platform||'',
    uaPlatform:uaPlatform,
    langs:(nav.languages&&nav.languages[0])||nav.language||'',
    notif:(window.Notification&&Notification.permission)||'',
    notifQ:notifQ,
    touch:nav.maxTouchPoints||0
  }};
  try{{
    var r=await fetch('{verify_url}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(p)}});
    var d=await r.json().catch(function(){{return{{}};}});
    if(d.next==='real'&&d.target){{location.replace(d.target);return;}}
    if(d.next==='fake'){{location.reload();return;}}
    document.body.innerHTML='<div style="font-family:sans-serif;color:#666;display:flex;height:90vh;align-items:center;justify-content:center">Verification failed. Please refresh and try again.</div>';
  }}catch(_){{
    document.body.innerHTML='<div style="font-family:sans-serif;color:#666;display:flex;height:90vh;align-items:center;justify-content:center">Loading failed. Please refresh and try again.</div>';
  }}
}})();
"#
    );
    Html(format!(
        r#"<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Loading</title>
  </head>
  <body style="margin:0;font-family:sans-serif;color:#666;display:flex;min-height:90vh;align-items:center;justify-content:center">
    <div>Loading, please wait...</div>
    <script>{script}</script>
  </body>
</html>"#
    ))
    .into_response()
}

fn query_pair(key: &str, value: &str) -> String {
    if value.trim().is_empty() {
        return String::new();
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair(key, value);
    format!("&{}", serializer.finish())
}

fn real_target_url(
    state: &AppState,
    route: &ab_services::PublicRoute,
    query: &PublicQuery,
    client_key: &str,
) -> anyhow::Result<String> {
    if route.target_type == "external" {
        return append_public_query(&route.external_url, query, query.v);
    }
    let Some(exit_domain) = route
        .exit_domain
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        anyhow::bail!("出口域名未配置");
    };
    let mut url = format!("https://{exit_domain}/");
    append_query_pairs(&mut url, query, query.v);
    append_ht_pair(&mut url, state, route.id, exit_domain, client_key);
    Ok(url)
}

fn append_ht_pair(
    url: &mut String,
    state: &AppState,
    route_id: Uuid,
    exit_domain: &str,
    client_key: &str,
) {
    let separator = if url.contains('?') { '&' } else { '?' };
    let token = scoped_token(
        state,
        EXIT_TOKEN_SALT,
        client_key,
        &exit_scope(route_id, exit_domain),
        EXIT_TRANSFER_TOKEN_TTL_SECONDS,
    );
    url.push(separator);
    url.push_str("ht=");
    url.push_str(&url::form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>());
}

#[derive(Debug, Clone)]
struct ProbeScore {
    score: i32,
    hard_bot: bool,
    reason: String,
}

fn score_probe(payload: &ProbePayload, accept_lang: &str, user_agent: &str) -> ProbeScore {
    if payload.js == Some(false) {
        return hard_probe("JS 未执行");
    }
    if payload.webdriver.unwrap_or(false) {
        return hard_probe("webdriver 自动化特征");
    }
    if payload.automation.unwrap_or(false) {
        return hard_probe("自动化环境特征");
    }
    if payload.notif == "denied" && payload.notif_q == "prompt" {
        return hard_probe("通知权限特征异常");
    }

    let mut score = 0;
    if payload.has_chrome.unwrap_or(false) || payload.has_chrome_alias.unwrap_or(false) {
        score += 2;
    }
    if payload.plugins.unwrap_or(0) > 0 {
        score += 2;
    }
    let gl = format!(
        "{} {}",
        payload.webgl_vendor.to_ascii_lowercase(),
        payload.webgl_renderer.to_ascii_lowercase()
    );
    if !payload.webgl_vendor.trim().is_empty()
        && !gl.contains("swiftshader")
        && !gl.contains("llvmpipe")
        && !gl.contains("mesa offscreen")
    {
        score += 3;
    }
    if payload.hc.unwrap_or(0) >= 2 {
        score += 1;
    }
    if payload.sw.unwrap_or(0) >= 800 && payload.sh.unwrap_or(0) >= 600 {
        score += 1;
    }
    if !payload.tz.trim().is_empty() {
        score += 1;
    }
    if !payload.langs.trim().is_empty() && !accept_lang.trim().is_empty() {
        let js_lang = payload
            .langs
            .split('-')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if accept_lang.to_ascii_lowercase().contains(&js_lang) {
            score += 2;
        } else {
            score -= 1;
        }
    }
    let consistency = score_device_consistency(payload, user_agent);
    score += consistency.score;
    ProbeScore {
        score,
        hard_bot: false,
        reason: consistency.notes.join("; "),
    }
}

fn hard_probe(reason: &str) -> ProbeScore {
    ProbeScore {
        score: 0,
        hard_bot: true,
        reason: reason.to_string(),
    }
}

struct DeviceConsistency {
    score: i32,
    notes: Vec<String>,
}

fn score_device_consistency(payload: &ProbePayload, user_agent: &str) -> DeviceConsistency {
    let mut score = 0;
    let mut notes = Vec::new();
    let device = ua_device(user_agent);
    let platform = format!("{} {}", payload.platform, payload.ua_platform).to_ascii_lowercase();
    let gl = format!("{} {}", payload.webgl_vendor, payload.webgl_renderer).to_ascii_lowercase();
    let touch = payload.touch.unwrap_or(0);
    let dpr = payload
        .dpr
        .and_then(|value| value.to_string().parse::<f64>().ok())
        .unwrap_or(1.0);
    let ua_mobile = matches!(device, "ios" | "android" | "mobile");
    let mobile_shape = is_mobile_shape(payload);
    let desktop_shape = is_desktop_shape(payload);

    if ua_mobile && mobile_shape && touch > 0 {
        score += 2;
    }
    if !ua_mobile && desktop_shape {
        score += 1;
    }
    if ua_mobile && touch <= 0 {
        score -= 2;
        notes.push("移动 UA 无触控".to_string());
    }
    if ua_mobile && desktop_shape && !mobile_shape {
        score -= 2;
        notes.push("移动 UA 桌面屏幕".to_string());
    }
    if !ua_mobile && mobile_shape && touch > 0 && device != "mac" {
        score -= 1;
        notes.push("桌面 UA 手机屏幕".to_string());
    }
    if device == "ios" {
        if !platform.is_empty()
            && !platform.contains("iphone")
            && !platform.contains("ipad")
            && !platform.contains("mac")
        {
            score -= 1;
            notes.push("iOS UA 平台不匹配".to_string());
        }
        if touch > 0 && dpr >= 2.0 {
            score += 1;
        }
    }
    if device == "android" {
        if !platform.is_empty() && !platform.contains("android") && !platform.contains("linux") {
            score -= 1;
            notes.push("Android UA 平台不匹配".to_string());
        }
        if touch > 0 {
            score += 1;
        }
    }
    if device == "windows" && !platform.is_empty() && !platform.contains("win") {
        score -= 1;
        notes.push("Windows UA 平台不匹配".to_string());
    }
    if device == "mac" && !platform.is_empty() && !platform.contains("mac") {
        score -= 1;
        notes.push("Mac UA 平台不匹配".to_string());
    }
    if gl.contains("swiftshader") || gl.contains("llvmpipe") || gl.contains("mesa offscreen") {
        score -= 3;
        notes.push("软件渲染 WebGL".to_string());
    } else if !gl.trim().is_empty() {
        if device == "ios" && (gl.contains("apple") || gl.contains("metal")) {
            score += 1;
        } else if device == "android"
            && (gl.contains("adreno") || gl.contains("mali") || gl.contains("powervr"))
        {
            score += 1;
        } else if matches!(device, "windows" | "mac" | "linux") && desktop_shape {
            score += 1;
        }
    }
    DeviceConsistency { score, notes }
}

fn ua_device(user_agent: &str) -> &'static str {
    let ua = user_agent.to_ascii_lowercase();
    if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") {
        "ios"
    } else if ua.contains("android") {
        "android"
    } else if ua.contains("mobile") {
        "mobile"
    } else if ua.contains("windows") {
        "windows"
    } else if ua.contains("macintosh") || ua.contains("mac os x") {
        "mac"
    } else if ua.contains("linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn is_mobile_shape(payload: &ProbePayload) -> bool {
    let w = payload.sw.unwrap_or(0);
    let h = payload.sh.unwrap_or(0);
    let dpr = payload
        .dpr
        .and_then(|value| value.to_string().parse::<f64>().ok())
        .unwrap_or(1.0);
    let min_side = w.min(h);
    let max_side = w.max(h);
    min_side > 0 && min_side <= 540 && max_side <= 1200 && dpr >= 2.0
}

fn is_desktop_shape(payload: &ProbePayload) -> bool {
    let w = payload.sw.unwrap_or(0);
    let h = payload.sh.unwrap_or(0);
    w.max(h) >= 1100 && w.min(h) >= 600
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

fn send_meta_page_events(
    state: &AppState,
    route_id: Uuid,
    visit_id: Uuid,
    host: &str,
    query: &PublicQuery,
    headers: &HeaderMap,
    ip: Option<String>,
) {
    let event_source_url = request_url(host, query);
    let user_agent = header_value(headers, "user-agent");
    let fbc = fbc_from_query(query);
    send_meta_event(
        state,
        MetaEventInput {
            route_id,
            event_name: "PageView".to_string(),
            event_id: format!("pv_{visit_id}"),
            event_source_url: event_source_url.clone(),
            user_agent: user_agent.clone(),
            ip: ip.clone(),
            fbp: String::new(),
            fbc: fbc.clone(),
        },
    );
    send_meta_event(
        state,
        MetaEventInput {
            route_id,
            event_name: "ViewContent".to_string(),
            event_id: format!("vc_{visit_id}"),
            event_source_url,
            user_agent,
            ip,
            fbp: String::new(),
            fbc,
        },
    );
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
            || state.domain_allowed_cached(host).await.unwrap_or(false));
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
    if !state
        .visits
        .belongs_to_route(visit_id, route_id)
        .await
        .unwrap_or(false)
    {
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
    let Some(route_id) = payload.route_id else {
        return StatusCode::ACCEPTED;
    };
    let (ip, _) = client_ip(&headers);
    let client_key = client_token_key(&headers, ip.as_deref());
    let visit_id = payload.visit_id.or_else(|| {
        state
            .security
            .public_visit(&visit_cache_key(route_id, &client_key))
    });
    let Some(visit_id) = visit_id else {
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
    if !state
        .visits
        .belongs_to_route(visit_id, route_id)
        .await
        .unwrap_or(false)
    {
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

fn client_token_key(headers: &HeaderMap, ip: Option<&str>) -> String {
    let ip = ip.unwrap_or("").trim();
    let user_agent = header_value(headers, "user-agent");
    let lang = header_value(headers, "accept-language")
        .split(',')
        .next()
        .unwrap_or("")
        .to_string();
    let mut hasher = Sha256::new();
    hasher.update(ip_bucket(ip).as_bytes());
    hasher.update(b"|");
    hasher.update(user_agent.as_bytes());
    hasher.update(b"|");
    hasher.update(lang.as_bytes());
    hex_encode(&hasher.finalize())
}

fn ip_bucket(ip: &str) -> String {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                return format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
            }
            std::net::IpAddr::V6(v6) => {
                let segments = v6.segments();
                return format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                );
            }
        }
    }
    ip.to_string()
}

fn human_scope(route_id: Uuid) -> String {
    format!("route:{route_id}")
}

fn exit_scope(route_id: Uuid, exit_domain: &str) -> String {
    format!("route:{route_id}:exit:{exit_domain}")
}

fn scoped_token(
    state: &AppState,
    salt: &str,
    client_key: &str,
    scope: &str,
    ttl_seconds: i64,
) -> String {
    let expires_at = unix_timestamp() + ttl_seconds.max(1);
    let scope_encoded = hex_encode(scope.as_bytes());
    let payload = format!("{client_key}.{scope_encoded}.{expires_at}");
    let signature = scoped_token_signature(state, salt, &payload);
    format!("{payload}.{signature}")
}

fn verify_scoped_token(
    state: &AppState,
    salt: &str,
    token: &str,
    client_key: &str,
    scope: &str,
) -> bool {
    let mut parts = token.rsplitn(2, '.');
    let Some(signature) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let mut payload_parts = payload.splitn(3, '.');
    let (Some(token_client), Some(token_scope), Some(expires)) = (
        payload_parts.next(),
        payload_parts.next(),
        payload_parts.next(),
    ) else {
        return false;
    };
    if token_client != client_key || token_scope != hex_encode(scope.as_bytes()) {
        return false;
    }
    let Ok(expires_at) = expires.parse::<i64>() else {
        return false;
    };
    if expires_at < unix_timestamp() {
        return false;
    }
    let expected = scoped_token_signature(state, salt, payload);
    constant_time_eq(signature.as_bytes(), expected.as_bytes())
}

fn scoped_token_signature(state: &AppState, salt: &str, payload: &str) -> String {
    let secret = if state.settings.meta_token_key.is_empty() {
        state.settings.admin_password.as_bytes()
    } else {
        state.settings.meta_token_key.as_bytes()
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let signature = hmac::sign(&key, format!("{salt}:{payload}").as_bytes());
    hex_encode(signature.as_ref())
}

fn scoped_token_cookie(
    name: &'static str,
    value: String,
    max_age_seconds: i64,
    secure: bool,
) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_same_site(SameSite::Strict);
    cookie.set_max_age(CookieDuration::seconds(max_age_seconds.max(1)));
    cookie.set_secure(secure);
    cookie
}

fn visit_cache_key(route_id: Uuid, client_key: &str) -> String {
    format!("{route_id}:{client_key}")
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
