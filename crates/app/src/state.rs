use ab_db::DbPool;
use ab_services::{
    AssetsService, AuthService, CloakService, GeoIpService, HealthService, MetaService, PromoHit,
    PromosService, PublicRoute, ResourcesService, RoutesService, StatsService, TemplatesService,
    VisitsService,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

use crate::settings::Settings;

const LOGIN_FAILURE_LIMIT: u32 = 5;
const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
const LOGIN_LOCKOUT: Duration = Duration::from_secs(15 * 60);
const PUBLIC_ROUTE_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const PUBLIC_NOT_FOUND_CACHE_TTL: Duration = Duration::from_secs(60);
const PUBLIC_CONFIG_CACHE_MAX_ITEMS: usize = 10_000;

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub public_cache: PublicRuntimeCache,
    pub security: SecurityState,
    pub assets: AssetsService,
    pub auth: AuthService,
    pub health: HealthService,
    pub cloak: CloakService,
    pub geo: GeoIpService,
    pub meta: MetaService,
    pub promos: PromosService,
    pub resources: ResourcesService,
    pub routes: RoutesService,
    pub stats: StatsService,
    pub templates: TemplatesService,
    pub visits: VisitsService,
}

impl AppState {
    pub fn new(settings: Settings, pool: DbPool) -> Self {
        tracing::debug!(data_dir = %settings.data_dir, "using data directory");
        Self {
            assets: AssetsService::new(pool.clone(), settings.data_dir.clone()),
            auth: AuthService::new(pool.clone()),
            health: HealthService::new(pool.clone()),
            cloak: CloakService::new(pool.clone(), settings.data_dir.clone()),
            geo: GeoIpService::new(pool.clone(), settings.data_dir.clone()),
            meta: MetaService::new(pool.clone(), settings.meta_token_key.clone()),
            promos: PromosService::new(pool.clone()),
            public_cache: PublicRuntimeCache::new(),
            resources: ResourcesService::new(pool.clone(), settings.meta_token_key.clone()),
            routes: RoutesService::new(pool.clone()),
            security: SecurityState::new(),
            stats: StatsService::new(pool.clone()),
            templates: TemplatesService::new(pool.clone(), settings.data_dir.clone()),
            visits: VisitsService::new(pool.clone()),
            settings,
        }
    }

    pub async fn find_public_route_cached(
        &self,
        host: &str,
    ) -> anyhow::Result<Option<PublicRoute>> {
        if let Some(route) = self.public_cache.public_route(host) {
            return Ok(route);
        }

        let route = self.routes.find_public_by_host(host).await?;
        self.public_cache.remember_public_route(
            host,
            route.clone(),
            public_config_ttl(route.is_some()),
        );
        Ok(route)
    }

    pub async fn domain_allowed_cached(&self, host: &str) -> anyhow::Result<bool> {
        if let Some(allowed) = self.public_cache.domain_allowed(host) {
            return Ok(allowed);
        }

        let allowed = self.routes.domain_allowed(host).await?;
        self.public_cache
            .remember_domain_allowed(host, allowed, public_config_ttl(allowed));
        Ok(allowed)
    }

    pub async fn find_enabled_promo_cached(
        &self,
        route_id: Uuid,
        code: &str,
    ) -> anyhow::Result<Option<PromoHit>> {
        if let Some(hit) = self.public_cache.promo(route_id, code) {
            return Ok(hit);
        }

        let hit = self.promos.find_enabled(route_id, code).await?;
        self.public_cache.remember_promo(
            route_id,
            code,
            hit.clone(),
            public_config_ttl(hit.is_some()),
        );
        Ok(hit)
    }

    pub fn clear_public_config_cache(&self) {
        self.public_cache.clear();
        self.cloak.clear_runtime_cache();
        self.meta.clear_runtime_cache();
    }
}

#[derive(Clone, Default)]
pub struct SecurityState {
    login_failures: Arc<Mutex<HashMap<String, LoginFailureState>>>,
    public_event_hits: Arc<Mutex<HashMap<String, Instant>>>,
    public_visits: Arc<Mutex<HashMap<String, (Uuid, Instant)>>>,
}

#[derive(Clone)]
struct LoginFailureState {
    count: u32,
    first_seen: Instant,
    locked_until: Option<Instant>,
}

impl SecurityState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn login_blocked(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut failures = self
            .login_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cleanup_login_failures(&mut failures, now);
        failures
            .get(key)
            .and_then(|state| state.locked_until)
            .map(|until| until > now)
            .unwrap_or(false)
    }

    pub fn record_login_failure(&self, key: &str) {
        let now = Instant::now();
        let mut failures = self
            .login_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cleanup_login_failures(&mut failures, now);
        let entry = failures
            .entry(key.to_string())
            .or_insert_with(|| LoginFailureState {
                count: 0,
                first_seen: now,
                locked_until: None,
            });
        if now.duration_since(entry.first_seen) > LOGIN_FAILURE_WINDOW {
            entry.count = 0;
            entry.first_seen = now;
            entry.locked_until = None;
        }
        entry.count += 1;
        if entry.count >= LOGIN_FAILURE_LIMIT {
            entry.locked_until = Some(now + LOGIN_LOCKOUT);
        }
    }

    pub fn clear_login_failure(&self, key: &str) {
        let mut failures = self
            .login_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        failures.remove(key);
    }

    pub fn mark_public_event_once(&self, key: &str, ttl: Duration) -> bool {
        let now = Instant::now();
        let mut hits = self
            .public_event_hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hits.retain(|_, expires_at| *expires_at > now);
        if hits
            .get(key)
            .map(|expires_at| *expires_at > now)
            .unwrap_or(false)
        {
            return false;
        }
        hits.insert(key.to_string(), now + ttl);
        true
    }

    pub fn clear_public_event_hit(&self, key: &str) {
        let mut hits = self
            .public_event_hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hits.remove(key);
    }

    pub fn remember_public_visit(&self, key: &str, visit_id: Uuid, ttl: Duration) {
        let expires_at = Instant::now() + ttl;
        let mut visits = self
            .public_visits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        visits.insert(key.to_string(), (visit_id, expires_at));
    }

    pub fn public_visit(&self, key: &str) -> Option<Uuid> {
        let now = Instant::now();
        let mut visits = self
            .public_visits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        visits.retain(|_, (_, expires_at)| *expires_at > now);
        visits
            .get(key)
            .and_then(|(visit_id, expires_at)| (*expires_at > now).then_some(*visit_id))
    }
}

#[derive(Clone, Default)]
pub struct PublicRuntimeCache {
    public_routes: Arc<Mutex<HashMap<String, CacheEntry<Option<PublicRoute>>>>>,
    domain_allowed: Arc<Mutex<HashMap<String, CacheEntry<bool>>>>,
    promos: Arc<Mutex<HashMap<String, CacheEntry<Option<PromoHit>>>>>,
}

#[derive(Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl PublicRuntimeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn public_route(&self, host: &str) -> Option<Option<PublicRoute>> {
        let key = normalize_cache_host(host)?;
        cache_get(&self.public_routes, &key)
    }

    pub fn remember_public_route(&self, host: &str, route: Option<PublicRoute>, ttl: Duration) {
        let Some(key) = normalize_cache_host(host) else {
            return;
        };
        cache_put(&self.public_routes, key, route, ttl);
    }

    pub fn domain_allowed(&self, host: &str) -> Option<bool> {
        let key = normalize_cache_host(host)?;
        cache_get(&self.domain_allowed, &key)
    }

    pub fn remember_domain_allowed(&self, host: &str, allowed: bool, ttl: Duration) {
        let Some(key) = normalize_cache_host(host) else {
            return;
        };
        cache_put(&self.domain_allowed, key, allowed, ttl);
    }

    pub fn promo(&self, route_id: Uuid, code: &str) -> Option<Option<PromoHit>> {
        let key = promo_cache_key(route_id, code)?;
        cache_get(&self.promos, &key)
    }

    pub fn remember_promo(&self, route_id: Uuid, code: &str, hit: Option<PromoHit>, ttl: Duration) {
        let Some(key) = promo_cache_key(route_id, code) else {
            return;
        };
        cache_put(&self.promos, key, hit, ttl);
    }

    pub fn clear(&self) {
        self.public_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.domain_allowed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.promos
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

fn public_config_ttl(found: bool) -> Duration {
    if found {
        PUBLIC_ROUTE_CACHE_TTL
    } else {
        PUBLIC_NOT_FOUND_CACHE_TTL
    }
}

fn cache_get<T: Clone>(cache: &Mutex<HashMap<String, CacheEntry<T>>>, key: &str) -> Option<T> {
    let now = Instant::now();
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match cache.get(key) {
        Some(entry) if entry.expires_at > now => Some(entry.value.clone()),
        Some(_) => {
            cache.remove(key);
            None
        }
        None => None,
    }
}

fn cache_put<T>(
    cache: &Mutex<HashMap<String, CacheEntry<T>>>,
    key: String,
    value: T,
    ttl: Duration,
) {
    let now = Instant::now();
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.retain(|_, entry| entry.expires_at > now);
    if cache.len() >= PUBLIC_CONFIG_CACHE_MAX_ITEMS {
        cache.clear();
    }
    cache.insert(
        key,
        CacheEntry {
            value,
            expires_at: now + ttl,
        },
    );
}

fn normalize_cache_host(host: &str) -> Option<String> {
    let host = host
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn promo_cache_key(route_id: Uuid, code: &str) -> Option<String> {
    let code = code.trim().to_uppercase();
    (!code.is_empty()).then(|| format!("{route_id}:{code}"))
}

fn cleanup_login_failures(failures: &mut HashMap<String, LoginFailureState>, now: Instant) {
    failures.retain(|_, state| {
        if let Some(until) = state.locked_until {
            return until > now;
        }
        now.duration_since(state.first_seen) <= LOGIN_FAILURE_WINDOW
    });
}
