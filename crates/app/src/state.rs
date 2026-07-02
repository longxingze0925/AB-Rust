use ab_db::DbPool;
use ab_services::{
    AssetsService, AuthService, CloakService, GeoIpService, HealthService, MetaService,
    PromosService, ResourcesService, RoutesService, StatsService, TemplatesService, VisitsService,
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

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
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
            resources: ResourcesService::new(pool.clone(), settings.meta_token_key.clone()),
            routes: RoutesService::new(pool.clone()),
            security: SecurityState::new(),
            stats: StatsService::new(pool.clone()),
            templates: TemplatesService::new(pool.clone(), settings.data_dir.clone()),
            visits: VisitsService::new(pool.clone()),
            settings,
        }
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

fn cleanup_login_failures(failures: &mut HashMap<String, LoginFailureState>, now: Instant) {
    failures.retain(|_, state| {
        if let Some(until) = state.locked_until {
            return until > now;
        }
        now.duration_since(state.first_seen) <= LOGIN_FAILURE_WINDOW
    });
}
