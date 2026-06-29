mod settings;
mod state;
mod web;

use std::net::SocketAddr;

use ab_db::{connect, migrate};
use settings::Settings;
use state::AppState;
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let settings = Settings::from_env()?;
    let pool = connect(&settings.database_url).await?;
    migrate(&pool).await?;

    let state = AppState::new(settings.clone(), pool);
    state
        .auth
        .ensure_admin_user(&settings.admin_user, &settings.admin_password)
        .await?;
    state.auth.cleanup_expired().await?;
    spawn_meta_worker(state.clone());
    let app = web::router(state)
        .nest_service("/static", ServeDir::new("static"))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", settings.host, settings.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "ab rust app listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn spawn_meta_worker(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(err) = state.meta.process_pending(50).await {
                tracing::warn!(error = %err, "failed to process meta event queue");
            }
        }
    });
}
